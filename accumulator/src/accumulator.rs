use super::{
    utils::{generate_fr, SALT},
    Error, SecretKey,
};
use crate::window_mul;
use blsful::inner_types::*;
use core::{
    convert::TryFrom,
    fmt::{self, Formatter},
};
use group::GroupEncoding;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// An element in the accumulator
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Element(pub Scalar);

impl Element {
    pub const BYTES: usize = 32;
    
    /// Return the multiplicative identity element
    pub fn one() -> Self {
        Self(Scalar::ONE)
    }

    /// Return the byte representation
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        self.0.to_be_bytes()
    }

    /// Construct an element by hashing the specified bytes
    pub fn hash(d: &[u8]) -> Self {
        Self(generate_fr(SALT, Some(d), rand_core::OsRng {}))
    }

    
    /// Compute an element from a Merlin Transcript
    pub fn from_transcript(label: &'static [u8], transcript: &mut merlin::Transcript) -> Self {
        let mut okm = [0u8; 64];
        transcript.challenge_bytes(label, &mut okm);
        Self::hash(&okm)
    }


    /// Construct a random element
    pub fn random() -> Self {
        Self(generate_fr(SALT, None, rand_core::OsRng {}))
    }
}


impl Hash for Element {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_be_bytes().hash(state)
    }
}

impl fmt::Display for Element {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Element {{ {} }}", self.0)
    }
}


impl TryFrom<&[u8; 32]> for Element {
    type Error = Error;

    fn try_from(value: &[u8; 32]) -> Result<Self, Self::Error> {
        let s = Scalar::from_be_bytes(value);
        if s.is_some().unwrap_u8() == 1u8 {
            Ok(Self(s.unwrap()))
        } else {
            Err(Error {
                message: String::from("incorrect byte sequence"),
                code: 1,
            })
        }
    }
}

/// A coefficent for updating witnesses
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Coefficient(pub G1Projective);
impl Coefficient {
    const BYTES: usize = 48;

    /// The byte representation of this coefficient
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut d = [0u8; Self::BYTES];
        d.copy_from_slice(self.0.to_bytes().as_ref());
        d
    }
}

impl fmt::Display for Coefficient {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Coefficient {{ {} }}", self.0)
    }
}

impl From<Coefficient> for G1Projective {
    fn from(c: Coefficient) -> Self {
        c.0
    }
}

impl From<G1Projective> for Coefficient {
    fn from(g: G1Projective) -> Self {
        Self(g)
    }
}

impl TryFrom<&[u8; 48]> for Coefficient {
    type Error = Error;

    fn try_from(value: &[u8; 48]) -> Result<Self, Self::Error> {
        let pt = G1Affine::from_compressed(value).map(G1Projective::from);
        if pt.is_some().unwrap_u8() == 1 {
            Ok(Self(pt.unwrap()))
        } else {
            Err(Error {
                message: String::from("incorrect byte sequence"),
                code: 1,
            })
        }
    }
}


/// Represents a Positive Bilinear Accumulator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Accumulator(pub G1Projective);

impl Accumulator {
    pub const BYTES: usize = 48;

    /// Creates a new random accumulator 
    /// as in https://ieeexplore.ieee.org/abstract/document/9505229 Section IV.
    pub fn random(rng: impl RngCore + CryptoRng) -> Self {
        let s = generate_fr(SALT, None, rng);
        Self(G1Projective::GENERATOR * s)
    }

    /// Using the trapdoor `key`, returns a new accumulator without the input element `deletion`
    pub fn remove(&self, key: &SecretKey, deletion: Element) -> Accumulator{
        self.clone().remove_assign(key, deletion)
    }

    /// Using the trapdoor `key`, modifyies the acumulator in-place, removing the input element `deletion`
    pub fn remove_assign(&mut self, key: &SecretKey, deletion: Element) -> Accumulator{
        self.0 *= key.batch_deletions(&[deletion]).0;
        *self
    }

    /// Using the trapdoor `key`, returns a new accumulator without the values in `deletions`. 
    pub fn remove_elements(&self, key: &SecretKey, deletions: &[Element]) -> Accumulator {
        let mut a = self.clone();
        a.remove_elements_assign(key, deletions);
        a
    }

    /// Using the trapdoor `key`, removes values in `deletions` 
    /// and updates the accumulator in-place.
    pub fn remove_elements_assign(&mut self, key: &SecretKey, deletions: &[Element]){
        // V_{t+1} = V_{t}*((x+e_1)*...*(x+e_n))^-1
        self.0 *= key.batch_deletions(deletions).0;
    }

    /// Given the accumulator trapdoor `key` and a list of deletions `deletions`, 
    /// returns the list of update coefficients for polynomial `Ω(X)` without updating the accumulator.
    pub fn update(
        &self,
        key: &SecretKey,
        deletions: &[Element]
    ) -> Vec<Coefficient>{
        self.clone().update_assign(key, deletions)
    }

    /// Given the accumulator trapdoor `key` and a list of deletions `deletions`, 
    /// performs a batch update of the accumulator returning the list of update coefficients.
    pub fn update_assign(
        &mut self,
        key: &SecretKey,
        deletions: &[Element],
    ) -> Vec<Coefficient> {

        // See page 34 of my thesis (eq. 4.4, 4.7)

        // d = ((x+e_1)*...*(x+e_m))^-1
        let d = key.batch_deletions(deletions);
        // v(X) = ∑^{m-1}_{i=0} c_i X^i
        let coefficients = key.gen_up_poly(deletions);

        // Optimized evaluation of [c_0*V, ..., c_{m-1}*V] using window multiplication
        let coefficients = window_mul(self.0, coefficients.into_iter().map(|c| c.0).collect());

        // V_{t+1} = V_t*d
        self.0 *= d.0;

        coefficients.into_iter().map(|c| Coefficient(c)).collect()
    }

    /// Generate accumulator id
    pub fn get_id(&self) -> Scalar{
        return generate_fr(SALT, Some(&self.to_bytes()), rand_core::OsRng{})
    }

    /// Convert accumulator to bytes
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut d = [0u8; Self::BYTES];
        d.copy_from_slice(self.0.to_bytes().as_ref());
        d
    }

    /// Performs a batch deletion as described on page 11, section 5 in
    /// https://eprint.iacr.org/2020/777.pdf. Unoptimized version, maintained only for testing
    fn _update_assign(
        &mut self,
        key: &SecretKey,
        deletions: &[Element],
    ) -> Vec<Coefficient> {
        let d = key.batch_deletions(deletions);
        let coefficients = key
            .gen_up_poly(deletions)
            .iter()
            .map(|c| Coefficient(self.0 * c.0))
            .collect();
        self.0 *= d.0;
        coefficients
    }

}


impl fmt::Display for Accumulator {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Accumulator {{ {} }}", self.0)
    }
}

impl From<Accumulator> for G1Projective {
    fn from(a: Accumulator) -> Self {
        a.0
    }
}

impl From<G1Projective> for Accumulator {
    fn from(g: G1Projective) -> Self {
        Self(g)
    }
}

impl TryFrom<&[u8; 48]> for Accumulator {
    type Error = Error;

    fn try_from(value: &[u8; 48]) -> Result<Self, Self::Error> {
        let pt = G1Affine::from_compressed(value).map(G1Projective::from);
        if pt.is_some().unwrap_u8() == 1 {
            Ok(Self(pt.unwrap()))
        } else {
            Err(Error {
                message: String::from("incorrect byte sequence"),
                code: 1,
            })
        }
    }
}

impl Default for Accumulator {
    fn default() -> Self {
        Self(G1Projective::GENERATOR)
    }
}



#[cfg(test)]
mod tests {
    use std::time::Instant;

    use group::ff::{Field, PrimeField};
    use rand::rngs::OsRng;
    use std::time::SystemTime;
    use crate::{UpMsg, MembershipWitness, PublicKey};

    use super::*;

    // Single removal
    #[test]
    fn acc_single_remove_test(){
        // Generate params        
        let (key, mut acc) = (SecretKey::new(Some(b"Key{i}")), Accumulator::random(rand_core::OsRng{}));
        let pub_key = PublicKey::from(&key);

        // Get witness for random element
        let el  = Element::random();
        let mut wit = MembershipWitness::new(&el, acc, &key);
        
        // Revoke first element
        let t = Instant::now();
        acc.remove_assign(&key, el);
        let t = t.elapsed();

        // Check first witness does not verify and second witness verifies
        assert!(!wit.verify(el, pub_key, acc));
        println!("Time for deleting single element: {:?}", t);
    }

    // Batch removals
    #[test]
    fn acc_batch_remove_test(){
        const BATCH_DELETIONS: usize = 1_000;
        // Generate params        
        let (key, mut acc) = (SecretKey::new(Some(b"Key{i}")), Accumulator::random(rand_core::OsRng{}));
        let pub_key = PublicKey::from(&key);

        // Get elements to delete and respective witnesses
        let (mut deletions, mut witnesses) = (Vec::with_capacity(BATCH_DELETIONS), Vec::with_capacity(BATCH_DELETIONS));
        (0..BATCH_DELETIONS).for_each(|i| {
            let el = Element::hash(format!("Element {i}").as_bytes());
            deletions.push(el); witnesses.push(MembershipWitness::new(&el, acc, &key));
        });
        
        // Revoke all elements
        let t = Instant::now();
        acc.remove_elements_assign(&key, &deletions.as_slice());
        let t = t.elapsed();

        // Check witnesses do not verify
        witnesses.iter().enumerate().for_each(|(i, wit)| {assert!(!wit.verify(deletions[i], pub_key, acc));});
        println!("Time for deleting {} elements: {:?}", BATCH_DELETIONS, t);
    }



    //Batch Update
    #[test]
    fn acc_batch_update_test() {

        const CREDENTIAL_SPACE: usize = 1_010;
        const BATCH_DELETIONS: usize = 1_000;

        // Generate params        
        let key = SecretKey::new(Some(b"Key{i}"));
        let mut a = Accumulator::random(rand_core::OsRng{});
        let mut a2 = a.clone();
        
        // Create users
        let mut users = Vec::with_capacity(CREDENTIAL_SPACE);
        users.push(Element::hash("User".as_bytes()));
        (1..CREDENTIAL_SPACE).for_each(|i| {
            users.push(Element(users[i-1].0.double()));
        });

        let revoked = &users[..BATCH_DELETIONS];
        
        let t1 = Instant::now();
        let coeff = a.update_assign(&key, revoked);
        let t1 = t1.elapsed();

        
        let t2 = Instant::now();
        let coeff2 = a2._update_assign(&key, revoked);
        let t2 = t2.elapsed();

        assert_eq!(coeff, coeff2);

        println!("Time to compute update poly omega for {BATCH_DELETIONS} deletions: {:?}", t2);
        println!("Time to compute updates poly omega for {BATCH_DELETIONS} deletions with windowed multiplication: {:?}", t1);
    }

   
}
