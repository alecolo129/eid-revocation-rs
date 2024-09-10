use crate::SALT;

use super::{
    utils::{generate_fr, Polynomial},
    Element, Error,
};
use blsful::inner_types::*;
use core::convert::TryFrom;
use group::GroupEncoding;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Represents x (secret key) 
#[derive(Clone, Debug, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct SecretKey(pub Scalar);


impl From<SecretKey> for [u8; 32] {
    fn from(s: SecretKey) -> Self {
        s.0.to_be_bytes()
    }
}

impl TryFrom<&[u8; 32]> for SecretKey {
    type Error = Error;

    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        let res = Scalar::from_be_bytes(bytes);
        if bool::from(res.is_some()) {
            Ok(Self(res.unwrap()))
        } else {
            Err(Error {
                message: String::from("invalid byte sequence"),
                code: 1,
            })
        }
    }
}

impl SecretKey {
    pub const BYTES: usize = 32;

    /// Create a new secret key from optional `seed`
    pub fn new(seed: Option<&[u8]>) -> Self {
        Self(generate_fr(
            SALT,
            seed, 
            rand_core::OsRng {}
        ))
    }

    /// Takes a list of elements `e_1, ..., e_m` and returns `(e_1+x)*...*(e_m+x)`
    fn batch_additions(&self, additions: &[Element]) -> Element {
        Element(
            additions
                .iter()
                .map(|e_i| e_i.0 + self.0)
                .fold(Scalar::ONE, |a, s_i| a * s_i),
        )
    }

    /// Takes a list of elements `e_1, ..., e_m` and returns `1/((e_1+x)*...*(e_m+x))`
    pub fn batch_deletions(&self, deletions: &[Element]) -> Element {
        Element(self.batch_additions(deletions).0.invert().expect("Inversion error: one of the deleted elements is outside accumulator domain"))
    }

    /// Create the coefficients for the polynomial v(X), as in Section 4.4.2 of my thesis. 
    /// 
    /// Returns an empty vector if the list of deletions is empty
    pub fn gen_up_poly(
        &self,
        deletions: &[Element],
    ) -> Vec<Element> {

        // Return empty poly if no deletion is batched
        if deletions.is_empty(){
            return vec![];
        }
   
        let m1 = -Scalar::ONE;
        let mut v = Polynomial::with_capacity(deletions.len());
        let mut pt = Polynomial::with_capacity(deletions.len()-1);
        
        // v(X) = ∑^{m}_{s=1}{ ∏^{s}_{i=1} {e_i + x}^-1 ∏^{s-1}_{j=1} {e_j - X}
        
        // Initialize both poly with first value (e_1+x)^-1
        let init = self.batch_deletions(&deletions[0..1]).0;
        pt.push(init);
        v.push(init);
        
        for s in 1..deletions.len() {
            // ∏ i=1..s {e_i + x}^-1
            pt *= self.batch_deletions(&deletions[s..s+1]).0;

            // ∏ j=1...s-1 {e_j - X}
            pt *= &[deletions[s-1].0, m1];
            v += pt.clone();
        }
        v.0.into_iter().map(|b| Element(b)).collect()
    }


    /// Create the Batch Polynomial coefficients as by Mike Lodder's implementation
    fn _create_coefficients(
        &self,
        additions: &[Element],
        deletions: &[Element],
    ) -> Vec<Element> {
        // vD(x) = ∑^{m}_{s=1}{ ∏ 1..s {yD_i + alpha}^-1 ∏ 1 ..s-1 {yD_j - x}
        let one = Scalar::ONE;
        let m1 = -one;
        let mut v_d = Polynomial::with_capacity(deletions.len());
        for s in 0..deletions.len() {
            // ∏ 1..s (yD_i + alpha)^-1
            let c = self.batch_deletions(&deletions[0..s + 1]).0;
            let mut poly = Polynomial::with_capacity(deletions.len());
            poly.push(one);
            // ∏ 1..(s-1) (yD_j - x)
            for j in deletions.iter().take(s) {
                poly *= &[j.0, m1];
            }
            poly *= c;
            v_d += poly;
        }

        //v_d(x) * ∏ 1..n (yA_i + alpha)
        v_d *= self.batch_additions(additions).0;

        // vA(x) = ∑^n_{s=1}{ ∏ 1..s-1 {yA_i + alpha} ∏ s+1..n {yA_j - x} }
        let mut v_a = Polynomial::with_capacity(additions.len());
        for s in 0..additions.len() {
            // ∏ 1..s-1 {yA_i + alpha}
            let c = if s == 0 {
                one
            } else {
                self.batch_additions(&additions[0..s]).0
            };
            let mut poly = Polynomial::with_capacity(additions.len());
            poly.push(one);
            // ∏ s+1..n {yA_j - x}
            for j in additions.iter().skip(s + 1) {
                poly *= &[j.0, m1];
            }
            poly *= c;
            v_a += poly;
        }
        // vA - vD
        v_a -= v_d;

        v_a.0.iter().map(|b| Element(*b)).collect()
    }


    /// Return the raw byte representation of the key
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        self.0.to_be_bytes()
    }
}



/// Represents X = x*G_2 (public key) defined in page 25 of my thesis
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey(pub G2Projective);

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey {{ {} }}", self.0)
    }
}

impl From<PublicKey> for G2Projective {
    fn from(p: PublicKey) -> Self {
        p.0
    }
}

impl From<G2Projective> for PublicKey {
    fn from(g: G2Projective) -> Self {
        Self(g)
    }
}

impl PublicKey {
    pub const BYTES: usize = 96;

    /// Return the byte representation for this public key
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut d = [0u8; Self::BYTES];
        d.copy_from_slice(self.0.to_bytes().as_ref());
        d
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        Self(G2Projective::GENERATOR * sk.0)
    }
}

impl TryFrom<&[u8; 96]> for PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8; 96]) -> Result<Self, Self::Error> {
        let res = G2Affine::from_compressed(bytes).map(G2Projective::from);
        if bool::from(res.is_some()){
            Ok(Self(res.unwrap()))
        } else {
            Err(Error {
                message: String::from("invalid byte sequence"),
                code: 1,
            })
        }
    }
}


#[cfg(test)]
mod tests {
    use std::time::Instant;
    use super::*;

    #[test]
    fn key_batch_test() {
        // Init parameters
        let key = SecretKey::new(None);
        let data = vec![Element::hash(b"value1"), Element::hash(b"value2")];
    
        // Compute (e_1+x)*(e_2+x), ((e_1+x)*(e_2+x))^-1
        let add = key.batch_additions(data.as_slice());
        let del = key.batch_deletions(data.as_slice());
        
        // Check del is inverse of add
        let res = add.0*del.0;
        assert_eq!(res, Scalar::ONE);
    }

    #[test] 
    #[should_panic]
    fn key_invalid_batch_test() {

        // Init parameters
        let key = SecretKey::new(None);
        let data = vec![Element(-key.0), Element::hash(b"value2")];
    
        // Compute ((-x+x)*(e_2+x))^-1
        let _ = key.batch_deletions(data.as_slice());
    }

    #[test]
    fn key_coefficient_test() {

        const BATCH_SIZE: usize = 100;

        // Init params
        let key = SecretKey::new(Some(b"1234567890"));
        let mut data = Vec::with_capacity(BATCH_SIZE);

        // Create vector of deletions
        (0..BATCH_SIZE).for_each(|i| {data.push(Element::hash(format!("Element {i}").as_bytes()))});

        // Compute update coefficients with optimization
        let t1 = Instant::now();
        let coefficients = key._create_coefficients(&[], &data);
        let t1 = t1.elapsed();

        // Compute update coefficients without optimization
        let t2 = Instant::now();
        let coefficients2 = key.gen_up_poly(&data);
        let t2 = t2.elapsed();

        // Check coeffiecients are the same
        coefficients.iter().zip(coefficients2.iter()).for_each(|(&c_1, &c_2)|{
            assert_eq!(c_1.0, -c_2.0);
        });
        

        println!("Old coefficient generation: {:?}", t1);
        println!("New coefficient generation: {:?}", t2);
    }

    
}
