use accumulator::{
    accumulator::{Accumulator, Element}, key::{PublicKey, SecretKey}, proof::ProofParamsPublic, window_mul, witness::MembershipWitness, Coefficient
};

use blsful::inner_types::{G1Projective, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap};

/// Represents a pair or update polynomials (\omega(x), dD(x))
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePolynomials {
    pub deletions: Vec<Element>,
    pub omegas: Vec<Coefficient>,
}

/// Represents a pair (C, y) of membership witness, revocation ID 
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationHandle {
    elem: Element,
    wit: MembershipWitness,
}

impl RevocationHandle {

    /// Creates a new RevocationHandle an accumulator value and the corrisponding secret key
    fn new(accumulator: Accumulator, secret_key: &SecretKey) -> Self {
        // Pick a random y
        let elem = Element::random();
        // Create a witness for y
        let wit = MembershipWitness::new(&elem, accumulator, secret_key);
        Self { elem, wit }
    }

    /// Returns the associated witness C
    pub fn get_witness(&self) -> MembershipWitness {
        return self.wit;
    }

    /// Returns the associated element y
    pub fn get_elem(&self) -> Element {
        return self.elem;
    }

    // Verifies witness validity
    pub fn verify(&self, pubkey: PublicKey, accumulator: Accumulator)->bool{
        self.wit.verify(self.elem, pubkey, accumulator)
    }

    /// Updates the witness with the input point
    fn update_witness(&mut self, new_wit: G1Projective) {
        self.wit.apply_update(new_wit);
    }
}

#[derive(Debug, Clone)]
pub struct Issuer {
    acc_sk: SecretKey,
    acc_pk: PublicKey,
    acc: Accumulator,
    witnesses: HashMap<String, RevocationHandle>,
    revocation_list: Vec<Element>,
}

impl Issuer {
    /// Creates a new `Issuer`.
    /// 
    /// # Arguments
    /// * `seed` - Optional seed for deriving the accumulator's secret key.  
    /// 
    /// # Returns
    /// * A new instance of `Issuer`.
    /// 
    /// # Examples
    /// ```
    /// let issuer = entities::Issuer::new(None);
    ///   
    /// assert!(issuer.get_witnesses().is_empty());     
    /// ```
    pub fn new(seed: Option<&[u8]>) -> Self {
        let acc_sk =  SecretKey::new(seed);
        Self {
            acc_pk: PublicKey::from(&acc_sk),
            acc_sk: acc_sk,
            acc: Accumulator::random(rand_core::OsRng {}),
            witnesses: HashMap::new(),
            revocation_list: Vec::new(),
        }
    }

    /// Adds a new holder to the system, generating a new `Revocation Handle` instance for the holder's credential.
    /// 
    /// # Arguments
    /// * `pseudo` - A unique pseudonym associated to the new holder.  
    /// 
    /// # Returns
    /// * `Some(`RevocationHandle`)` if the addition is succesful.
    /// * `None` if the additon fails (e.g., the pseudonym is already used).
    /// 
    /// # Examples
    /// ```
    /// // Create a new issuer and add holder_1
    /// let mut issuer = entities::Issuer::new(None);
    /// let rh = issuer.add("holder_1").unwrap();
    /// 
    /// // Verification succeeds
    /// assert!(rh.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// 
    /// // We can't add holder_1 a second time
    /// assert!(issuer.add("holder_1").is_none());
    /// ```
    pub fn add<T: Into<String>>(&mut self, pseudo: T) -> Option<RevocationHandle> {
        let pseudo: String = pseudo.into();
        match self.witnesses.entry(pseudo.clone()) {
            Entry::Occupied(_) => return None,
            Entry::Vacant(v) => {
                let r = v.insert(RevocationHandle::new(self.acc, &self.acc_sk));
                return Some(*r);
            }
        }
    }
        
        
    /// Revokes a credential holder from the system.
    /// 
    /// # Arguments
    /// * `pseudo` - The unique pseudonym of holder to be revoked.  
    /// 
    /// # Returns
    /// * `Some(`UpdatePolynomial`)` if the holder is succesfully revoked.
    /// * `None` if the addition fails (e.g., the holder was already revoked).
    /// 
    /// # Examples
    /// ```
    ///
    /// let mut issuer = entities::Issuer::new(None); 
    /// let rh = issuer.add("holder_1").unwrap();
    /// 
    /// // Revoke holder_1
    /// let up_poly = issuer.revoke("holder_1");
    /// 
    /// // Revocation is enforced
    /// assert!(!rh.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// 
    /// // Update polynomial is created and second revocation of the same user fails
    /// assert!(up_poly.is_some());
    /// assert!(issuer.revoke("holder_1").is_none());
    /// ```
    pub fn revoke(&mut self, pseudo: &str) -> Option<UpdatePolynomials> {
        let rh = self.witnesses.remove(pseudo)?;  
        let deletions = vec![rh.elem];
        let omegas = self.acc.update_assign(&self.acc_sk, deletions.as_slice());
        return Some(UpdatePolynomials{deletions, omegas});
    }
    
    
    
    
    /// Revokes multiple credential holders from the system as a single batch.
    ///
    ///# Arguments
    /// * `pseudo` - The unique pseudonym of holder to be revoked.  
    /// 
    /// # Returns
    /// * `Some(`UpdatePolynomial`)` if some holders were succesfully revoked.
    /// * `None` no holder could be revoked (e.g., all holders were already revoked).
    /// 
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// let rh_1 = issuer.add("holder_1").unwrap();
    /// let rh_2 = issuer.add("holder_2").unwrap();
    /// 
    /// // Try to revoke two valid pseudonyms and an invalid one
    /// let up_poly = issuer.batch_revoke(&[&"holder_1", &"holder_2", &"holder_3"]).unwrap();
    /// 
    /// // The two valid pseudonyms are actually revoked
    /// assert!(up_poly.deletions.len() == 2);
    /// assert!(!rh_1.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(!rh_2.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// ```
    pub fn batch_revoke<T: AsRef<str>>(&mut self, pseudos: &[T]) -> Option<UpdatePolynomials>{
        
        // Create list of deletions with all the elements associated to existing pseudonyms
        let deletions: Vec<Element> = pseudos.iter().filter_map(|pseudo| {
            match self.witnesses.remove(pseudo.as_ref()){
                Some(rh) => Some(rh.elem),
                None => None
            }
        }).collect();
    
        // Return None if no pseudonym was valid
        if deletions.is_empty(){
            return None;
        }

        // Otherwise revoke all valid pseudonyms, updating accumulator and computing update poly
        let omegas = self.acc.update_assign(&self.acc_sk, deletions.as_slice());
        Some(UpdatePolynomials{deletions, omegas})
    }



    /// Adds some credential holders to the list of revocations to be performed in the future.
    /// 
    /// # Arguments
    /// * `pseudo` - The unique pseudonym associated to the revoked holder.  
    /// 
    /// # Returns
    /// * `Some(`RevocationHandle`)` if the holder is succesfully added.
    /// * None if addition to the revocation list fails (e.g., the pseudonym is already in revocation list).
    /// 
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// let rh = issuer.add("holder_1").unwrap(); 
    /// 
    /// // Add one element to revocation list
    /// let added = issuer.add_to_revoke_list(&[&"holder_1", &"some"]);
    /// assert_eq!(added, 1);
    /// 
    /// // Witness is still valid until `issuer::revoke_list' is called
    /// assert!(rh.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// 
    /// // Can't re-add same user two times
    /// assert_eq!(issuer.add_to_revoke_list(&[&"holder_1"]), 0);
    /// ```
    pub fn add_to_revoke_list<T: AsRef<str>>(&mut self, pseudos: &[T]) -> usize {
        pseudos.iter().map(|pseudo| {
            match self.witnesses.remove(pseudo.as_ref()){
                // If pseudo was in witness list, add to revocation list and count 1
                Some(rh) => {
                    self.revocation_list.push(rh.elem);
                    1
                },
                // Otherwise do nothing
                None => 0
            }}).sum()
    }
    
    /// Batch-revoke all the holders contained in the issuer's revocation list. 
    ///    
    /// # Returns
    /// * `Some(`UpdatePolynomial`)` if some holders were succesfully revoked.
    /// * `None` if the revocation fails (e.g., the revocation list is empty).
    /// 
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// 
    /// let rh_1 = issuer.add("holder_1").unwrap(); 
    /// let rh_2 = issuer.add("holder_2").unwrap(); 
    /// let rh_3 = issuer.add("holder_3").unwrap(); 
    /// 
    /// // Add all holders to revocation list
    /// issuer.add_to_revoke_list(&[&"holder_1", &"holder_2"]);
    /// issuer.add_to_revoke_list(&[&"holder_3"]);
    /// 
    /// // Revoke all holders in list
    /// let up_poly = issuer.revoke_list().unwrap();
    /// assert!(up_poly.deletions.len()==3);
    /// assert!(issuer.revoke_list().is_none());
    /// 
    /// // Revocation is enforced
    /// assert!(!rh_1.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(!rh_2.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(!rh_3.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// ```
    pub fn revoke_list(&mut self) -> Option<UpdatePolynomials>{ 
        
        // If no deletions return `None`
        if self.revocation_list.is_empty() {
            return None
        }
        
        //Compute update polys
        let omegas = self.acc.update_assign(&self.acc_sk, self.revocation_list.as_slice());
        let polys = UpdatePolynomials{deletions: self.revocation_list.clone(), omegas};
        
        //Clear list of deletions
        self.revocation_list.clear();

        return Some(polys)
    }

    
    /// Performs a periodic update. Revokes any element left in the list of deletions and update all witnesses
    pub fn update_periodic(&mut self){
        
        // Create new random accumulator
        self.acc = Accumulator::random(rand_core::OsRng{});

        // Any remaining element is automatically revoked by the new accumulator
        self.revocation_list.clear();

        // Compute updated witnesses for all valid users (i.e., [(\alpha + y_1)^-1, ..., (\alpha + y_m)^-1])
        let new_wits = window_mul(self.acc.0, self.witnesses
            .iter()
            .map(|(_, rh)| 
                self.acc_sk.batch_deletions(&[rh.get_elem()]).0
            )
            .collect());

        self.witnesses
            .iter_mut()
            .enumerate()
            .for_each(|(i, (_, rh))| rh.update_witness(new_wits[i]));
    }

    /// Get the current accumulator value.
    /// 
    /// # Returns
    /// * `Accumulator`: the current accumulator value.
    /// 
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// let acc_1 = issuer.get_accumulator();
    /// 
    /// // Additions don't modify the accumulator value
    /// issuer.add("holder_1").unwrap();
    /// assert_eq!(acc_1, issuer.get_accumulator());
    /// 
    /// // Revocations modify the accumulator value
    /// issuer.revoke("holder_1").unwrap();
    /// assert!(acc_1 != issuer.get_accumulator());
    /// ```
    pub fn get_accumulator(&self) -> Accumulator {
        self.acc
    }
    
    /// Get the identifier associated to the current accumulator
    /// 
    /// # Returns
    /// * `Scalar`: the accumulator's identifier.
    /// 
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// let id = issuer.get_accumulator_id();
    /// ```
    pub fn get_accumulator_id(&self) -> Scalar {
        
        self.acc.get_id()
    }


    /// Get the issuer's public key
    ///
    /// # Returns
    /// * `PublicKey`: the issuer's public key.
    /// 
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// let pk = issuer.get_pk();
    /// ```
    pub fn get_pk(&self) -> PublicKey {
        return self.acc_pk;
    }

    /// Get the public parameters used for generating and verifying membership proofs.
    /// 
    /// # Returns
    /// * `ProofParametersPublic` an up-to-date instance of the public parameters (i.e., accumulator value and accumulator public key).
    /// 
    /// # Examples
    /// ```
    /// let issuer = entities::Issuer::new(None);
    /// let proof_params = issuer.get_proof_params();
    /// ```
    pub fn get_proof_params(&self) -> ProofParamsPublic {
        ProofParamsPublic::new(&self.acc, &self.acc_pk)
    }

    /// Get all witnesses associated to valid holders.
    /// 
    /// # Returns
    /// * `HashMap<String, MembershipWitness>` a dictionary where keys are holders pseudonyms and values are the associated witnesses.
    /// 
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// let rh = issuer.add("holder_1").unwrap();
    /// let witness_dict = issuer.get_witnesses();
    /// assert_eq!(rh.get_witness(), witness_dict["holder_1"]);
    /// ```
    pub fn get_witnesses(&self) -> HashMap<String, MembershipWitness> {
        //Return witness list
        let wit: HashMap<String, MembershipWitness> = self
            .witnesses
            .iter()
            .map(|(k, v)| (k.clone(), v.wit))
            .collect();
        return wit;
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::holder::Holder;
    use crate::verifier::Verifier;
    use std::time::{Instant, SystemTime};
    const ADD_SIZE: usize = 1000;


    #[test]
    fn setup() {
        let time = Instant::now();
        let iss = Issuer::new(None);
        iss.get_proof_params();
        println!(
            "Setup time: {:?}",
            time.elapsed()
        )
    }

    #[test]
    fn issue() {
        //Issuer
        let mut iss = Issuer::new(None);
        let pp = iss.get_proof_params();
        let rh = iss.add("test");
        let rh = rh.expect("Cannot issue witness");

        //Holder
        let holder = Holder::new(String::from("Holder"), rh, pp.clone());
        let t = Instant::now();
        let proof = holder.proof_membership(None);
        println!(
            "Time to create membership proof: {:?}",
            t.elapsed()
        );
  
        //Verifier
        let ver_params = iss.get_proof_params();
        let ver = Verifier::new(ver_params);
        let time = SystemTime::now();
        assert!(ver.verify(proof));
        println!(
            "Time to verify membership proof: {:?}",
            SystemTime::now().duration_since(time).unwrap()
        );
    }

    #[test]
    fn issuer_single_update() {
        // Setup issuer
        let mut issuer = Issuer::new(None);
        
        // Compute witnesses for ADD_SIZE elements
        let mut elements = Vec::new();
        let mut witness = Vec::new();
        (0..ADD_SIZE).for_each(|i| {
            let rh = issuer.add(i.to_string()).expect("Cannot add witness");
            witness.push(rh.get_witness());
            elements.push(rh.get_elem());
        });

        // Delete one of the elements and compute update
        let t = Instant::now();
        let polys = issuer.revoke(&0.to_string()).expect("Non existing element");
        println!(
            "Time to remove one element and compute update polynomials: {:?}",
            t.elapsed()
        );

        // Check non-revoked witness is invalid before updating and is valid after updating
        let valid_y = elements[1];
        let mut valid_wit = witness[1];
        assert!(!valid_wit.verify(valid_y, issuer.get_pk(), issuer.get_accumulator()));
        assert!(valid_wit.batch_update_assign(valid_y, polys.deletions.as_slice(), polys.omegas.as_slice()).is_ok());
        assert!(valid_wit.verify(valid_y, issuer.get_pk(), issuer.get_accumulator()));

        // Check revoked witness is always invalid
        let revoked_y = elements[0];
        let mut revoked_wit = witness[0];
        assert!(!revoked_wit.verify(revoked_y, issuer.get_pk(), issuer.get_accumulator()));
        assert!(revoked_wit.batch_update_assign(elements[0], polys.deletions.as_slice(), polys.omegas.as_slice()).is_err());
        assert!(!revoked_wit.verify(revoked_y, issuer.get_pk(), issuer.get_accumulator()));
        assert!(issuer.revocation_list.is_empty())
    }

    
    
    #[test]
    fn issuer_batch_update() {
        // Setup issuer
        let mut issuer = Issuer::new(None);
        
        // Compute witnesses for ADD_SIZE elements
        let mut elements = Vec::new();
        let mut witness = Vec::new();
        (0..ADD_SIZE).for_each(|i| {
            let rh = issuer.add(i.to_string()).expect("Cannot add witness");
            witness.push(rh.get_witness());
            elements.push(rh.get_elem());
        });

        // Revoke ADD_SIZE/2 elements and compute update polys
        let num_deletions = ADD_SIZE / 2;
        let deletions: Vec<String> = (0..num_deletions).map(|i| i.to_string()).collect();
        let t = Instant::now();
        let polys = issuer.batch_revoke(deletions.as_slice());
        issuer.add_to_revoke_list(&["a", "b"]);
        println!(
            "Time to revoke {num_deletions} witness and compute update polynomials: {:?}",
            t.elapsed()
        );
        let polys = polys.expect("Deletion list is empty");

        // Check non-revoked witness is invalid before updating and is valid after updating
        let valid_y = elements[num_deletions];
        let mut valid_wit = witness[num_deletions];
        assert!(!valid_wit.verify(valid_y, issuer.get_pk(), issuer.get_accumulator()));
        assert!(valid_wit.batch_update_assign(valid_y, polys.deletions.as_slice(), polys.omegas.as_slice()).is_ok());
        assert!(valid_wit.verify(valid_y, issuer.get_pk(), issuer.get_accumulator()));

        // Check revoked witness is always invalid
        let revoked_y = elements[0];
        let mut revoked_wit = witness[0];
        assert!(!revoked_wit.verify(revoked_y, issuer.get_pk(), issuer.get_accumulator()));
        let _ = revoked_wit.batch_update_assign(elements[0], polys.deletions.as_slice(), polys.omegas.as_slice());
        assert!(!revoked_wit.verify(revoked_y, issuer.get_pk(), issuer.get_accumulator()));
        assert!(issuer.revocation_list.is_empty())
    }

    #[test]
    fn issuer_mixed_batch_single_update() {
        // Setup issuer
        let mut issuer = Issuer::new(None);
        
        // Compute witnesses for ADD_SIZE elements
        let mut elements = Vec::new();
        let mut witness = Vec::new();
        (0..ADD_SIZE).for_each(|i| {
            let rh = issuer.add(i.to_string()).expect("Cannot add witness");
            witness.push(rh.get_witness());
            elements.push(rh.get_elem());
        });

        let mut polys = Vec::new();

        // Delete one of the elements and compute update
        let t = Instant::now();
        polys.push(issuer.revoke(&1.to_string()).expect("Non existing element"));
        println!(
            "Time to remove one element and compute update polynomials: {:?}",
            t.elapsed()
        );

        // Delete one of the elements without updating
        let t = Instant::now();
        let revoked_pseudos: Vec<String> =  (2..ADD_SIZE/2).map(|i| i.to_string()).collect();
        polys.push(issuer.batch_revoke(&revoked_pseudos.as_slice()).expect("Non existing element"));
        println!(
            "Time to remove {} elements and compute update polynomials: {:?}",
            ADD_SIZE/2-2,
            t.elapsed()
        );

        // Delete one of the elements without updating
        let t = Instant::now();
        issuer.add_to_revoke_list(&[(ADD_SIZE/2+1).to_string()]);
        println!(
            "Time to remove one element without computing update: {:?}",
            t.elapsed()
        );

        // Delete one of the elements without updating
        let t = Instant::now();
        let revoked_pseudos: Vec<String> =  (ADD_SIZE/2+2..ADD_SIZE).map(|i| i.to_string()).collect();
        issuer.add_to_revoke_list(revoked_pseudos.as_slice());
        println!(
            "Time to remove {} elements without computing update: {:?}",
            ADD_SIZE-ADD_SIZE/2-2,
            t.elapsed()
        );

        let t = Instant::now();
        let rev_number = issuer.revocation_list.len();
        polys.push(issuer.revoke_list().expect("No update poly"));
        println!(
            "Time to update after removal of {} elements: {:?}",
            rev_number,
            t.elapsed()
        );

        // Check non-revoked witness is invalid before updating and is valid after updating
        let valid_y = elements[0];
        let mut valid_wit = witness[0];
        assert!(!valid_wit.verify(valid_y, issuer.get_pk(), issuer.get_accumulator()));
        for poly in &polys{
            let _ = valid_wit.batch_update_assign(valid_y, &poly.deletions, &poly.omegas);
        }
        assert!(valid_wit.verify(valid_y, issuer.get_pk(), issuer.get_accumulator()));

        // Check revoked witness is always invalid
        let revoked_y = elements[1];
        let mut revoked_wit = witness[1];
        assert!(!revoked_wit.verify(revoked_y, issuer.get_pk(), issuer.get_accumulator()));
        for poly in &polys{
            let _ = revoked_wit.batch_update_assign(revoked_y, &poly.deletions, &poly.omegas);
        }        
        assert!(!revoked_wit.verify(revoked_y, issuer.get_pk(), issuer.get_accumulator()));
        assert!(issuer.revocation_list.is_empty())
    }

    #[test]
    fn issuer_epoch_update() {
        // Setup issuer
        let mut issuer = Issuer::new(None);
        
        // Compute witnesses for ADD_SIZE elements
        let mut elements = Vec::new();
        let mut witness = Vec::new();
        (0..ADD_SIZE).for_each(|i| {
            let rh = issuer.add(i.to_string()).expect("Cannot add witness");
            witness.push(rh.get_witness());
            elements.push(rh.get_elem());
        });

        // Simulate we have ADD_SIZE/2 elements to delete
        let num_deletions = ADD_SIZE / 2;
        let deletions: Vec<String> = (0..num_deletions).map(|i| i.to_string()).collect();
        issuer.add_to_revoke_list(deletions.as_slice());

        // Revoke removed elements and update all witnessses for valid elements
        let t = Instant::now();
        issuer.update_periodic();
        println!(
            "Time to compute periodic update of {} witness: {:?}",
            ADD_SIZE-num_deletions,
            t.elapsed()
        );

        let new_wits = issuer.get_witnesses();

        // Check all witnesses in previous witnesss list are invalid
        (0..ADD_SIZE).for_each(|i|{
            assert!(!witness[i].verify(elements[i], issuer.get_pk(), issuer.get_accumulator()));
        });

        // Check non-revoked witness are updated
        (num_deletions..ADD_SIZE).for_each(|i|{
            let wit = new_wits.get(&i.to_string());
            let wit = wit.expect("Non-revoked element is not present in witness list!");
            assert!(wit.verify(elements[i], issuer.get_pk(), issuer.get_accumulator()))
        });

        // Check revoked witness are not updated
        (0..num_deletions).for_each(|i|{
            let wit = new_wits.get(&i.to_string());
            assert!(wit.is_none());
        });
    }
}
