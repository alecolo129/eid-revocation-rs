use accumulator::{
    accumulator::{Accumulator, Element}, key::{PublicKey, SecretKey}, proof::ProofParamsPublic, window_mul, witness::MembershipWitness, Coefficient
};

use bls12_381_plus::{G1Projective, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap};


/// Represents a pair or update polynomials (\omega(x), dD(x))
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePolynomials {
    pub deletions: Vec<Element>,
    pub omegas: Vec<Coefficient>,
}

/// Represents a pair (C, y) of membership witness, revocation ID 
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
    deletions: Vec<Element>,
}

impl Issuer {
    ///Creates a new `Issuer` instance.
    ///Generates the accumulator's secret key using the provided seed.  
    pub fn new(seed: Option<&[u8]>) -> Self {
        let acc_sk = SecretKey::new(seed);
        let acc_pk = PublicKey::from(&acc_sk);
        let acc = Accumulator::random(rand_core::OsRng {});
        Self {
            acc_sk,
            acc_pk,
            acc,
            witnesses: HashMap::new(),
            deletions: Vec::new(),
        }
    }

    /// Add a new witness to the list of witnesses
    /// 
    /// If the value is not present, prouces a new instance of `Revocation Handle`.
    /// Otherwise, does nothing and returns `None`
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


    ///Removes the element associated with the psedonym `pseudo` from the list of witnesses, and adds it to the deletion list.
    ///Note that the accumulator value is NOT modified by this operation.
    ///    
    ///If the value is present, returns the old `RevocationHandle`.
    ///Otherwise, does nothing and returns `None`
    pub fn remove(&mut self, pseudo: &String) -> Option<RevocationHandle> {
        let rh = self.witnesses.remove(pseudo)?;
        self.deletions.push(rh.get_elem());       
        return Some(rh);
    }

    ///Removes the elements associated with the psedonyms `pseudos` from the list of witnesses, and adds them to the deletion list.
    ///Note that the accumulator value is NOT modified by this operation.
    ///    
    ///Does nothing for all the pseudonyms that are not associated to any accumulated element.
    pub fn remove_elements(&mut self, pseudos: &[String]) {
        let mut existing_elements: Vec<Element> = Vec::with_capacity(pseudos.len());
        pseudos.iter().for_each(|pseudo| {
            if let Some(rh) = self.witnesses.remove(pseudo) {
                existing_elements.push(rh.elem);
            }
        });
        self.deletions.append(&mut existing_elements);
    }

    ///Performs a batch deletion of all the elements stored in the `deletions` list. 
    ///Note that this operation modifies the accumulator value and empties the list of deletions.
    ///    
    ///If the `deletions` list is not empty, returns the update polynomials.
    ///Otherwise does nothing and returns `None`.
    pub fn update(&mut self) -> Option<UpdatePolynomials>{ 
        // If no deletions return `None`
        if self.deletions.is_empty() {
            return None
        }
        //Compute update polys
        let omegas = self.acc.update_assign(&self.acc_sk, self.deletions.as_slice());
        let polys = UpdatePolynomials{deletions: self.deletions.clone(), omegas};
        //Clear list of deletions
        self.deletions.clear();
        return Some(polys)
    }

    ///Performs a periodic update. Revokes any element left in the list of deletions and update all witnesses
    pub fn update_periodic(&mut self){
        
        // Revoke any elements to be revoked
        if !self.deletions.is_empty(){
            self.acc.remove_elements_assign(&self.acc_sk, self.deletions.as_slice());
            self.deletions.clear();
        }

        // Compute coefficients for the update (i.e., [(\alpha + y_1)^-1, ..., (\alpha + y_m)^-1])
        let coefficients: Vec<Scalar> = self.witnesses
            .iter()
            .map(|(_, rh)| 
                self.acc_sk.batch_deletions(&[rh.get_elem()]).0
            )
            .collect();

        // Efficiently update all witnesses
        let new_wits = window_mul(self.acc.0, coefficients);
        self.witnesses
            .iter_mut()
            .enumerate()
            .for_each(|(i, (_, rh))| rh.update_witness(new_wits[i]));
    }

    ///Deletes the element associated with `pseudo` from the accumulator and the list of witnesses.
    ///Note that this operation modifies the accumulator value.
    ///    
    ///If present, returns the update polynomials for the deleted element. 
    ///Otherwise, does nothing and returns `None`
    pub fn delete(&mut self, pseudo: &String) -> Option<UpdatePolynomials> {
        let rh = self.witnesses.remove(pseudo)?;  
        let deletions = vec![rh.elem];
        let omegas = self.acc.update_assign(&self.acc_sk, deletions.as_slice());
        return Some(UpdatePolynomials{deletions, omegas});
    }

    pub fn get_proof_params(&self) -> ProofParamsPublic {
        ProofParamsPublic::new(&self.acc, &self.acc_pk)
    }

    pub fn get_witnesses(&self) -> HashMap<String, MembershipWitness> {
        //Return witness list
        let wit: HashMap<String, MembershipWitness> = self
            .witnesses
            .iter()
            .map(|(k, v)| (k.clone(), v.wit))
            .collect();
        return wit;
    }

    pub fn get_accumulator(&self) -> Accumulator {
        self.acc
    }

    pub fn get_pk(&self) -> PublicKey {
        return self.acc_pk.clone();
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::holder::Holder;
    use crate::verifier::Verifier;
    use accumulator::{generate_fr, witness, SALT};
    use core::num;
    use std::time::{Instant, SystemTime};
    const ADD_SIZE: usize = 1000;
    //const _SIZE: usize = 10;
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
        let holder = Holder::new(String::from("Holder"), rh, Some(pp));
        let t = Instant::now();
        let proof_params = iss.get_proof_params();
        let proof = holder.proof_membership(&proof_params);
        println!(
            "Time to create membership proof: {:?}",
            t.elapsed()
        );
  
        //Verifier
        let ver_params = iss.get_proof_params();
        let ver = Verifier::new(&ver_params);
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
        let polys = issuer.delete(&0.to_string()).expect("Non existing element");
        println!(
            "Time to remove one element and compute update polynomials: {:?}",
            t.elapsed()
        );

        // Check non-revoked witness is invalid before updating and is valid after updating
        let valid_y = elements[1];
        let mut valid_wit = witness[1];
        assert!(!valid_wit.verify(valid_y, issuer.get_pk(), issuer.get_accumulator()));
        valid_wit.batch_update_assign(valid_y, polys.deletions.as_slice(), polys.omegas.as_slice());
        assert!(valid_wit.verify(valid_y, issuer.get_pk(), issuer.get_accumulator()));

        // Check revoked witness is always invalid
        let revoked_y = elements[0];
        let mut revoked_wit = witness[0];
        assert!(!revoked_wit.verify(revoked_y, issuer.get_pk(), issuer.get_accumulator()));
        revoked_wit.batch_update_assign(elements[0], polys.deletions.as_slice(), polys.omegas.as_slice());
        assert!(!revoked_wit.verify(revoked_y, issuer.get_pk(), issuer.get_accumulator()));
        assert!(issuer.deletions.is_empty())
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
        let t = Instant::now();
        let deletions: Vec<String> = (0..num_deletions).map(|i| i.to_string()).collect();
        issuer.remove_elements(deletions.as_slice());
        let polys = issuer.update();
        println!(
            "Time to revoke {num_deletions} witness and compute update polynomials: {:?}",
            t.elapsed()
        );
        let polys = polys.expect("Deletion list is empty");

        // Check non-revoked witness is invalid before updating and is valid after updating
        let valid_y = elements[num_deletions];
        let mut valid_wit = witness[num_deletions];
        assert!(!valid_wit.verify(valid_y, issuer.get_pk(), issuer.get_accumulator()));
        valid_wit.batch_update_assign(valid_y, polys.deletions.as_slice(), polys.omegas.as_slice());
        assert!(valid_wit.verify(valid_y, issuer.get_pk(), issuer.get_accumulator()));

        // Check revoked witness is always invalid
        let revoked_y = elements[0];
        let mut revoked_wit = witness[0];
        assert!(!revoked_wit.verify(revoked_y, issuer.get_pk(), issuer.get_accumulator()));
        revoked_wit.batch_update_assign(elements[0], polys.deletions.as_slice(), polys.omegas.as_slice());
        assert!(!revoked_wit.verify(revoked_y, issuer.get_pk(), issuer.get_accumulator()));
        assert!(issuer.deletions.is_empty())
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
        issuer.remove_elements(deletions.as_slice());

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
