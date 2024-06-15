use accumulator::{
    accumulator::{Accumulator, Element},
    key::{PublicKey, SecretKey},
    proof::ProofParamsPublic,
    witness::MembershipWitness, PolynomialG1,
};

use bls12_381_plus::Scalar;
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RevocationHandle {
    elem: Element,
    wit: MembershipWitness,
}

impl RevocationHandle {
    fn new(accumulator: Accumulator, secret_key: &SecretKey) -> Self {
        let elem = Element::random();
        let wit = MembershipWitness::new(&elem, accumulator, secret_key);
        Self { elem, wit }
    }

    pub fn get_witness(&self) -> MembershipWitness {
        return self.wit;
    }

    pub fn get_elem(&self) -> Element {
        return self.elem;
    }

    fn update_witness(&mut self, coeff: &Scalar) {
        self.wit.fast_update_assign(coeff);
    }
}

#[derive(Debug, Clone)]
pub struct Issuer {
    acc_sk: SecretKey,
    acc_pk: PublicKey,
    acc: Accumulator,
    witnesses: HashMap<String, RevocationHandle>,
    update_coeff: Scalar,
    update_list: Vec<Element>,
    omega: PolynomialG1
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
            update_coeff: Scalar::ONE,
            update_list: Vec::new(),
            omega: PolynomialG1::with_capacity(1)
        }
    }

    /// Add a new witness to the list of witnesses
    /// 
    /// If the value is not present, prouces a new instance of `Revocation Handle`.
    /// Otherwise, does nothing and returns `None`
    pub fn add(&mut self, pseudo: String) -> Option<RevocationHandle> {
        match self.witnesses.entry(pseudo.clone()) {
            Entry::Occupied(_) => return None,
            Entry::Vacant(v) => {
                let r = v.insert(RevocationHandle::new(self.acc, &self.acc_sk));
                return Some(*r);
            }
        }
    }

    ///Deletes a witness from the list of witnesses
    ///
    ///If the value is present, updates the list and returns the old `MembershipWitness`.
    ///Otherwise, does nothing and returns `None`
    fn remove(&mut self, value: &String) -> Option<RevocationHandle> {
        return self.witnesses.remove(value);
    }

    ///Removes a witness from the accumulator
    ///    
    ///If the value is present, updates the accumulator and returns the old `Revocation Handle`.
    ///Otherwise, does nothing and returns `None`
    pub fn delete(&mut self, pseudo: &String) -> Option<RevocationHandle> {
        let rh = self.witnesses.remove(pseudo)?;
        self.update_coeff *= self.acc_sk.batch_deletions(&[rh.get_elem()]).0;
        return Some(rh);
    }

    pub fn delete_elements(&mut self, values: &[String]) {
        let mut existing_elements: Vec<Element> = Vec::new();
        values.iter().for_each(|pseudo| {
            if let Some(rh) = self.remove(&pseudo) {
                existing_elements.push(rh.elem);
            }
        });
        self.update_coeff *= self.acc_sk.batch_deletions(existing_elements.as_slice()).0;
    }

    /// Update all witnesses in witness list.
    pub fn update(&mut self) {
        // TODO: do this more efficiently with windowed mult
        self.acc.0 *= self.update_coeff;
        self.witnesses
            .iter_mut()
            .for_each(|(_, rh)| rh.update_witness(&self.update_coeff));
        self.update_coeff = Scalar::ONE;
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


/*
#[cfg(test)]
mod tests {
    use super::*;
    use crate::holder::Holder;
    use crate::verifier::Verifier;
    use crate::{generate_fr, SALT};
    use std::time::SystemTime;
    const ADD_SIZE: usize = 1000;
    //const _SIZE: usize = 10;
    #[test]
    fn setup() {
        let time = SystemTime::now();
        let iss = Issuer::new(Some(b"setup_acc"));
        iss.get_proof_params();
        println!(
            "Setup time: {:?}",
            SystemTime::now().duration_since(time).unwrap()
        )
    }

    #[test]
    fn issue() {
        //Issuer
        let mut iss = Issuer::new(Some(b"setup_acc"));
        let pp = iss.get_proof_params();
        let w = iss.add(b"test");
        assert!(w.is_some());

        //Holder
        let holder = Holder::new(Element::hash(b"test"), Some(pp), w);
        let time = SystemTime::now();
        let proof_params = iss.get_proof_params();
        let proof = holder.proof_membership(&proof_params);
        println!(
            "Time to create membership proof: {:?}",
            SystemTime::now().duration_since(time).unwrap()
        );
        assert!(proof.is_some());
        let proof = proof.unwrap();

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
    fn add() {
        let issuer = Issuer::new(Some(b"setup_acc"));
        let mut elements: Vec<Element> = Vec::new();
        (0..ADD_SIZE).for_each(|_| elements.push(Element::random()));

        let time = SystemTime::now();
        //issuer.add_all(&elements);
        println!(
            "Time to create and add {ADD_SIZE} witness: {:?}",
            SystemTime::now().duration_since(time).unwrap()
        );
        issuer
            .witnesses
            .iter()
            .for_each(|(el, w)| assert!(w.verify(*el, issuer.acc_pk, issuer.acc)))
    }

    #[test]
    fn periodic_update() {
        let mut issuer = Issuer::new(Some(b"test"));

        let time = SystemTime::now();
        let mut elements: Vec<Element> = Vec::new();
        (0..ADD_SIZE).for_each(|i| {
            elements.push(Element::hash(i.to_string().as_bytes()));
        });
        println!(
            "Time to init vector: {:?}",
            SystemTime::now().duration_since(time).unwrap()
        );

        let time = SystemTime::now();
        elements.iter().enumerate().for_each(|(i, el)| {
            issuer.add(i.to_string().as_bytes());
        });
        println!(
            "Time to add {} witness: {:?}",
            ADD_SIZE,
            SystemTime::now().duration_since(time).unwrap()
        );

        let deletions = &elements[..ADD_SIZE / 2];
        let time = SystemTime::now();

        deletions.into_iter().for_each(|el| {
            issuer.delete(&el);
        });
        println!(
            "Time to remove {ADD_SIZE} witness: {:?}",
            SystemTime::now().duration_since(time).unwrap()
        );

        let time = SystemTime::now();
        issuer.update();
        println!(
            "Time to update remaining {} witnesses: {:?}",
            ADD_SIZE - ADD_SIZE / 2,
            SystemTime::now().duration_since(time).unwrap()
        );

        println!("Size witnesses: {:?}", issuer.witnesses.len());
    }
}*/

/*
mod performance_tests{
    use super::*;
    use std::{time::SystemTime, usize};


    fn _update(size: usize){
        let issuer = Issuer::new(Some(b"test"), Some(b"testone"));
        let mut witnesses: Vec<MembershipWitness> = Vec::new();
        (0..=size).for_each(|_| witnesses.push(MembershipWitness::random()));


        let time = SystemTime::now();
        issuer._update_all(&mut witnesses);
        println!(
            "Time to update {} witnesses: {:?}",
            size,
            SystemTime::now().duration_since(time).unwrap()
        );
    }

    #[test] #[allow(non_snake_case)]
    fn update_1(){
        _update(1);
    }

    #[test] #[allow(non_snake_case)]
    fn update_10(){
        _update(10);
    }

    #[test] #[allow(non_snake_case)]
    fn update_100(){
        _update(10);
    }

    #[test] #[allow(non_snake_case)]
    fn update_1K(){
        _update(1_000);
    }

    #[test] #[allow(non_snake_case)]
    fn update_10K(){
        _update(10_000);
    }

    #[test] #[allow(non_snake_case)]
    fn update_100K(){
        _update(100_000);
    }

    #[test] #[allow(non_snake_case)]
    fn update_1M(){
        _update(1_000_000);
    }
}*/
