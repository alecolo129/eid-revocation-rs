use merlin::Transcript;

use accumulator::{
    accumulator::Accumulator, proof::{self, Proof, ProofParamsPublic}
};
use crate::Updatable;

#[derive(Debug)]
pub struct Verifier {
    params: ProofParamsPublic
} 


impl Verifier {

    /// Creates a new `Verifier` instance, associated with the input proof parameters `params`.
    pub fn new(params: ProofParamsPublic) -> Self {
        Self {
            params
        }
    }  
    
    /// Verifies the input membership proof `mem_proof` against the stored proof parameters.
    pub fn verify(&self, mem_proof: Proof)->bool{
        let mut transcript = Transcript::new(proof::PROOF_LABEL);
        self.params.add_to_transcript(&mut transcript);

        let final_proof = mem_proof.finalize(&self.params);
        return final_proof.verify(&mut transcript);
    }
}

impl Updatable for Verifier{

    /// Update the verifier's public parameters with the new parameters `new_pp`.
    fn update_public_params(&mut self, new_pp: ProofParamsPublic) {
        self.params = new_pp;
    }

    /// Update the verifier's accumulator with the new accumulator `new_acc`.
    fn update_accumulator(&mut self, new_acc: Accumulator) {
        self.params.update_accumulator(new_acc);
    }
}

#[cfg(test)]
mod tests {
    use crate::{Holder, Issuer, Verifier};
    use std::time::Instant; 


    #[test]
    fn verifier_proof_succeed() {
        let mut issuer = Issuer::new(None);

        // Init Holder
        let rh = issuer.add("holder1").unwrap();
        let params = issuer.get_proof_params();
        let holder = Holder::new("holder1", rh, params);
        
        // Init Verifier
        let ver = Verifier::new(params);
        
        // Compute proof
        let proof = holder.proof_membership(None);
        
        // Verify proof
        let t = Instant::now();
        assert!(ver.verify(proof));
        let t = t.elapsed();
        println!(
            "Valid proof - verification time: {:?}",
            t
        )
    }

    #[test]
    fn verifier_proof_fails() {
        let mut issuer = Issuer::new(None);

        // Init Holder
        let rh = issuer.add("holder1").unwrap();
        let params = issuer.get_proof_params();
        let holder = Holder::new("holder1", rh, params);
        
        // Init Verifier
        let mut ver = Verifier::new(params);


        // Delete holder
        issuer.revoke_instant(&String::from("holder1"));

        // Update verifier
        let new_acc = issuer.get_accumulator();
        ver.update_acc(new_acc);

        // Compute proof
        let proof = holder.proof_membership(None);
        
        // Verify proof is not valid
        let t = Instant::now();
        assert!(!ver.verify(proof));
        let t = t.elapsed();
        println!(
            "Non valid proof - verification time: {:?}",
            t
        )
    }
}