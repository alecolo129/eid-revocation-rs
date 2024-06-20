use merlin::Transcript;

use accumulator::{
    accumulator::Accumulator, proof::{self, Proof, ProofParamsPublic}
};

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

    /// Updates stored proof params incorporating new accumulator value `acc`.
    pub fn update_acc(&mut self, acc: Accumulator) -> Accumulator{
        let old_acc = self.params.c_m;
        self.params.c_m = acc.0;
        return Accumulator(old_acc);
    }   

    /// Updates stored proof params with input parameters `params`.
    pub fn update_params(&mut self, params: ProofParamsPublic)->ProofParamsPublic{
        let old_params = self.params;
        self.params = params;
        return old_params;
    }   
    
    /// Verifies the input membership proof `mem_proof` against the stored proof parameters.
    pub fn verify(&self, mem_proof: Proof)->bool{
        let mut transcript = Transcript::new(proof::PROOF_LABEL);
        self.params.add_to_transcript(&mut transcript);

        let final_proof = mem_proof.finalize(&self.params);
        return final_proof.verify(&mut transcript);
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