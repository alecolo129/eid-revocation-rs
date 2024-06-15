use merlin::Transcript;

use accumulator::{
    accumulator::Accumulator, proof::{self, Proof, ProofParamsPublic}
};

#[derive(Debug)]
pub struct Verifier {
    params: ProofParamsPublic
} 


impl Verifier {
    pub fn new(params: &ProofParamsPublic) -> Self {
        Self {
            params: *params
        }
    }

    pub fn update_acc(&mut self, acc: &Accumulator) -> Accumulator{
        let old_acc = self.params.c_m;
        self.params.c_m = acc.0;
        return Accumulator(old_acc);
    }   

    pub fn update_params(&mut self, params: &ProofParamsPublic)->ProofParamsPublic{
        let old_params = self.params;
        self.params = *params;
        return old_params;
    }   
    
    pub fn verify(&self, mem_proof: Proof)->bool{
        let mut transcript = Transcript::new(proof::PROOF_LABEL);
        self.params.add_to_transcript(&mut transcript);

        let final_proof = mem_proof.finalize(&self.params);
        return final_proof.verify(&mut transcript);
    }
}
