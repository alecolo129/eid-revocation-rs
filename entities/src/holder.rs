use accumulator::{
    accumulator::Element, proof::{self, ProofParamsPublic}, witness::{Deletion, MembershipWitness}, Coefficient, Error, ProofParamsPrivate
};
use crate::issuer::RevocationHandle;

#[derive(Debug)]
pub struct Holder {
    pseudo: String,
    pub y: Element,
    pub w: MembershipWitness,
    pub pp: Option<ProofParamsPublic>,
}

impl Holder {

    /// Returns a new `Holder` instance, associated with pseudonym `pseudo` and revocation handle `rh`.
    /// 
    /// Optionally specify the public parameters `pp` to be used for producing non-revocation proofs.
    pub fn new(pseudo: String, rh: RevocationHandle, pp: Option<ProofParamsPublic>) -> Self {
        Self { pseudo, y: rh.get_elem(), w: rh.get_witness(), pp}
    }

    /// Sequentially updates the witness using the vector of deletions `rh`.
    pub fn update(&mut self, del: &[Deletion]){
        self.w.update_assign(self.y, del);
    }

    /// Batch update the holder's witness with the update polynomials received as input.
    pub fn batch_update(& mut self, deletions: &[Element], omega: &[Coefficient]) -> Result<MembershipWitness, Error>{
        self.w.batch_update_assign(self.y, deletions, omega)
    }
    
    /// Replace the holder's witness with the input witness `new_mw`.
    pub fn replace_witness(&mut self, new_mw: MembershipWitness) {
        self.w = new_mw;
    }

    /// Replace the holder's public parameters with the new parameters `pub_params`.
    pub fn replace_public_params(&mut self, pub_params: ProofParamsPublic) {
        self.pp = Some(pub_params);
    }

    /// Test membership of the holder's witness against the accumulator contained 
    /// in the proof parameters `pp` received as input or in the cached parameters.
    /// 
    /// Returns `None` if no parameters can be found. 
    pub fn test_membership(&self, pp: Option<ProofParamsPublic>)->Option<bool>{
        let pp = if pp.is_some() { pp } else { self.pp };
        match pp {
            Some(pp) => Some(self.w.verify(self.y, pp.get_public_key(), pp.get_accumulator())),
            None => None,
        }
    }

    /// Creates a new membership proof
    pub fn proof_membership(&self, pub_params: &ProofParamsPublic) -> proof::Proof {
        let mut transcript = merlin::Transcript::new(proof::PROOF_LABEL);
        pub_params.add_to_transcript(&mut transcript);

        let priv_params = ProofParamsPrivate::new(self.y, &self.w);
        let pc = proof::ProofCommitting::new(&pub_params, &priv_params);
        pc.get_bytes_for_challenge(&mut transcript);

        let challenge_hash = Element::from_transcript(proof::PROOF_LABEL, &mut transcript);
        return pc.gen_proof(challenge_hash);
    }

    pub fn get_pseudo(&self) -> String{
        return self.pseudo.clone();
    }
}
