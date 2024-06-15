use accumulator::{
    accumulator::Element,
    proof::{self, ProofParamsPublic},
    witness::{Deletion, MembershipWitness},
    ProofParamsPrivate,
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
    pub fn new(pseudo: String, rh: RevocationHandle, pp: Option<ProofParamsPublic>) -> Self {
        Self { pseudo, y: rh.get_elem(), w: rh.get_witness(), pp}
    }

    pub fn update(&self, del: &[Deletion]){
        self.w.update(self.y, del);
    }

    pub fn replace_witness(&mut self, new_mw: MembershipWitness) {
        self.w = new_mw;
    }

    pub fn replace_public_params(&mut self, pub_params: ProofParamsPublic) {
        self.pp = Some(pub_params);
    }

    pub fn test_membership(&self, pp: Option<ProofParamsPublic>)->Option<bool>{
        let pp = if pp.is_some() { pp } else { self.pp };
        match pp {
            Some(pp) => Some(self.w.verify(self.y, pp.get_public_key(), pp.get_accumulator())),
            None => None,
        }
    }

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
