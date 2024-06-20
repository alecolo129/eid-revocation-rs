use crate::{
    accumulator::{Accumulator, Element}, generate_fr, key::PublicKey, witness::MembershipWitness, SALT, Error
};
use bls12_381_plus::{G1Affine, G1Projective, G2Projective, Gt, Scalar};
use group::{Curve, Group, GroupEncoding};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use core::fmt::{self, Formatter};
use merlin::Transcript;

/* 
Use the efficient BBS+ zero-knowledge proof described in section 5.2 of <https://link.springer.com/chapter/10.1007/978-3-031-30589-4_24>
which proofs e(A,e*g_2+X_2) = e(C(m), g_2). By doing the following substitutions:
    A => C, 
    e => y, 
    g_2 => P~,
    C(m) <-> V, 
    X_2 => Q~
this is equivalent to e(C, yP~ + Q~) = e(V, P~), as per Section 2 in <https://eprint.iacr.org/2020/777>.
*/

pub const PROOF_LABEL: &[u8;16] = b"Membership Proof";

/// Represents proof public parameters as in Section 5.2 of <https://link.springer.com/chapter/10.1007/978-3-031-30589-4_24>
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProofParamsPublic {
    pub c_m: G1Projective,
    pub g_1: G1Projective,
    pub x_2: G2Projective,
    pub g_2: G2Projective,
}

impl fmt::Display for ProofParamsPublic {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProofParams {{ Cm: {:?}, G1: {:?}, X2: {:?}, G2: {:?} }}",
            self.c_m.to_bytes(),
            self.g_1.to_bytes(),
            self.x_2.to_bytes(),
            self.g_2.to_bytes()
        )
    }
}

impl ProofParamsPublic {
    pub const BYTES: usize = 288;

    // Build new Proof params from accumulator and public key
    pub fn new(acc: &Accumulator, public_key: &PublicKey) -> Self {
        //C_m = V and X_2 = Q~
        Self {
            c_m: acc.0,
            g_1: G1Projective::GENERATOR,
            x_2: public_key.0,
            g_2: G2Projective::GENERATOR
        }
    }

    /// Updates public parameters with input accumulator
    pub fn update_accumulator(&mut self, acc: Accumulator){
        self.c_m = acc.0;
    }

    /// Get the accumulator used to build the params
    pub fn get_accumulator(&self)->Accumulator{
        return Accumulator::from(self.c_m);
    }
    
    /// Get the public key used to build the params
    pub fn get_public_key(&self)->PublicKey{
        return PublicKey::from(self.x_2);
    }
    
    /// Add these proof params to the transcript
    pub fn add_to_transcript(&self, transcript: &mut Transcript) {
        transcript.append_message(b"Proof Param Cm", self.c_m.to_bytes().as_ref());
        transcript.append_message(b"Proof Param G1", self.g_1.to_bytes().as_ref());
        transcript.append_message(b"Proof Param X2", self.x_2.to_bytes().as_ref());
        transcript.append_message(b"Proof Param G2", self.g_2.to_bytes().as_ref());
    }
    
}

/// Represents proof private parameters as in Section 5.2 of <https://link.springer.com/chapter/10.1007/978-3-031-30589-4_24> 
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ProofParamsPrivate{ 
    a: G1Projective,
    e: Scalar,
}

impl ProofParamsPrivate {
    pub const BYTES: usize = 80;

    pub fn new(y: Element, mw: &MembershipWitness) -> Self {
        //a = C and y=e
        Self{a: mw.0, e: y.0}
    }

}

#[derive(Debug, Copy, Clone)]
pub struct ProofCommitting {
    a_bar: G1Projective,
    b_bar: G1Projective,
    u: G1Projective,
    alpha: Scalar,
    beta: Scalar,
    r: Scalar,
    e: Scalar,
}

impl ProofCommitting {
    /// Create a new membership proof committing phase
    pub fn new(params_pub: &ProofParamsPublic, params_priv: &ProofParamsPrivate) -> Self {
        
        let mut rng = rand_core::OsRng {};
        
        // Randomly select r
        let r = generate_fr(SALT, None, &mut rng);

        
        //A_bar = A*r
        let a_bar = params_priv.a * r;
        
        //B_bar = (C_m-e*A)*r
        let b_bar = (params_pub.c_m - params_priv.a * params_priv.e)*r;
        
        // Randomly select alpha, beta
        let alpha = generate_fr(SALT, None, &mut rng);
        let beta = generate_fr(SALT, None, &mut rng);

        // U = alpha*C_m + beta*A_bar
        let u =  alpha * params_pub.c_m + beta * a_bar;
        
        Self {
            a_bar,
            b_bar,
            u,
            alpha,
            beta,
            r,
            e: params_priv.e,
        }
    }

    /// Return bytes that need to be hashed for generating challenge.
    /// A_bar || B_bar || U
    pub fn get_bytes_for_challenge(self, transcript: &mut Transcript){
        transcript.append_message(b"A_bar", self.a_bar.to_bytes().as_ref());
        transcript.append_message(b"B_bar", self.b_bar.to_bytes().as_ref());
        transcript.append_message(b"U", self.u.to_bytes().as_ref());
    }

    pub fn gen_proof(&self, challenge_hash: Element) -> Proof {

        // s = alpha + rc
        let s = schnorr(self.alpha, self.r, challenge_hash.0);

        // t = beta - ec
        let t = schnorr(self.beta, -self.e, challenge_hash.0);

        Proof {
            a_bar: self.a_bar,
            b_bar: self.b_bar,
            s,
            t,
            challenge_hash: challenge_hash.0,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Proof {
    /// A ZKP membership proof
    a_bar: G1Projective,
    b_bar: G1Projective,
    s: Scalar,
    t: Scalar,
    challenge_hash: Scalar
}

impl Proof {
    const BYTES: usize = 192;

    /// Generate the structure that can be used in the challenge hash
    /// returns a struct to avoid recomputing
    pub fn finalize(
        &self,
        params: &ProofParamsPublic,
    ) -> ProofFinal {

        // e(A_bar, X_2) - e(B_bar, g_2) = 0
        let pair_final = pair(self.a_bar, params.x_2)-pair(self.b_bar, params.g_2);
        
        // Reconstruct U = s*C_m + t*A_bar - c*B_bar
        let u = self.s*params.c_m + self.t*self.a_bar - self.challenge_hash * self.b_bar;
        ProofFinal {
            pair_final: pair_final,
            a_bar: self.a_bar,
            b_bar: self.b_bar,
            u: u,
            challenge_hash: self.challenge_hash,
        }
    }

    /// Get the byte representation of the proof
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut result = [0u8; Self::BYTES];
        result[..48].copy_from_slice(&self.a_bar.to_affine().to_compressed());
        result[48..96].copy_from_slice(&self.b_bar.to_affine().to_compressed());
        result[96..128].copy_from_slice(&self.s.to_be_bytes());
        result[128..160].copy_from_slice(&self.t.to_be_bytes());
        result[160..192].copy_from_slice(&self.challenge_hash.to_be_bytes());
        result
    }

    /// Convert a byte representation to a proof
    pub fn from_bytes(input: &[u8; Self::BYTES]) -> Result<Self, Error> {
        let g1 = |b: &[u8]| -> Result<G1Projective, Error> {
            let buf = <[u8; 48]>::try_from(b)
                .map_err(|_| Error::from_msg(1, "Signature Serialization Error"))?;
            let pt = G1Affine::from_compressed(&buf).map(G1Projective::from);
            if pt.is_some().unwrap_u8() == 1 {
                Ok(pt.unwrap())
            } else {
                Err(Error::from_msg(1, "Signature Serialization Error"))
            }
        };
        let sc = |b: &[u8]| -> Result<Scalar, Error> {
            let buf = <[u8; 32]>::try_from(b)
                .map_err(|_| Error::from_msg(2, "Signature Serialization Error"))?;
            let pt = Scalar::from_be_bytes(&buf);
            if pt.is_some().unwrap_u8() == 1 {
                Ok(pt.unwrap())
            } else {
                Err(Error::from_msg(2, "Signature Serialization Error"))
            }
        };
        Ok(Self {
            a_bar: g1(&input[0..48])?,
            b_bar: g1(&input[48..96])?,
            s: sc(&input[96..128])?,
            t: sc(&input[128..160])?,
            challenge_hash: sc(&input[160..192])?,
        })
    }

}


/// The computed values after running MembershipProof.finalize
#[derive(Debug, Copy, Clone)]
pub struct ProofFinal {
    a_bar: G1Projective,
    b_bar: G1Projective,
    u: G1Projective,
    pair_final: Gt,
    challenge_hash: Scalar,
}

impl ProofFinal {

    /// Return bytes that need to verify the challenge.
    /// A_bar || B_bar || U
    pub fn get_bytes_for_challenge(self, transcript: &mut Transcript){
        transcript.append_message(b"A_bar", self.a_bar.to_bytes().as_ref());
        transcript.append_message(b"B_bar", self.b_bar.to_bytes().as_ref());
        transcript.append_message(b"U", self.u.to_bytes().as_ref());
    }

    pub fn verify(&self, transcript: &mut Transcript) -> bool {
        self.get_bytes_for_challenge(transcript);
        let computed_challenge = Element::from_transcript(PROOF_LABEL, transcript);
        return (self.pair_final.is_identity().unwrap_u8() == 1) && self.challenge_hash == computed_challenge.0;
    }
}


pub fn schnorr(r: Scalar, v: Scalar, challenge: Scalar) -> Scalar {
    v * challenge + r
}


pub fn pair(g1: G1Projective, g2: G2Projective) -> Gt {
    bls12_381_plus::pairing(&g1.to_affine(), &g2.to_affine())
}

pub fn pairing(g1: G1Projective, g2: G2Projective, exp: Scalar) -> Gt {
    let base = g1 * exp;
    bls12_381_plus::pairing(&base.to_affine(), &g2.to_affine())
}

#[cfg(test)]
mod tests {


    use std::{convert::TryFrom, time::Instant};

    use crate::{
        accumulator::Element, proof::Proof, witness::Deletion, Accumulator, MembershipWitness, ProofCommitting, ProofParamsPrivate, ProofParamsPublic, PROOF_LABEL, SecretKey, PublicKey
    };

    
    #[test]
    fn proof_test_fiat_shamir_succeed() {
        // Get public parameters 
        let (mut acc, key) = (Accumulator::random(rand_core::OsRng{}), SecretKey::new(None));
        let pub_key = PublicKey::from(&key);       
        let params_pub = ProofParamsPublic::new(&acc, &pub_key);
        
        // Generate witness and private params for accumulated element
        let id = Element::hash(b"test");
        let wit = MembershipWitness::new(&id, acc, &key);
        let params_priv = ProofParamsPrivate::new(id, &wit);

        // Add params to transcript
        let mut transcript = merlin::Transcript::new(PROOF_LABEL);
        params_pub.add_to_transcript(&mut transcript);

        // Create non-interactive proof using fiat-shamir transform
        let t1 = Instant::now();
        let pc = ProofCommitting::new(&params_pub, &params_priv);
        pc.get_bytes_for_challenge(&mut transcript);
        let challenge_hash = Element::from_transcript(PROOF_LABEL, &mut transcript);
        let proof = pc.gen_proof(challenge_hash);
        let t1 = t1.elapsed();
        
        // Verify proof
        let t2 = Instant::now();
        let mut transcript_ver = merlin::Transcript::new(PROOF_LABEL);
        params_pub.add_to_transcript(&mut transcript_ver);
        let proof_final = proof.finalize(&params_pub);
        proof_final.get_bytes_for_challenge(&mut transcript);
        assert!(proof_final.verify(&mut transcript_ver));
        let t2 = t2.elapsed();

        println!("Time to compute non-revocation proof: {:?}", t1);
        println!("Time to verify non-revocation proof: {:?}", t2);
    }
    
    #[test]
    fn proof_fiat_shamir_fail() {
        // Get public parameters 
        let (mut acc, key) = (Accumulator::random(rand_core::OsRng{}), SecretKey::new(None));
        let pub_key = PublicKey::from(&key);       
        let params_pub = ProofParamsPublic::new(&acc, &pub_key);
        
        // Generate witness and private params for accumulated element
        let id = Element::hash(b"test");
        let wit = MembershipWitness::new(&id, acc, &key);
        let params_priv = ProofParamsPrivate::new(id, &wit);

        // Add params to transcript
        let mut transcript = merlin::Transcript::new(PROOF_LABEL);
        params_pub.add_to_transcript(&mut transcript);

        // Create non-interactive proof using fiat-shamir transform
        let t1 = Instant::now();
        let pc = ProofCommitting::new(&params_pub, &params_priv);
        pc.get_bytes_for_challenge(&mut transcript);
        let challenge_hash = Element::from_transcript(PROOF_LABEL, &mut transcript);
        let proof = pc.gen_proof(challenge_hash);
        let t1 = t1.elapsed();
        
        // Revoke element and update public parameters
        acc.remove_assign(&key, id);
        let params_pub = ProofParamsPublic::new(&acc, &pub_key);
        
        // Check verification fails
        let t2 = Instant::now();
        let mut transcript_ver = merlin::Transcript::new(PROOF_LABEL);
        params_pub.add_to_transcript(&mut transcript_ver);
        let proof_final = proof.finalize(&params_pub);
        proof_final.get_bytes_for_challenge(&mut transcript);
        assert!(!proof_final.verify(&mut transcript_ver));
        let t2 = t2.elapsed();

        println!("Time to compute non-revocation proof: {:?}", t1);
        println!("Time to verify non-revocation proof: {:?}", t2);
    }

    
    #[test]
    fn proof_test_serialize(){
        // Get public parameters 
        let (mut acc, key) = (Accumulator::random(rand_core::OsRng{}), SecretKey::new(None));
        let pub_key = PublicKey::from(&key);       
        let params_pub = ProofParamsPublic::new(&acc, &pub_key);
         
        // Generate witness and private params for accumulated element
        let id = Element::hash(b"test");
        let wit = MembershipWitness::new(&id, acc, &key);
        let params_priv = ProofParamsPrivate::new(id, &wit);
 
        // Add params to transcript
        let mut transcript = merlin::Transcript::new(PROOF_LABEL);
        params_pub.add_to_transcript(&mut transcript);
 
        // Create non-interactive proof using fiat-shamir transform
        let pc = ProofCommitting::new(&params_pub, &params_priv);
        pc.get_bytes_for_challenge(&mut transcript);
        let challenge_hash = Element::from_transcript(PROOF_LABEL, &mut transcript);

        // Serialize and deserialize proof
        let proof = pc.gen_proof(challenge_hash);
        let proof_bytes = proof.to_bytes();
        let proof_from: Proof = Proof::from_bytes(&proof_bytes).unwrap();
        assert!(proof == proof_from);        
        println!("Membership proof: {} bytes", proof_bytes.len());

    }

}
