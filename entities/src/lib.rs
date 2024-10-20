pub mod holder;
pub mod issuer;
pub mod verifier;

pub use holder::*;
pub use issuer::*;
pub use verifier::*;

/// Client trait for updating public parameters
pub trait Updatable {
    fn update_accumulator(&mut self, acc: accumulator::Accumulator);
    fn update_public_params(&mut self, new_pp: accumulator::ProofParamsPublic);
}
