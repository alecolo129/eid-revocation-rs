use super::{
    aggregate_eval_omega, Accumulator, Coefficient, Element, Error, PolynomialG1, PublicKey,
    SecretKey,
};

use blsful::inner_types::*;
use core::{convert::TryFrom, fmt};
use group::{Curve, Group, GroupEncoding};
use serde::{Deserialize, Serialize};

/// Represents a pair or update polynomials (\omega(x), dD(x))
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePolynomials {
    pub deletions: Vec<Element>,
    pub omegas: Vec<Coefficient>,
}

// Groups the deleted element and new accumulator value
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpMsg {
    acc: Accumulator,
    el: Element,
}

impl UpMsg {
    pub fn new(acc: Accumulator, el: Element) -> Self {
        Self { acc, el }
    }

    pub fn get_element(&self) -> Element {
        self.el
    }

    pub fn get_coefficient(&self) -> Coefficient {
        return Coefficient(self.acc.0);
    }

    pub fn get_accumulator(&self) -> Accumulator {
        return self.acc;
    }
}

impl Into<UpdatePolynomials> for UpMsg {
    fn into(self) -> UpdatePolynomials {
        UpdatePolynomials {
            deletions: vec![self.get_element()],
            omegas: vec![self.get_coefficient()],
        }
    }
}

/// A membership witness that can be used for membership proof generation,
/// as described in Section 4 in my thesis
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MembershipWitness(pub G1Projective);

impl fmt::Display for MembershipWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MembershipWitness {{ {} }}", self.0)
    }
}

impl From<MembershipWitness> for G1Projective {
    fn from(m: MembershipWitness) -> Self {
        m.0
    }
}

impl From<G1Projective> for MembershipWitness {
    fn from(g: G1Projective) -> Self {
        Self(g)
    }
}

impl TryFrom<&[u8; 48]> for MembershipWitness {
    type Error = Error;

    fn try_from(value: &[u8; 48]) -> Result<Self, Self::Error> {
        let pt = G1Affine::from_compressed(value).map(G1Projective::from);
        if pt.is_some().unwrap_u8() == 1 {
            Ok(Self(pt.unwrap()))
        } else {
            Err(Error {
                message: String::from("incorrect byte sequence"),
                code: 1,
            })
        }
    }
}

impl MembershipWitness {
    const BYTES: usize = 80;

    /// Compute the witness associated to a prehashed `value`, for the input `accumulator` and respective `secret_key`
    pub fn new(value: &Element, accumulator: Accumulator, secret_key: &SecretKey) -> Self {
        Self(accumulator.remove(secret_key, *value).0)
    }

    /// Takes as input the associated element `e`, and a list of update messages `updates`.
    /// Sequentially applies the single witness update algorithm.
    ///
    /// Returns a new up-to-date witness if e was not revoked, an invalid witness otherwise
    pub fn update_seq(&self, e: Element, updates: &[UpMsg]) -> Self {
        let mut clone = *self;
        clone.update_seq_assign(e, updates);
        clone
    }

    /// Takes as input the associated element `e`, and a list of update messages `del`.
    /// Sequentially applies the single witness update algorithm.
    ///
    /// Updates the witness if `e` was not revoked, otherwise returns an invalid witness.
    pub fn update_seq_assign(&mut self, e: Element, updates: &[UpMsg]) {
        // Membership witness single update algorithm as defined in page 25 (Figure 4.1) of my thesis.

        // A_{t+1} = 1/(e_t - e) (A_t - V_{t+1})
        for msg in updates {
            // e_t =  msg.get_element()
            let mut inv = msg.get_element().0 - e.0;

            // If this fails, then `e` was removed
            let t = inv.invert();
            if bool::from(t.is_none()) {
                return;
            }
            inv = t.unwrap();

            // V_{t+1} = msg.get_accumulator().0
            self.0 -= msg.get_accumulator().0;
            self.0 *= inv;
        }
    }

    /// Perform batch update using the associated element `e`, the list of coefficients `omega`,
    /// and list of deleted elements `deletions`.
    ///
    /// Returns a new updated instance of `MembershipWitness` or `Error`.
    pub fn batch_update(
        &self,
        e: Element,
        deletions: &[Element],
        omega: &[Coefficient],
    ) -> Result<MembershipWitness, Error> {
        return self.clone().batch_update_assign(e, deletions, omega);
    }

    /// Perform batch update of the witness in-place
    /// using the associated element `e`, the list of coefficients `omega`,
    /// and list of deleted elements `deletions`.
    ///
    /// Returns a new updated instance of `MembershipWitness` or `Error`
    pub fn batch_update_assign(
        &mut self,
        e: Element,
        deletions: &[Element],
        omega: &[Coefficient],
    ) -> Result<MembershipWitness, Error> {
        // d(e) = ∏ 1..m (e_i - e)
        let mut d_e = dd_eval(&vec![deletions], e.0);

        let t = d_e.invert();

        // If this fails, then this value was removed
        if bool::from(t.is_none()) {
            return Err(Error::from_msg(1, "no inverse exists"));
        }
        d_e = t.unwrap();

        // Build polynomial from coefficient list
        let poly = PolynomialG1(
            omega
                .as_ref()
                .iter()
                .map(|c| c.0)
                .collect::<Vec<G1Projective>>(),
        );

        // Compute Ω(e) using Pippenger's approach for Multi Scalar Multiplication
        if let Some(v) = poly.msm(&e.0) {
            // A_{t+1} = 1/d(e) * (A - Ω(e))
            self.0 -= v;
            self.0 *= d_e;
            Ok(*self)
        } else {
            Err(Error::from_msg(2, "polynomial could not be evaluated"))
        }
    }

    /// Perform batch updates of the witness aggregating the list of coefficients `omegas`
    /// and using the associated element `e`,
    /// and list of deleted elements `deletions`.
    ///
    /// Returns a new updated instance of `MembershipWitness` or `Error`
    pub fn update(
        &mut self,
        e: Element,
        deletions: &Vec<&[Element]>,
        omegas: Vec<&[Coefficient]>,
    ) -> Result<MembershipWitness, Error> {
        return self.clone().update_assign(e, deletions, omegas);
    }

    /// Perform batch updates of the witness in-place aggregating the list of coefficients `omegas`
    /// and using the associated element `e`,
    /// and list of deleted elements `deletions`.
    ///
    /// Returns a new updated instance of `MembershipWitness` or `Error`
    pub fn update_assign(
        &mut self,
        e: Element,
        deletions: &Vec<&[Element]>,
        omegas: Vec<&[Coefficient]>,
    ) -> Result<MembershipWitness, Error> {
        // Build update polynomials using omega coefficients
        let coeff = omegas
            .into_iter()
            .map(|omega| {
                PolynomialG1(
                    omega
                        .into_iter()
                        .map(|&coeff| coeff.into())
                        .collect::<Vec<G1Projective>>(),
                )
            })
            .collect::<Vec<PolynomialG1>>();

        // Compute evaluations a_{t+1},...,a_{t+n} as in page 39 of my thesis
        let scalars = dd_evals(deletions, e.0);

        // d_{t -> t+n}(e) = ∏^{t+m}_{i=t+1} d_i(e) = d_{t+1}(e) * a_{t+n}
        let mut d_d: Scalar =
            scalars.last().unwrap() * dd_eval(&vec![deletions.last().unwrap()], e.0);
        let t = d_d.invert();

        // If this fails, then 'e' was removed
        if bool::from(t.is_none()) {
            return Err(Error::from_msg(1, "no inverse exists"));
        }
        d_d = t.unwrap();

        // Compute aggragated evaluation Ω_{t->t+n}(e) using Multi Scalar Multiplication
        if let Some(v) = aggregate_eval_omega(coeff, &scalars, e.0) {
            // A_{t+n} = 1 / d_{t->t+n}(e) * (A_t - Ω_{t->t+n}(e))
            self.0 -= v;
            self.0 *= d_d;
            Ok(*self)
        } else {
            Err(Error::from_msg(2, "polynomial could not be evaluated"))
        }
    }

    /// Substitutes the underlying G1 point with the `new_wit` given as input.
    pub fn apply_update(&mut self, new_wit: G1Projective) {
        self.0 = new_wit;
    }

    /// Directly verify that this is a valid witness for element `e`, public key `pubkey`, and accumulator value `accumulator`.
    pub fn verify(&self, y: Element, pubkey: PublicKey, accumulator: Accumulator) -> bool {
        let mut p = G2Projective::GENERATOR;
        p *= y.0;
        p += pubkey.0;
        let g2 = G2Projective::GENERATOR;

        // e(A_t, eG_2 + X) == e(V_t, G_2) <=>  e(A_t, eG_2 + X) - e(V_t, G_2) == 0_{G_t}
        bool::from(
            multi_miller_loop(&[
                // e(A_t, eG_2 + X)
                (&self.0.to_affine(), &G2Prepared::from(p.to_affine())),
                // e(V_t, G_2)
                (
                    &accumulator.0.to_affine(),
                    &G2Prepared::from(-g2.to_affine()),
                ),
            ])
            .final_exponentiation()
            .is_identity(),
        )
    }

    /// Return the byte sequence for this witness.
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut res = [0u8; Self::BYTES];
        res.copy_from_slice(self.0.to_bytes().as_ref());
        res
    }

    /// Old unoptimized version from ALLOSAUR implementation, just for testing
    fn _batch_update_assign(
        &mut self,
        y: Element,
        deletions: &[Element],
        coefficients: &[Coefficient],
    ) -> Result<MembershipWitness, Error> {
        // dD(x) = ∏ 1..m (yD_i - x)
        let mut d_d = dd_eval(&vec![deletions], y.0);

        let t = d_d.invert();
        // If this fails, then this value was removed
        if bool::from(t.is_none()) {
            return Err(Error::from_msg(1, "no inverse exists"));
        }
        d_d = t.unwrap();

        let poly = PolynomialG1(
            coefficients
                .as_ref()
                .iter()
                .map(|c| c.0)
                .collect::<Vec<G1Projective>>(),
        );

        // Compute〈Υy,Ω〉using direct evaluation
        if let Some(v) = poly.evaluate(&y.0) {
            // C' = 1 / dD * (C -〈Υy,Ω))
            self.0 -= v;
            self.0 *= d_d;
            Ok(*self)
        } else {
            Err(Error::from_msg(2, "polynomial could not be evaluated"))
        }
    }
}

/// Evaluates poly d(e) = ∏ 1..m (e_i - e)
fn dd_eval(values: &Vec<&[Element]>, e: Scalar) -> Scalar {
    values
        .iter()
        .map(|value| {
            value
                .iter()
                .map(|e_i| e_i.0 - e)
                .fold(Scalar::ONE, |s_i, e| s_i * e)
        })
        .product()
}

/// Creates list of evaluations for aggregating multiple update polynomials.
///
/// Uses the list of batch deletions `batch_dels`, and the element `e`
/// to compute the list of evaluatations `a_{t+1},...,a_{t+n}` as by page 39 of my thesis.
fn dd_evals(batch_dels: &Vec<&[Element]>, e: Scalar) -> Vec<Scalar> {
    let mut res = Vec::with_capacity(batch_dels.len());

    //`[1, d_{t+2}(e), d_{t+2}(e)*d_{t+3}(e),...,∏^{t+n}_{i=t+2} d_i(e)]`
    res.push(Scalar::ONE);
    batch_dels[0..batch_dels.len() - 1]
        .iter()
        .for_each(|&value| {
            res.push(res.last().unwrap() * dd_eval(&vec![value], e));
        });
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key;
    use std::time::Duration;
    use std::time::Instant;

    fn init(upd_size: usize) -> (key::SecretKey, key::PublicKey, Accumulator, Vec<Element>) {
        let key = SecretKey::new(Some(b"1234567890"));
        let pubkey = PublicKey::from(&key);
        let mut elements = vec![Element::one(); upd_size];

        (0..upd_size).for_each(|i| elements[i] = Element::hash(i.to_string().as_bytes()));

        let acc = Accumulator::random(rand_core::OsRng {});
        (key, pubkey, acc, elements)
    }

    fn wit_sequential_update(upd_size: usize) {
        let (key, pubkey, mut acc, elements) = init(upd_size + 1);

        // Non revoked (y,C) pair
        let elem = elements[0];
        let mut wit = MembershipWitness::new(&elem, acc, &key);

        // Revoked (y,C) pair
        let elem_d = elements[1];
        let mut wit_d = MembershipWitness::new(&elem_d, acc, &key);

        // Revoke everyone except for elem
        let dels = &elements[1..];
        let mut deletions: Vec<UpMsg> = Vec::new();
        dels.iter().for_each(|&d| {
            // Modify accumulator
            acc.remove_assign(&key, d);
            // Create update message
            deletions.push(UpMsg { acc, el: d });
        });

        // Update non-revoked element sequentially applying single update algorithm
        let t = Instant::now();
        wit.update_seq_assign(elem, &deletions.as_slice());
        let t = t.elapsed();

        // Try update revoked elem
        wit_d.update_seq_assign(elem_d, &deletions.as_slice());

        assert!(wit.verify(elem, pubkey, acc));
        assert!(!wit.verify(elem_d, pubkey, acc));

        println!(
            "Sequential update of {} deletions: {:?}",
            deletions.len(),
            t
        );
    }

    fn wit_batch_update(upd_size: usize) {
        let (key, pubkey, mut acc, elements) = init(upd_size + 1);

        // Non revoked (y, wit) pair
        let y = elements[0];
        let mut wit = MembershipWitness::new(&y, acc, &key);

        // Revoked (y_d, wit_d) pair
        let y_d = elements[1];
        let mut wit_d = MembershipWitness::new(&y_d, acc, &key);

        // Revoke y_1, ..., y_(upd_size-1) and compute coefficients for batch update
        let deletions = &elements[1..];
        let coefficients = acc.update_assign(&key, deletions);

        // Update non-revoked element with both versions
        let mut wit2 = wit.clone();
        let t1 = Instant::now();
        wit.batch_update_assign(y, deletions, &coefficients)
            .expect("Error when evaluating poly");
        let t1 = t1.elapsed();
        let t2 = Instant::now();
        wit2._batch_update_assign(y, deletions, &coefficients)
            .expect("Error when evaluating poly");
        let t2 = t2.elapsed();

        // Try updating revoked element
        assert!(wit_d
            .batch_update_assign(y_d, deletions, &coefficients)
            .is_err());

        // Check (non)revocation of updated witness
        assert!(!wit_d.verify(y_d, pubkey, acc));
        assert!(wit.verify(y, pubkey, acc));

        println!(
            "Batch update of {} deletions without MSM: {:?}",
            deletions.len(),
            t2
        );
        println!(
            "Batch update of {} deletions with MSM: {:?}",
            deletions.len(),
            t1
        );
    }

    fn wit_batch_updates(number_upds: usize, batch_size: usize) {
        let (key, pubkey, mut acc, elements) = init(number_upds * batch_size + 1);

        // Non revoked (e, wit) pair
        let e = elements[0];
        let mut wit = MembershipWitness::new(&e, acc, &key);

        // Revoke e_1, ..., e_{upd_size} and compute coefficients for batch update
        let deletions: Vec<&[Element]> = elements[1..].chunks(batch_size).collect();

        // Compute update coefficients
        let mut coefficients = Vec::new();
        for i in 0..number_upds {
            coefficients.push(acc.update_assign(&key, &deletions[i]));
        }

        // Update non-revoked element with both versions
        let mut wit2 = wit.clone();

        let t1 = Instant::now();
        wit.update_assign(
            e,
            &deletions,
            coefficients.iter().map(|v| v.as_slice()).collect(),
        )
        .expect("Error when evaluating poly");
        let t1 = t1.elapsed();

        let mut t2 = Duration::from_micros(0);
        for i in 0..deletions.len() {
            let t = Instant::now();
            wit2.batch_update_assign(e, deletions[i], coefficients[i].as_slice())
                .expect("Error when evaluating poly");
            t2 += t.elapsed();
        }

        println!(
            "Batch update of {} deletions without aggregation: {:?}",
            deletions.len(),
            t2
        );
        println!(
            "Batch update of {} deletions with aggregation: {:?}",
            deletions.len(),
            t1
        );

        // Check (non)revocation of updated witness
        assert!(wit2.verify(e, pubkey, acc));
        assert!(wit.verify(e, pubkey, acc));
    }

    // Test sequential and batch updates
    #[test]
    fn wit_test_update() {
        let upd_size = 10_000;
        wit_sequential_update(upd_size);
        wit_batch_update(upd_size);

        let batch_size = 1;
        wit_batch_updates(upd_size, batch_size);
    }

    // Test serialization
    #[test]
    fn wit_test_serialize() {
        // Init parameters
        let sk = SecretKey::new(Some(b"test"));
        let acc = Accumulator::random(rand_core::OsRng {});
        let wit = MembershipWitness::new(&Element::hash(b"test"), acc, &sk);

        // Try serialize and deserialize
        let bytes = bincode::serialize(&wit).expect("Serialization error!");
        let wit = bincode::deserialize::<MembershipWitness>(&bytes).expect("Deserialization error");

        // Check witness verifies
        assert!(wit.verify(Element::hash(b"test"), PublicKey::from(&sk), acc))
    }
}
