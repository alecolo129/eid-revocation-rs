use accumulator::{
    accumulator::{Accumulator, Element},
    key::{PublicKey, SecretKey},
    proof::ProofParamsPublic,
    window_mul,
    witness::{MembershipWitness, UpdatePolynomials},
    UpMsg,
};

use blsful::inner_types::{G1Projective, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap};

/// A `RevocationHandle` instance is issued to every new credential holder, and contains an `(acccumulator::Element, accumulator::MembershipWitness)` pair.
///
/// Non-revocation is proved by showing that the associated element `elem` is contained in the public `accumulator::Accumulator`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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

    /// Returns the associated witness `wit`
    pub fn get_witness(&self) -> MembershipWitness {
        return self.wit;
    }

    /// Returns the associated element `elem`
    pub fn get_elem(&self) -> Element {
        return self.elem;
    }

    /// Updates `self.wit`, executing the update over a list of `UpdatePolynomials` instances.
    ///
    /// # Examples:
    /// ```
    /// use entities::RevocationHandle;
    /// use entities::Issuer;
    ///
    /// let mut issuer = Issuer::new(None);
    /// let mut rh1: RevocationHandle = issuer.add("holder_1").expect("Failed to add");
    /// issuer.add("holder_2");
    ///
    /// let update_poly = issuer.revoke("holder_2").unwrap();  
    /// assert!(!rh1.verify(issuer.get_pk(), issuer.get_accumulator()));     
    ///
    /// let update_res = rh1.update_assign(&vec![update_poly]);
    /// assert!(update_res.is_ok());
    /// assert!(rh1.verify(issuer.get_pk(), issuer.get_accumulator()));     
    /// ```
    pub fn update_assign(
        &mut self,
        update_polys: &Vec<UpdatePolynomials>,
    ) -> Result<MembershipWitness, accumulator::Error> {
        let (deletions, omegas) = update_polys
            .iter()
            .map(|poly| (poly.deletions.as_slice(), poly.omegas.as_slice()))
            .unzip();
        self.wit.update_assign(self.elem, &deletions, omegas)
    }

    /// Sequentially updates `self.wit` executing the single update algorithm over the input instances of `UpMsg`.
    ///
    /// # Note:
    /// This algorithm is implemented for comparison tests only.
    /// When computing a large number of updates, `RevocationHandle::update_assign` is considerably more efficient.
    pub fn update_seq_assign(&mut self, updates: &[UpMsg]) {
        self.wit.update_seq_assign(self.elem, updates);
    }

    /// Batch-updates `self.wit` using the input instance of `UpdatePolynomials`.
    ///    
    /// # Note:
    /// This algorithm is implemented for comparison tests only.
    /// When a list of `UpdatePolynomials` instances is given, `RevocationHandle::update_assign` is considerably more efficient than a sequential application of this algorithm.
    pub fn batch_update_assign(
        &mut self,
        update_poly: &UpdatePolynomials,
    ) -> Result<MembershipWitness, accumulator::Error> {
        self.wit
            .batch_update_assign(self.elem, &update_poly.deletions, &update_poly.omegas)
    }

    /// Use `self.wit` to locally verify membership of `self.elem` in a public `accumulator::Accumulator`.
    ///
    /// # Examples:
    /// ```
    /// use entities::RevocationHandle;
    /// use entities::Issuer;
    ///
    /// let mut issuer = Issuer::new(None);
    ///
    /// // Add "holder_1" producing a RevocationHandle instance
    /// let mut rh1: RevocationHandle = issuer.add("holder_1").expect("Failed to add");
    ///
    /// // Check validity of `self.wit` with respect to public values
    /// assert!(rh1.verify(issuer.get_pk(), issuer.get_accumulator()));     
    /// ```
    pub fn verify(&self, pubkey: PublicKey, accumulator: Accumulator) -> bool {
        self.wit.verify(self.elem, pubkey, accumulator)
    }

    /// Updates the witness with the input point
    pub fn update_witness(&mut self, new_wit: G1Projective) {
        self.wit.apply_update(new_wit);
    }
}

/// `Issuer` implements the central credential issuer.
/// It maintains the public accumulator value representing the set of non-revoked credential holders.
#[derive(Debug, Clone)]
pub struct Issuer {
    acc_sk: SecretKey,
    acc_pk: PublicKey,
    acc: Accumulator,
    witnesses: HashMap<String, RevocationHandle>,
    revocation_list: Vec<Element>,
}

impl Issuer {
    /// Creates a new `Issuer`.
    ///
    /// # Arguments
    /// * `seed` - Optional seed for deriving the accumulator's secret key.  
    ///
    /// # Returns
    /// * A new instance of `Issuer`.
    ///
    /// # Examples
    /// ```
    /// let issuer = entities::Issuer::new(None);
    ///   
    /// assert!(issuer.get_witnesses().is_empty());     
    /// ```
    pub fn new(seed: Option<&[u8]>) -> Self {
        let acc_sk = SecretKey::new(seed);
        Self {
            acc_pk: PublicKey::from(&acc_sk),
            acc_sk: acc_sk,
            acc: Accumulator::random(rand_core::OsRng {}),
            witnesses: HashMap::new(),
            revocation_list: Vec::new(),
        }
    }

    /// Adds a new holder to the system.
    /// Generates a new `Revocation Handle` instance, attestating the non-revocation status of the new holder's credential.
    ///
    /// # Arguments
    /// * `pseudo` - A unique pseudonym associated to the new holder.  
    ///
    /// # Returns
    /// * `Some(`RevocationHandle`)` if the addition is succesful.
    /// * `None` if the additon fails (e.g., the pseudonym is not unique).
    ///
    /// # Examples
    /// ```
    /// // Create a new issuer and add holder_1
    /// let mut issuer = entities::Issuer::new(None);
    /// let rh = issuer.add("holder_1").unwrap();
    ///
    /// // Verification succeeds
    /// assert!(rh.verify(issuer.get_pk(), issuer.get_accumulator()));
    ///
    /// // We can't add holder_1 a second time
    /// assert!(issuer.add("holder_1").is_none());
    /// ```
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

    /// Revokes the input credential holder from the system.
    ///
    /// # Arguments
    /// * `pseudo`: pseudonyms of holder to be revoked
    ///
    /// # Returns
    /// * `Some(`UpdatePolynomials`)` if the holder is succesfully revoked.
    /// * `None` the holder could not be revoked (e.g., he was already revoked).
    ///
    /// ```
    ///
    /// let mut issuer = entities::Issuer::new(None);
    /// let rh_1 = issuer.add("holder_1").unwrap();
    /// let rh_2 = issuer.add("holder_2").unwrap();
    /// let rh_3 = issuer.add("holder_3").unwrap();
    ///
    /// // Revoke holder_3
    /// let up_poly = issuer.revoke("holder_3").unwrap();
    ///
    /// // Revocation is enforced
    /// assert!(!rh_1.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(!rh_2.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(!rh_3.verify(issuer.get_pk(), issuer.get_accumulator()));
    ///
    /// // Second revocation of the same user fails
    /// assert!(issuer.revoke("holder_3").is_none());
    ///
    /// ```
    pub fn revoke<T: AsRef<str>>(&mut self, pseudo: T) -> Option<UpdatePolynomials> {
        match self.witnesses.remove(pseudo.as_ref()) {
            Some(rh) => Some(UpdatePolynomials {
                omegas: vec![self.acc.remove_assign(&self.acc_sk, rh.elem).into()],
                deletions: vec![rh.elem],
            }),
            None => None,
        }
    }

    /// Revokes multiple credential holders from the system as a single batch.
    ///
    /// # Arguments
    /// * `pseudos` - The pseudonyms of the holders to be revoked.  
    ///
    /// # Returns
    /// * `Some(`UpdatePolynomial`)` if some holders were succesfully revoked.
    /// * `None` if no holder could be revoked (e.g., all holders were already revoked).
    ///
    /// # Note:
    /// this algorithm has quadratic complexity on the batch size, and it is only maintained for comparison.
    /// For better performances, a sequential application of `issuer::revoke` should be preferred.
    ///
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// let rh_1 = issuer.add("holder_1").unwrap();
    /// let rh_2 = issuer.add("holder_2").unwrap();
    ///
    /// // Try to revoke two valid pseudonyms and an invalid one
    /// let up_poly = issuer.batch_revoke(&[&"holder_1", &"holder_2", &"holder_3"]).unwrap();
    ///
    /// // The two valid pseudonyms are actually revoked
    /// assert!(up_poly.deletions.len() == 2);
    /// assert!(!rh_1.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(!rh_2.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// ```
    pub fn batch_revoke<T: AsRef<str>>(&mut self, pseudos: &[T]) -> Option<UpdatePolynomials> {
        // Create list of deletions with all the elements associated to existing pseudonyms
        let deletions: Vec<Element> = pseudos
            .iter()
            .filter_map(|pseudo| match self.witnesses.remove(pseudo.as_ref()) {
                Some(rh) => Some(rh.elem),
                None => None,
            })
            .collect();

        // Return None if no pseudonym was valid
        if deletions.is_empty() {
            return None;
        }

        // Otherwise revoke all valid pseudonyms, updating accumulator and computing update poly
        let omegas = self.acc.update_assign(&self.acc_sk, deletions.as_slice());
        Some(UpdatePolynomials { deletions, omegas })
    }

    /// Sequentially revokes multiple credential holder from the system.
    ///
    /// # Arguments
    /// * `pseudos`: pseudonyms of holders to be revoked
    ///
    /// # Returns
    /// * `Some(`Vec<UpMsg>`)` if some holders were succesfully revoked.
    /// * `None` no holder could be revoked (e.g., all holders were already revoked).
    ///
    /// # Examples:
    /// ```
    ///
    /// let mut issuer = entities::Issuer::new(None);
    /// let rh_1 = issuer.add("holder_1").unwrap();
    /// let rh_2 = issuer.add("holder_2").unwrap();
    /// let rh_3 = issuer.add("holder_3").unwrap();
    ///
    /// // Revoke holder_2 and holder_3
    /// let up_msgs = issuer.revoke_seq(&["holder_2", "holder_3"]).unwrap();
    ///
    /// // Revocation is enforced
    /// assert!(!rh_1.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(!rh_2.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(!rh_3.verify(issuer.get_pk(), issuer.get_accumulator()));
    ///
    /// // Second revocation of the same user fails
    /// assert!(issuer.revoke("holder_2").is_none());
    /// assert!(issuer.revoke_seq(&["holder_2", "holder_3"]).is_none());
    /// ```
    pub fn revoke_seq<T: AsRef<str>>(&mut self, pseudos: &[T]) -> Option<Vec<UpMsg>> {
        let polys: Vec<_> = pseudos
            .iter()
            .filter_map(|pseudo| match self.witnesses.remove(pseudo.as_ref()) {
                // Only revoke valid holders
                Some(rh) => Some(UpMsg::new(
                    self.acc.remove_assign(&self.acc_sk, rh.elem),
                    rh.elem,
                )),
                None => None,
            })
            .collect();

        match polys.len() {
            0 => None,
            _ => Some(polys),
        }
    }

    /// Adds some credential holders to the list of revocations to be performed in the future.
    /// This action locally invalidates the input holders: any subsequent application of `Issuer::revoke` on one of these holders will fail.
    ///
    /// # Arguments
    /// * `pseudos` - The unique pseudonyms associated to the input holders.  
    ///
    /// # Returns
    /// * `usize` the number of holders succesfully added to the revocation list.
    ///
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// let rh = issuer.add("holder_1").unwrap();
    ///
    /// // Locally invalidate "holder_1" by adding it to the revocation list
    /// let added = issuer.add_to_revocation_list(&["holder_1", "invalid"]);
    /// assert_eq!(added, 1);
    ///
    /// // Witness is still valid until `issuer::revoke_list' is called
    /// assert!(rh.verify(issuer.get_pk(), issuer.get_accumulator()));
    ///
    /// // Any subsequent revocation of the invalidated user fails
    /// assert!(issuer.revoke("holder_1").is_none());
    /// ```
    pub fn add_to_revocation_list<T: AsRef<str>>(&mut self, pseudos: &[T]) -> usize {
        pseudos
            .iter()
            .map(|pseudo| {
                match self.witnesses.remove(pseudo.as_ref()) {
                    // If pseudo was in witness list, add to revocation list and count 1
                    Some(rh) => {
                        self.revocation_list.push(rh.elem);
                        1
                    }
                    // Otherwise do nothing
                    None => 0,
                }
            })
            .sum()
    }

    /// Batch-revoke all the holders contained in the revocation list.
    ///    
    /// # Returns
    /// * `Some(`UpdatePolynomial`)` if some holders were succesfully revoked.
    /// * `None` if the revocation fails (e.g., the revocation list is empty).
    ///
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    ///
    /// let rh_1 = issuer.add("holder_1").unwrap();
    /// let rh_2 = issuer.add("holder_2").unwrap();
    /// let rh_3 = issuer.add("holder_3").unwrap();
    ///
    /// // Add first two holders to revocation list
    /// issuer.add_to_revocation_list(&[&"holder_1", &"holder_2"]);
    ///
    /// /*
    ///     ........ other operations ........
    /// */  
    ///
    /// // Add last holder to revocation list
    /// issuer.add_to_revocation_list(&[&"holder_3"]);
    ///
    /// // Revoke all holders in list
    /// let up_poly = issuer.revoke_list().unwrap();
    /// assert!(up_poly.deletions.len()==3);
    /// assert!(issuer.revoke_list().is_none());
    ///
    /// // Revocation is enforced
    /// assert!(!rh_1.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(!rh_2.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(!rh_3.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// ```
    pub fn revoke_list(&mut self) -> Option<UpdatePolynomials> {
        // If no deletions return `None`
        if self.revocation_list.is_empty() {
            return None;
        }

        //Compute update polys
        let omegas = self
            .acc
            .update_assign(&self.acc_sk, self.revocation_list.as_slice());
        let polys = UpdatePolynomials {
            deletions: self.revocation_list.clone(),
            omegas,
        };

        //Clear list of deletions
        self.revocation_list.clear();

        return Some(polys);
    }

    /// Performs a periodic update. Revokes any element left in the list of deletions and update all witnesses.
    ///
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    ///
    /// let mut rh_1 = issuer.add("holder_1").unwrap();
    /// let mut rh_2 = issuer.add("holder_2").unwrap();
    /// let rh_3 = issuer.add("holder_3").unwrap();
    ///
    /// // Add holder_3 to revocation list
    /// issuer.add_to_revocation_list(&[&"holder_3"]);
    ///
    /// // Execute periodic update
    /// issuer.update_periodic();
    /// assert!(issuer.revoke_list().is_none());
    ///
    /// // Revocation is enforced
    /// assert!(!rh_1.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(!rh_2.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(!rh_3.verify(issuer.get_pk(), issuer.get_accumulator()));
    ///
    /// let witnesses = issuer.get_witnesses();
    ///
    /// // Updated witnesses are computed for revoked holders
    /// rh_1.update_witness(witnesses["holder_1"].0);
    /// rh_2.update_witness(witnesses["holder_2"].0);
    /// assert!(rh_1.verify(issuer.get_pk(), issuer.get_accumulator()));
    /// assert!(rh_2.verify(issuer.get_pk(), issuer.get_accumulator()));
    ///
    /// // No witness is computed for revoked holder
    /// assert!(!witnesses.contains_key("holder_3"));
    /// ```
    pub fn update_periodic(&mut self) {
        // Create new random accumulator
        self.acc = Accumulator::random(rand_core::OsRng {});

        // Any remaining element is automatically revoked by the new accumulator
        self.revocation_list.clear();

        // Compute updated witnesses for all valid users (i.e., [(\alpha + y_1)^-1, ..., (\alpha + y_m)^-1])
        let new_wits = window_mul(
            self.acc.0,
            self.witnesses
                .iter()
                .map(|(_, rh)| self.acc_sk.batch_deletions(&[rh.get_elem()]).0)
                .collect(),
        );

        self.witnesses
            .iter_mut()
            .enumerate()
            .for_each(|(i, (_, rh))| rh.update_witness(new_wits[i]));
    }

    /// Get the current accumulator value.
    ///
    /// # Returns
    /// * `Accumulator`: the current accumulator value.
    ///
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// let acc_1 = issuer.get_accumulator();
    ///
    /// // Additions don't modify the accumulator value
    /// issuer.add("holder_1").unwrap();
    /// assert_eq!(acc_1, issuer.get_accumulator());
    ///
    /// // Revocations modify the accumulator value
    /// issuer.revoke("holder_1").unwrap();
    /// assert!(acc_1 != issuer.get_accumulator());
    /// ```
    pub fn get_accumulator(&self) -> Accumulator {
        self.acc
    }

    /// Get the identifier associated to the current accumulator
    ///
    /// # Returns
    /// * `Scalar`: the accumulator's identifier.
    ///
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// let id = issuer.get_accumulator_id();
    /// ```
    pub fn get_accumulator_id(&self) -> Scalar {
        self.acc.get_id()
    }

    /// Get the issuer's public key
    ///
    /// # Returns
    /// * `PublicKey`: the issuer's public key.
    ///
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// let pk = issuer.get_pk();
    /// ```
    pub fn get_pk(&self) -> PublicKey {
        return self.acc_pk;
    }

    /// Get the public parameters used for generating and verifying membership proofs.
    ///
    /// # Returns
    /// * `ProofParametersPublic` an up-to-date instance of the public parameters (i.e., accumulator value and accumulator public key).
    ///
    /// # Examples
    /// ```
    /// let issuer = entities::Issuer::new(None);
    /// let proof_params = issuer.get_proof_params();
    /// ```
    pub fn get_proof_params(&self) -> ProofParamsPublic {
        ProofParamsPublic::new(&self.acc, &self.acc_pk)
    }

    /// Get all witnesses associated to valid holders.
    ///
    /// # Returns
    /// * `HashMap<String, MembershipWitness>` a dictionary where keys are holders pseudonyms and values are the associated witnesses.
    ///
    /// # Examples
    /// ```
    /// let mut issuer = entities::Issuer::new(None);
    /// let rh = issuer.add("holder_1").unwrap();
    /// let witness_dict = issuer.get_witnesses();
    /// assert_eq!(rh.get_witness(), witness_dict["holder_1"]);
    /// ```
    pub fn get_witnesses(&self) -> HashMap<String, MembershipWitness> {
        //Return witness list
        let wit: HashMap<String, MembershipWitness> = self
            .witnesses
            .iter()
            .map(|(k, v)| (k.clone(), v.wit))
            .collect();
        return wit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    const ADD_SIZE: usize = 1000;

    #[test]
    fn issuer_setup() {
        let time = Instant::now();
        let iss = Issuer::new(None);
        iss.get_proof_params();
        println!("Setup time: {:?}", time.elapsed())
    }

    #[test]
    fn issuer_add_succeed() {
        let mut iss = Issuer::new(None);

        let t = Instant::now();
        let rh = iss.add("test").expect("Cannot issue witness");
        println!("Time to add new holder: {:?}", t.elapsed());

        assert!(rh.verify(iss.get_pk(), iss.get_accumulator()));
    }

    #[test]
    fn issuer_add_fail() {
        let mut iss = Issuer::new(None);
        let rh = iss.add("test").expect("Cannot issue witness");
        assert!(rh.verify(iss.get_pk(), iss.get_accumulator()));

        // Trying to add same pseudo multiple times fails
        for _ in 0..3 {
            assert!(iss.add("test").is_none());
        }
        assert!(rh.verify(iss.get_pk(), iss.get_accumulator()));
    }

    #[test]
    fn issuer_revoke() {
        // Setup issuer
        let mut issuer = Issuer::new(None);

        // Add ADD_SIZE elements
        let mut rhs = Vec::with_capacity(ADD_SIZE);
        (0..ADD_SIZE).for_each(|i| {
            rhs.push(issuer.add(i.to_string()).expect("Cannot add witness"));
        });

        // Delete one of the elements and compute update
        let t = Instant::now();
        let polys = issuer.revoke(&"0").expect("Non existing element");
        println!(
            "Time to remove one element and compute update polynomial: {:?}",
            t.elapsed()
        );

        // No element is added to revocation list
        assert!(issuer.revocation_list.is_empty());

        // Consider revoked and non-revoked revocation handles
        let mut revoked_rh = rhs[0];
        let mut valid_rh = rhs[1];

        // Check revocation is enforced
        assert!(!valid_rh.verify(issuer.get_pk(), issuer.get_accumulator()));
        assert!(!revoked_rh.verify(issuer.get_pk(), issuer.get_accumulator()));

        // Check update succeeds only for non-revoked handle
        assert!(valid_rh.update_assign(&vec![polys.clone()]).is_ok());
        assert!(revoked_rh.update_assign(&vec![polys]).is_err());

        assert!(valid_rh.verify(issuer.get_pk(), issuer.get_accumulator()));
        assert!(!revoked_rh.verify(issuer.get_pk(), issuer.get_accumulator()));
    }

    #[test]
    fn issuer_batch_revoke() {
        // Setup issuer
        let mut issuer = Issuer::new(None);

        // Add ADD_SIZE elements
        let mut rhs = Vec::with_capacity(ADD_SIZE);
        (0..ADD_SIZE).for_each(|i| {
            rhs.push(issuer.add(i.to_string()).expect("Cannot add witness"));
        });

        // Revoke ADD_SIZE/2 elements and compute update polys
        let num_deletions = ADD_SIZE / 2;
        let deletions: Vec<String> = (0..num_deletions).map(|i| i.to_string()).collect();
        let t = Instant::now();
        let polys = issuer.batch_revoke(deletions.as_slice());
        println!(
            "Time to revoke {num_deletions} witness and compute update polynomials: {:?}",
            t.elapsed()
        );
        let polys = polys.expect("Deletion list is empty");

        // No element is added to revocation list
        assert!(issuer.revocation_list.is_empty());

        // Consider revoked and non-revoked revocation handles
        let mut revoked_rh = rhs[0];
        let mut valid_rh = rhs[num_deletions];

        // Check revocation is enforced
        assert!(!revoked_rh.verify(issuer.get_pk(), issuer.get_accumulator()));
        assert!(!valid_rh.verify(issuer.get_pk(), issuer.get_accumulator()));

        // Check update succeeds only for non-revoked handle
        assert!(revoked_rh.batch_update_assign(&polys).is_err());
        assert!(valid_rh.batch_update_assign(&polys).is_ok());

        assert!(!revoked_rh.verify(issuer.get_pk(), issuer.get_accumulator()));
        assert!(valid_rh.verify(issuer.get_pk(), issuer.get_accumulator()));
    }

    #[test]
    fn issuer_mixed_single_batch() {
        // Setup issuer
        let mut issuer = Issuer::new(None);

        // Add ADD_SIZE elements
        let mut rhs = Vec::with_capacity(ADD_SIZE);
        (0..ADD_SIZE).for_each(|i| {
            rhs.push(issuer.add(i.to_string()).expect("Cannot add witness"));
        });

        // Revoke one of the elements and compute update
        let t = Instant::now();
        let mut polys = vec![issuer.revoke(&"1").unwrap()];
        println!(
            "Time to remove one element and compute update message: {:?}",
            t.elapsed()
        );

        // Batch revoke ADD_SIZE/2 - 1 elements
        let t = Instant::now();
        let revoked_pseudos: Vec<String> = (1..ADD_SIZE / 2).map(|i| i.to_string()).collect();
        polys.push(issuer.batch_revoke(&revoked_pseudos.as_slice()).unwrap());

        println!(
            "Time to remove {} elements and compute update polynomials: {:?}",
            ADD_SIZE / 2 - 2,
            t.elapsed()
        );

        // Only non-revoked elements (i.e., in [2, ADD_SIZE/2-1)) have beend batched
        assert_eq!(polys.last().unwrap().deletions.len(), ADD_SIZE / 2 - 2);

        // Add one of the elements to revocation list
        let t = Instant::now();
        issuer.add_to_revocation_list(&[(ADD_SIZE / 2 + 1).to_string()]);
        println!(
            "Time to remove one element without computing update: {:?}",
            t.elapsed()
        );

        // Trying to instantly revoke the same element fails
        assert!(issuer.revoke(&(ADD_SIZE / 2 + 1).to_string()).is_none());

        // Re-add the same element and all the remaining elemnts to revocation list
        let t = Instant::now();
        let revoked_pseudos: Vec<String> = (ADD_SIZE / 2 + 1..ADD_SIZE)
            .map(|i| i.to_string())
            .collect();
        issuer.add_to_revocation_list(revoked_pseudos.as_slice());
        println!(
            "Time to add {} elements to revocation list: {:?}",
            ADD_SIZE - ADD_SIZE / 2 - 2,
            t.elapsed()
        );

        let t = Instant::now();
        let rev_number = issuer.revocation_list.len();
        polys.push(issuer.revoke_list().expect("No update poly"));
        println!(
            "Time to revoke a list of {} elements: {:?}",
            rev_number,
            t.elapsed()
        );

        // No element is left in revocation list
        assert!(issuer.revocation_list.is_empty());

        // Consider revoked and non-revoked revocation handles
        let mut revoked_rh = rhs[1];
        let mut valid_rh = rhs[0];

        // Check revocation is enforced
        assert!(!revoked_rh.verify(issuer.get_pk(), issuer.get_accumulator()));
        assert!(!valid_rh.verify(issuer.get_pk(), issuer.get_accumulator()));

        // Check update succeeds only for non-revoked handle
        assert!(revoked_rh.update_assign(&polys).is_err());
        assert!(valid_rh.update_assign(&polys).is_ok());

        assert!(!revoked_rh.verify(issuer.get_pk(), issuer.get_accumulator()));
        assert!(valid_rh.verify(issuer.get_pk(), issuer.get_accumulator()));
    }

    #[test]
    fn issuer_epoch_update() {
        // Setup issuer
        let mut issuer = Issuer::new(None);

        // Add ADD_SIZE elements
        let mut rhs = Vec::with_capacity(ADD_SIZE);
        (0..ADD_SIZE).for_each(|i| {
            rhs.push(issuer.add(i.to_string()).expect("Cannot add witness"));
        });

        // Simulate we have ADD_SIZE/2 elements to delete
        let num_deletions = ADD_SIZE / 2;
        let deletions: Vec<String> = (0..num_deletions).map(|i| i.to_string()).collect();
        issuer.add_to_revocation_list(deletions.as_slice());

        // Revoke removed elements and update all witnessses for valid elements
        let t = Instant::now();
        issuer.update_periodic();
        println!(
            "Time to compute periodic update of {} witness: {:?}",
            ADD_SIZE - num_deletions,
            t.elapsed()
        );

        let new_wits = issuer.get_witnesses();

        // Check all witnesses in previous witnesss list are invalid
        (0..ADD_SIZE).for_each(|i| {
            assert!(!rhs[i].verify(issuer.get_pk(), issuer.get_accumulator()));
        });

        // Check non-revoked witness are updated
        (num_deletions..ADD_SIZE).for_each(|i| {
            let wit = new_wits
                .get(&i.to_string())
                .expect("Non-revoked element is not present in witness list!");
            rhs[i].update_witness(wit.0);
            assert!(rhs[i].verify(issuer.get_pk(), issuer.get_accumulator()))
        });

        // Check revoked witness are not updated
        (0..num_deletions).for_each(|i| {
            assert!(new_wits.get(&i.to_string()).is_none());
        });
    }
}
