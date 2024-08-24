use std::{time::Instant, usize, cmp::max};
use ark_ff::{One, Zero};
use bls12_381_plus::{elliptic_curve::hash2curve::ExpandMsgXof, G1Projective, Scalar};
use digest::{ExtendableOutput, Update, XofReader};
use group::ff::{Field, PrimeField};
use rand_core::{CryptoRng, RngCore};
use sha3::Shake256;

/// Similar to https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3
/// info is left blank
pub fn generate_fr(salt: &[u8], ikm: Option<&[u8]>, mut rng: impl RngCore + CryptoRng) -> Scalar {
    let mut hasher = Shake256::default();
    match ikm {
        Some(v) => {
            hasher.update(salt);
            hasher.update(v);
        }
        None => {
            hasher.update(salt);
            let mut arr = [0u8; 32];
            rng.fill_bytes(&mut arr);
            hasher.update(&arr);
        }
    };
    let mut okm = [0u8; 64];
    let mut xof = hasher.finalize_xof();
    xof.read(&mut okm);
    Scalar::from_bytes_wide(&okm)
}

pub fn hash_to_g1<I: AsRef<[u8]>>(data: I) -> G1Projective {
    const DST: &[u8] = b"BLS12381G1_XOF:SHAKE256_SSWU_RO_VB_ACCUMULATOR:1_0_0";
    G1Projective::hash::<ExpandMsgXof<Shake256>>(data.as_ref(), DST)
}

/// Salt used for hashing values into the accumulator
/// Giuseppe Vitto, Alex Biryukov = VB
/// Ioanna Karantaidou, Foteini Baldimtsi = KB
/// Accumulator = ACC
pub const SALT: &[u8] = b"KB-VB-ACC-HASH-SALT-";

/// A Polynomial for Points
#[derive(Default, Clone, Debug)]
pub struct PolynomialG1(pub Vec<G1Projective>);

impl PolynomialG1 {
    #[cfg(any(feature = "std", feature = "alloc"))]
    /// Initialize this polynomial with the expected capacity
    pub fn with_capacity(size: usize) -> Self {
        Self(Vec::with_capacity(size))
    }

    #[cfg(not(any(feature = "std", feature = "alloc")))]
    /// Initialize this polynomial with the expected capacity
    pub fn with_capacity(_size: usize) -> Self {
        Self(Vec::new())
    }

    /// Return the result of evaluating the polynomial with the specified point `x`. If the polynomial is empty return `None`.
    /// 
    /// NOTE: this function should only be used for testing, evaluation can be computed more efficiently with the `msm` function.
    pub fn evaluate(&self, x: &Scalar) -> Option<G1Projective> {

        if self.0.is_empty() {
            return None;
        }

        let mut p = *x;
        let mut res = self.0[0];

        for i in 1..self.0.len() {
            res += self.0[i] * p;
            p *= x;
        }
        Some(res)
    }

    // Get best window size according to ark-ec implementation
    fn get_window_size(&self) -> usize{
        match self.0.len(){
            size if size>=32 => (usize::ilog2(size) * 69 / 100) as usize + 2,
            _ => 3
        } 
    }
    
    /// Returns all the powers of 'x` needed for evaluation of the poly
    /// e.g., 1, x, x^2, ..., x^d
    fn compute_powers_for_eval(&self, x: &Scalar) -> Vec<Scalar>{
        let mut ret = Vec::with_capacity(self.0.len());
        ret.push(Scalar::ONE);
        for i in 1..self.0.len(){
            ret.push(x*ret[i-1])
        }
        ret
    }


        
    /// Optimized implementation of multi-scalar multiplication adapted from ark-ec library. 
    pub fn msm(&self, x: &Scalar) -> Option<G1Projective> {
        /*
            TODO: consider rewriting library using ark-ec and adopting their implementation of msm. 
        */

        // If the polynomial is empty we return None
        if self.0.is_empty() {
            return None;
        }

        // If x is 0 we return the point at infinity
        if bool::from(Field::is_zero(x)) {
            return Some(G1Projective::IDENTITY);
        }

        // If the poly is small, evaluate directly
        if *x==Scalar::ONE || self.0.len()<=8{
            return self.evaluate(x);
        }

        // Compute 1,x,...,x^d
        let scalars = self.compute_powers_for_eval(x);
        
        // Get an iterator with coefficients and scalars pairs (c_1, 1), (c_2,x), ..., (c_d, x^d) 
        let scalars_and_coeff_iter = scalars.iter().zip(self.0.clone());
        let c = self.get_window_size();

        // Get indexes of msm windows
        let num_bits = Scalar::BYTES*8 as usize;
        let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();
        let zero = G1Projective::IDENTITY;
        
        // Each window is of size `c`.
        // We divide up the bits 0..num_bits into windows of size `c`, and
        // process each such window.
        let window_sums: Vec<_> = window_starts.into_iter()
            .map(|w_start| {
                let mut res = zero;
                // We don't need the "zero" bucket, so we only have 2^c - 1 buckets.
                let mut buckets = vec![zero; (1 << c) - 1];
                scalars_and_coeff_iter.clone().for_each(|(&scalar, base)| {                    

                    let mut scalar = scalar.clone();
                    // Extract the `c` bits correspondig to our window:
                    // Right-shift by w_start to remove the lower bits
                    shr_assign(&mut scalar, w_start);
                    // Apply mod 2^{window size} to the result to remove the higher bits
                    apply_modulo2(&mut scalar, c);

                    // The remaining extracted bits form our index in the bucket
                    let index = scalar_to_usize(&scalar);
                    
                    // If the scalar is non-zero, we update the corresponding
                    // bucket.
                    if index != 0 {
                        buckets[index - 1] += base;
                    }
                    
                });

                // Compute sum_{i in 0..num_buckets} (sum_{j in i..num_buckets} bucket[j])
                // This is computed below for b buckets, using 2b curve additions.
                //
                // We could first normalize `buckets` and then use mixed-addition
                // here, but that's slower for the kinds of groups we care about
                // (Short Weierstrass curves and Twisted Edwards curves).
                // In the case of Short Weierstrass curves,
                // mixed addition saves ~4 field multiplications per addition.
                // However normalization (with the inversion batched) takes ~6
                // field multiplications per element,
                // hence batch normalization is a slowdown.

                // `running_sum` = sum_{j in i..num_buckets} bucket[j],
                // where we iterate backward from i = num_buckets to 0.
                let mut running_sum = G1Projective::IDENTITY;
                buckets.into_iter().rev().for_each(|b| {
                    running_sum += &b;
                    res += &running_sum;
                });
                res
            })
            .collect();

        // We store the sum for the lowest window.
        let lowest = *window_sums.first().unwrap();
        
        // We're traversing windows from high to low.
        Some(lowest
            + &window_sums[1..]
                .iter()
                .rev()
                .fold(zero, |mut total, sum_i| {
                    total += sum_i;
                    for _ in 0..c {
                        total = total.double();
                    }
                    total
                }))
    }

    pub fn degree(&self)->usize{
        self.0.len()-1
    }
}

/// Given a point P and a vector of coefficients [coeff_1, ..., coeff_n] 
/// efficiently compute the vector [coeff_1*P...coeff_n*P]
pub fn window_mul(point: G1Projective, coefficients: Vec<Scalar>)-> Vec<G1Projective>{
    
    if coefficients.is_empty(){
        return Vec::new();
    }

    // Get value for c
    let c = match coefficients.len(){
        size if size >= 32 => (usize::ilog2(size) * 69 / 100) as usize + 2,
        _ => 3
    };

    // Get indexes of msm windows
    let num_bits = Scalar::BYTES*8 as usize;
    let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();

    let zero = G1Projective::IDENTITY;
    let mut table = vec![G1Projective::IDENTITY; (1<<c)-1];
    
    // Efficiently precompute [P, 2P, 3P, ..., cP]
    table[0] = point;
    for i in 1..table.len(){
        table[i]=table[i-1]+point;
    }

    coefficients.iter().map(|&coeff| {        
        // Result of the multiplication            
        let mut res = zero;
        window_starts.iter().rev().for_each(|&w_start|{
            
            // Extract the `c` bits of the scalar for our current window
            // Shift right to remove LSB, apply modulo 2 to remove MSB
            let mut coeff = coeff.clone();
            shr_assign(&mut coeff, w_start);
            apply_modulo2(&mut coeff, c);

            // Get the index on the precomputed table
            let index = scalar_to_usize(&coeff);

            if index!=0{
                res+=table[index-1];
            }
            
            if w_start !=0 {
                for _ in 0..c {
                    res = res.double();
                }
            }
        });
        res
    }).collect()
}


/// Unchecked conversion from `Scalar` to `usize`, truncating to the LSB.
fn scalar_to_usize(s: &Scalar) -> usize {
    const BITS: usize = (usize::BITS/8) as usize;
    let bytes: [u8; BITS] = s.to_be_bytes()[32-BITS..32].try_into().expect("Invalid number of bytes during conversion");
    usize::from_be_bytes(bytes)
}

/// Performs the >>= operator to a Scalar.
#[inline]
fn shr_assign(s: &mut Scalar, rhs: usize) {
    // The default implementation in bls12-381-plus::Scalar is inefficient and works only when s is multiple of 2
    // If bits to shift are more than Scalar bits, we set scalar to 0
    
    let mut bytes = s.to_be_bytes();
    if rhs >= (Scalar::NUM_BITS as usize){
        bytes.fill(0);
        *s = Scalar::from_be_bytes(&bytes).unwrap();
        return;
    }

    /*TODO: do this in one pass */
    //Get the number of bytes that will be fully (resp. partially) zero
    let del_full = rhs >> 3;
    let del_par = (rhs % 8) as u32; 
    let mask = 0xFF_u8.wrapping_shr(8 - del_par);

    if del_par>0{
        let mut rem: u8 = 0x00; 
        for i in 0..bytes.len(){
            let temp = bytes[i] & mask; 
            bytes[i] >>= del_par;
            bytes[i] += rem;
            rem = temp<<(8 - del_par);
        }
    }
        
    for i in (del_full..bytes.len()).rev(){
        bytes[i]=bytes[i-del_full];
    
    }
    for i in 0..del_full{
        bytes[i] = 0;
    }
    *s = Scalar::from_be_bytes(&bytes).unwrap();
}

/// Clear the first `n` bits of the Scalar `s`, starting from the MSB
fn clear_left_bits(s: &mut Scalar, n: usize){
    let mut bytes = s.to_be_bytes();

    let k = usize::min(Scalar::NUM_BITS as usize, n);
    
    let zeros = k>>3;
    let remainder = k%8;

    for i in 0..zeros{
        bytes[i].set_zero();
    } 

    if remainder>0 {
        let mask: u8 = (1 << (8-remainder))-1;
        bytes[zeros] &= mask;
    }
    *s = Scalar::from_be_bytes(&bytes).unwrap();
}

/// Reduces the scalar `s` modulo  `2^n`
fn apply_modulo2(s: &mut Scalar, n: usize){
    clear_left_bits(s, 32*8-n);    
}



impl core::ops::AddAssign for PolynomialG1 {
    fn add_assign(&mut self, rhs: Self) {
        let min_len = core::cmp::min(self.0.len(), rhs.0.len());

        if self.0.len() == min_len {
            for i in min_len..rhs.0.len() {
                self.0.push(rhs.0[i]);
            }
        }
        for i in 0..min_len {
            self.0[i] += rhs.0[i];
        }
    }
}

impl core::ops::MulAssign<Scalar> for PolynomialG1 {
    fn mul_assign(&mut self, rhs: Scalar) {
        for i in 0..self.0.len() {
            self.0[i] *= rhs;
        }
    }
}


/// Optimized implementation of multi-scalar multiplication adapted from ark-ec library. 
pub fn msm(coeff: &Vec<G1Projective>, scalars: &Vec<Scalar>) -> Option<G1Projective> {
    /*
        TODO: consider rewriting library using ark-ec and adopting their implementation of msm. 
    */

    // If the polynomial is empty we return None
    if coeff.is_empty() || coeff.len() != scalars.len(){
        return None;
    }

    
    // Get an iterator with coefficients and scalars pairs (c_1, 1), (c_2,x), ..., (c_d, x^d) 
    let scalars_and_coeff_iter = scalars.iter().zip(coeff.clone());
    
    // Get widow size
    let c = match scalars.len() {
        size if size>=32 => (usize::ilog2(size) * 69 / 100) as usize + 2,
        _ => 3
    };

    // Get indexes of msm windows
    let num_bits = Scalar::BYTES*8 as usize;
    let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();
    let zero = G1Projective::IDENTITY;
    
    // Each window is of size `c`.
    // We divide up the bits 0..num_bits into windows of size `c`, and
    // process each such window.
    let window_sums: Vec<_> = window_starts.into_iter()
        .map(|w_start| {
            let mut res = zero;
            // We don't need the "zero" bucket, so we only have 2^c - 1 buckets.
            let mut buckets = vec![zero; (1 << c) - 1];
            scalars_and_coeff_iter.clone().for_each(|(&scalar, base)| {                    

                let mut scalar = scalar.clone();
                // Extract the `c` bits correspondig to our window:
                // Right-shift by w_start to remove the lower bits
                shr_assign(&mut scalar, w_start);
                // Apply mod 2^{window size} to the result to remove the higher bits
                apply_modulo2(&mut scalar, c);

                // The remaining extracted bits form our index in the bucket
                let index = scalar_to_usize(&scalar);
                
                // If the scalar is non-zero, we update the corresponding
                // bucket.
                if index != 0 {
                    buckets[index - 1] += base;
                }
                
            });

            let mut running_sum = G1Projective::IDENTITY;
            buckets.into_iter().rev().for_each(|b| {
                running_sum += &b;
                res += &running_sum;
            });
            res
        })
        .collect();

    // We store the sum for the lowest window.
    let lowest = *window_sums.first().unwrap();
    
    // We're traversing windows from high to low.
    Some(lowest
        + &window_sums[1..]
            .iter()
            .rev()
            .fold(zero, |mut total, sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total = total.double();
                }
                total
            }))
}

/// A Polynomial for scalars
#[derive(Default, Clone)]
pub struct Polynomial(pub Vec<Scalar>);

impl Polynomial {
    #[cfg(any(feature = "std", feature = "alloc"))]
    /// Initialize this polynomial with the expected capacity
    pub fn with_capacity(size: usize) -> Self {
        Self(Vec::with_capacity(size))
    }

    #[cfg(not(any(feature = "std", feature = "alloc")))]
    /// Initialize this polynomial with the expected capacity
    pub fn with_capacity(_size: usize) -> Self {
        Self(Vec::new())
    }

    /// Add the scalar to the end of the polynomial
    pub fn push(&mut self, value: Scalar) {
        self.0.push(value);
    }

    /// Evaluate the polynomial
    pub fn eval(&self, value: Scalar) -> Scalar {
        // Compute the polynomial value using Horner's method
        let degree = self.0.len() - 1;
        let mut r = self.0[degree];
        for i in (0..degree).rev() {
            // b_{n-1} = a_{n-1} + b_n * x
            r *= value;
            r += self.0[i];
        }
        r
    }

    /// Calculate the polynomial degree
    pub fn degree(&self) -> usize {
        self.0.len() - 1
    }
}

impl From<Vec<Scalar>> for Polynomial {
    fn from(scalars: Vec<Scalar>) -> Self {
        Self(scalars)
    }
}

impl core::ops::AddAssign for Polynomial {
    fn add_assign(&mut self, rhs: Self) {
        *self += rhs.0.as_slice();
    }
}

impl core::ops::AddAssign<&[Scalar]> for Polynomial {
    fn add_assign(&mut self, rhs: &[Scalar]) {
        let min_len = core::cmp::min(self.0.len(), rhs.len());

        if self.0.len() == min_len {
            for i in rhs.iter().skip(min_len) {
                self.0.push(*i);
            }
        }
        for (i, item) in rhs.iter().enumerate().take(min_len) {
            self.0[i] += item;
        }
    }
}

impl core::ops::SubAssign for Polynomial {
    fn sub_assign(&mut self, rhs: Self) {
        *self -= rhs.0.as_slice();
    }
}

impl core::ops::SubAssign<&[Scalar]> for Polynomial {
    fn sub_assign(&mut self, rhs: &[Scalar]) {
        let min_len = core::cmp::min(self.0.len(), rhs.len());
        if self.0.len() == min_len {
            for item in rhs.iter().skip(min_len) {
                self.0.push(-item);
            }
        }
        for (i, item) in rhs.iter().enumerate().take(min_len) {
            self.0[i] -= item;
        }
    }
}


impl core::ops::MulAssign for Polynomial {
    fn mul_assign(&mut self, rhs: Self) {
        *self *= rhs.0.as_slice();
    }
}

impl core::ops::MulAssign<&[Scalar; 2]> for Polynomial {
    fn mul_assign(&mut self, rhs: &[Scalar; 2]) {
        *self *= &rhs[..];
    }
}

impl core::ops::MulAssign<&[Scalar]> for Polynomial {
    fn mul_assign(&mut self, rhs: &[Scalar]) {
        let orig = self.0.clone();

        // Both vectors can't be empty
        if !self.0.is_empty() || !rhs.is_empty() {
            for i in 0..self.0.len() {
                self.0[i] = Scalar::ZERO;
            }
            // M + N - 1
            self.0
                .resize_with(self.0.len() + rhs.len() - 1, || Scalar::ZERO);

            // Calculate product
            for (i, item) in orig.iter().enumerate() {
                for (j, jitem) in rhs.iter().enumerate() {
                    self.0[i + j] += jitem * item;
                }
            }
        }
    }
}

impl core::ops::MulAssign<Scalar> for Polynomial {
    fn mul_assign(&mut self, rhs: Scalar) {
        for i in 0..self.0.len() {
            self.0[i] *= rhs;
        }
    }
}



fn aggregate_d(omegas: &Vec<PolynomialG1>, scalars: &Vec<Scalar>, e: Scalar) -> Vec<Scalar>{
    let max_deg = omegas.iter().max_by(|x, y| x.degree().cmp(&y.degree())).unwrap().degree();

    // Pre-compute all required powers of the input element
    let mut powers = Vec::<Scalar>::with_capacity(max_deg);
    powers.push(Scalar::one());
    (1..=max_deg).for_each(|i|{powers.push(powers[i-1]*e);});
    
    // Scalar vector
    let mut scalars_ret = Vec::new();
    omegas.iter().enumerate().for_each(|(j, omega)|{
        (0..=omega.degree()).for_each(|i|{
            scalars_ret.push(scalars[j]*powers[i]);
        })
    });
    scalars_ret
}


pub fn aggregate_eval_omega(omegas: Vec<PolynomialG1>, scalars: &Vec<Scalar>, e: Scalar)->Option<G1Projective>{
    if omegas.len() == 0 || omegas.len()!= scalars.len(){
        return None;
    }
    let max_deg = omegas.iter().max_by(|x, y| x.degree().cmp(&y.degree())).unwrap().degree();


    // Pre-compute all required powers of the input element
    let mut powers = Vec::<Scalar>::with_capacity(max_deg);
    powers.push(Scalar::one());
    (1..=max_deg).for_each(|i|{powers.push(powers[i-1]*e);});
    
    // Scalar vector
    let scalars = aggregate_d(&omegas, scalars, e);

    //Point Vector
    let omega: Vec<G1Projective> = omegas.into_iter().map(|p| p.0).flatten().collect();
    msm(&omega, &scalars)
}

#[cfg(test)]
mod tests {
    use core::time;
    use std::time::{Duration, Instant, SystemTime};
    use group::{ff::PrimeField, Group};
    use rand::{random, rngs::OsRng};

    use super::*;
    
    #[test]
    fn utils_test_shr(){
        // Pick random u128 
        let mut bytes = [0u8; 16];
        rand_core::OsRng{}.fill_bytes(&mut bytes);
        let mut int = u128::from_be_bytes(bytes);

        // Two scalar representations of integer
        let mut s = Scalar::from_u128(int); 
        let mut s2 = s.clone();

        //Pick random shift value and apply mod to avoid huge rhs
        let mut rhs = [0u8; 8];
        rand_core::OsRng{}.fill_bytes(&mut rhs);
        let mut rhs = usize::from_be_bytes(rhs);
        rhs %= Scalar::BYTES+2;
        let rhs = 16;

        // u128 shr_assign
        let t1 = Instant::now();
        int >>= rhs;
        let t1 = t1.elapsed();


        // Function shr_assign
        let t2 = Instant::now();
        shr_assign(&mut s, rhs);
        let t2 = t2.elapsed();

        // Scalar shr_assign
        let t3 = Instant::now();
        s2 >>= rhs;
        let t3 = t3.elapsed(); 
        

        // check my implementation gives correct result
        assert_eq!(Scalar::from_u128(int), s);

        println!("Compute shift u128: {:?}", t1);
        println!("Compute shift Scalar optimized: {:?}", t2);
        println!("Compute shift scalar built-in: {:?}", t3);
        
    }
    
    #[test]
    fn utils_test_mul(){
        let size = 10_000;
        let v = G1Projective::random(rand_core::OsRng{});
        let mut cs = Vec::with_capacity(size);
        (0..size).for_each(|_| cs.push(Scalar::random(rand_core::OsRng{})));  

        let t1 = Instant::now();
        let res = window_mul(v.clone(), cs.clone());
        let t1 = t1.elapsed();

        
        let t2 = Instant::now();
        let res2: Vec<G1Projective> = cs.iter().map(|c| c*v).collect();
        let t2 = t2.elapsed();
        
        for i in (0..size){
            assert_eq!(res[i], res2[i]);
        }
        
        println!("Compute {size} multiplications without DP: {:?}", t2);
        println!("Compute {size} multiplications with DP: {:?}", t1);
    }


    #[test]
    fn utils_test_eval(){
        
        let d = 1_000;
        let mut p = PolynomialG1::with_capacity(d);
        for i in 0..d{
            p.0.push(G1Projective::random(rand_core::OsRng{}));
        }

        let x = Scalar::random(rand_core::OsRng{});
        
        let t1 = Instant::now();
        let r1 = p.evaluate(&x).unwrap();
        let t1 = t1.elapsed();

        let t2 = Instant::now();
        let r2 = p.msm(&x).unwrap();
        let t2 = t2.elapsed();

        println!("Evaluate degree {d} poly without optimization: {:?}", t1);
        println!("Evaluate degree {d} poly using multi scalar multiplication: {:?}", t2);

        assert_eq!(r1, r2);
        
    }



    #[test]
    fn utils_test_msm(){
        
        let d = 1000;
        let mut p = PolynomialG1::with_capacity(d);
        let mut c =  G1Projective::random(rand_core::OsRng{});
        for i in 0..d{
            p.0.push(c);
            c=c.double();
        }
        println!("Finished creating poly");

        let x = Scalar::random(rand_core::OsRng{});
        
        let t1 = Instant::now();
        let r1 = p.msm(&x).unwrap();
        let t1 = t1.elapsed();
        

        let inner_p = p.0.clone();
        let p = vec![p];
        
        let t2 = Instant::now();
        let scalars = aggregate_d(&p, &vec![Scalar::ONE], x);
        let r2 = msm(&inner_p, &scalars).unwrap();
        let t2 = t2.elapsed();

        println!("Evaluate msm method: {:?}", t1);
        println!("Evaluate msm fun: {:?}", t2);

        assert_eq!(r1, r2);
        
    }


    #[test]
    fn utils_test_window(){
        
        let d = 16_384;
        let mut point =  G1Projective::random(rand_core::OsRng{});

        let scalars: Vec<Scalar> = (1..=d).map(|i| Scalar::random(rand_core::OsRng{})).collect();
        
        let t = Instant::now();
        let a = window_mul(point, scalars.clone());         
        println!("Window mul: {:?}", t.elapsed());

        let mut a2 = Vec::with_capacity(scalars.len());
        let t = Instant::now();
        scalars.iter().for_each(|s| a2.push(s*point));
        println!("Trivial: {:?}", t.elapsed());

        assert_eq!(a, a2);
    }

    /* 
    #[test]
    fn utils_test_aggregate_eval(){
        
        let n = 100;
        let d = 100;
        
        let mut omegas: Vec<PolynomialG1> = Vec::with_capacity(n);
        for i in (0..n){
            let mut p = PolynomialG1::with_capacity(d);
            for i in 0..d{
                p.0.push(G1Projective::random(rand_core::OsRng{}));
            }
            omegas.push(p);
        }

        let mut ds: Vec<Polynomial> = Vec::with_capacity(n);
        for i in (0..n){
            let mut p  = Polynomial::with_capacity(d);
            for i in 0..d{
                p.0.push(Scalar::random(rand_core::OsRng{}));
            }
            ds.push(p);
        }

        let x = Scalar::random(rand_core::OsRng{});
        
        let mut r1 = G1Projective::IDENTITY;
        let mut t1 = Duration::from_millis(0); 
        omegas.iter().for_each(|p|{
                let t = Instant::now();
                let tmp = p.msm(&x).unwrap();
                let t = t.elapsed();
                r1+=tmp; t1+=t;
            }
        );

        let t2 = Instant::now();
        let r2 = aggregate_eval_omega(omegas, &ds, x).unwrap();
        let t2 = t2.elapsed();

        assert_eq!(r1, r2);

        println!("Evaluate {n} degree {d} poly without aggregation: {:?}", t2);
        println!("Evaluate {n} degree {d} poly using aggregation: {:?}", t2);
        
    }*/

}