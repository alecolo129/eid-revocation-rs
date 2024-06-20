# Accumulator

This package contains an implementation of a pairing-based accumulator, based on the work of [Ngu05](https://link.springer.com/chapter/10.1007/978-3-540-30574-3_19).


## Content
This package contains the following files:

- `accumulator.rs`: implements a positive, dynamic accumulator $V$ supporting single/batch element removals, and keyed witness updates. No operation is performed on addition of new elements;

- `key.rs`: implements the accumulator's private key $\alpha$, and public key $\tilde{Q}$. The `SecretKey` structure provides primitives for computing multiplicative coefficient of a batch deletion $c = (\alpha+y_{D_1})^{-1} \cdots (\alpha+y_{D_m})^{-1}$, and the batch update polynomial $\Omega(x) = \sum_{s=1}^m \prod_{i=1}^s (y_{D_i}+\alpha)^{-1}\ \prod_{j=1}^{s-1} (y_{D_j}-x)$;

- `witness.rs`: implements a membership witness $C = (\alpha+y)^{-1}\ V$. Provides primitives for witness creation, computation of single/batch update from the input update coefficients, and local verification of the witness; 

- `proof.rs`: implements a ZKP which proofs membership of the input witness in the accumulated set, as $e(C, y\tilde{P} + \tilde{Q}) = e(V, \tilde{P})$. This proofs has been optimized as in TZ23 (Section 5.2), so that the holder doesn't need to compute any pairing operations. Furthermore, we adopt the Fiat-Shamir non-interactive transformation where the challenge is derived from public parameters and initial commitments.

- `utils.rs`: provides some useful functions for polynomials and random scalar generation.



## Testing

An example usage of the primitives provided in this library can be found in the `tests` module at the end of each file. 

To run a test in debug mode execute: 

`cargo test [file_name/test_name] -- --nocapture`

For the optimized release mode execute:

`cargo test [file_name/test_name] --release -- --nocapture`

and the results will be output to the terminal. File names *should not* include the `.rs` extension.

