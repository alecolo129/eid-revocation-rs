# Accumulator

This package contains an implementation of a pairing-based accumulator, based on the communication-optimal non adaptively sound construction defined in [KB21](https://ieeexplore.ieee.org/abstract/document/9505229).


## Content
This package contains the following files:

- `accumulator.rs`: implements a *positive*, *dynamic* accumulator $V$. The accumulator supports single/batch element removals, and keyed witness updates. No operation is performed on addition of new elements;

- `key.rs`: implements the accumulator's private key $x$, and public key $X \leftarrow xG_2$. The `SecretKey` type provides primitives for computing the batch update polynomial $\Omega(X) = \sum_{s=1}^m \prod_{i=1}^s (e_i+x)^{-1}\ \prod_{j=1}^{s-1} (e_j-X)$;

- `witness.rs`: implements a membership witness $A_t = (x+e)^{-1}\ V_t$. Provides primitives for witness creation, computation of single/batch updates from the input update coefficients, and local verification of the witness. Multiple single/batch updates can be efficiently aggregated and evaluated as a *single batch* (as by pages 37-38 of my thesis); 

- `proof.rs`: implements a ZKP which proofs membership of the input witness in the accumulated set, as $e(A_t, eG_2 + X_2) = e(V_t, G_2)$. Our membership proof is borrowed from the BBS full disclosure proof in TZ23 (Section 5.2), which doesn't require any pairing operations on the holder's side. 

- `utils.rs`: provides some useful functions for polynomials and random scalar generation. It implements efficient polynomial evaluation using Pippenger's approach for MSM, and supports *aggregated evaluation* of multiple smaller polynomials as a single larger polynomial (as by pages 37-38 of my thesis).


## Security Considerations
In Section 4.3 of my thesis, we show that the implemented accumulator preserves the non-adaptive soundness property of the construction defined in [KB21](https://ieeexplore.ieee.org/abstract/document/9505229). Hence, our accumulator is secure when the accumulated elements are *random* (as shown in ). 

In Section 5 of my thesis, we explain how elements included in the accumulator can be bound to the BBS signatures that are distributed to every holder on e-ID issuance. As we show in page 55-56, binding the positive dynamic non-adaptively sound accumulator (i.e., the one defined in this package), and a positive adaptively sound accumulator (i.e., BBS signatures) defines a new positive *dynamic* *adaptively sound* accumulator.


## Testing

An example usage of the primitives provided in this library can be found in the `tests` module at the end of each file. 

To run a test in debug mode execute: 

`cargo test [file_name/test_name] -- --nocapture`

For the optimized release mode execute:

`cargo test [file_name/test_name] --release -- --nocapture`

and the results will be output to the terminal. File names *should not* include the `.rs` extension.

