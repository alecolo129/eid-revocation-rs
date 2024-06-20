# eID Revocation

This repository contains a proof-of-concept implementation of the accumulator-based proposal for revoking electronic identities. in the context of Scenario B.

## Structure of the Repository
This repository contains the following packages:

- `accumulator`: contains the implementation of a pairing-based accumulator based on the theoretical constructions of [VB20](https://link.springer.com/chapter/10.1007/978-3-030-95312-6_17), and [KB21](https://ieeexplore.ieee.org/abstract/document/9505229);

- `entities`: wraps the cryptographic functions implemented in the `accumulator` package into the main roles defined in the [Swiss Trust Infrastructure](https://github.com/e-id-admin/open-source-community/blob/main/discussion-paper-tech-proposal/discussion-paper-tech-proposal.md) (i.e., *Issuer*, *Holder*, and *Verifier*);

- `networking`: provides basic server implementations for the *Base Registry* and the *Issuer*. It also contains wrappers around *Holder* and *Verifier* to conveniently query the two servers.


# Benchmarks

To run the benchmarks, from this directory call

`cargo bench`

and the results will be output to the terminal.

The benchmarks cover three different methods to anonymously update a user's witness: the original implementation from [accumulator-rs](https://github.com/mikelodder7/accumulator-rs) with the full batch update polynomials, the split batch updates from the single-server approach of our paper, and ALLOSAUR's multi-party updates. 

The parameters to these benchmarks are in `benches/updates.rs`.

## Credits
The accumulator package is built on top of the ALLOSAUR [implementation](https://github.com/sam-jaques/allosaurust) of Sam Jaques. 