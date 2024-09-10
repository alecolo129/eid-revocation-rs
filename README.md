# Swiss e-ID Revocation

This repository contains a proof-of-concept implementation of an accumulator-based proposal for revoking electronic identities in the context of Scenario B of the [Swiss eID Community](https://github.com/e-id-admin/open-source-community/blob/main/discussion-paper-tech-proposal/discussion-paper-tech-proposal.md).

## Structure of the Repository
This repository contains the following packages:

- `accumulator`: implements a pairing-based accumulator of the type described in Section 4 of my thesis. The accumulator is built on top of the communication-efficient construction provided in [KB21](https://ieeexplore.ieee.org/abstract/document/9505229). Additionally, our accumulator provides support for batch operations, optimizing the work in [VB22](https://link.springer.com/chapter/10.1007/978-3-030-95312-6_17). Furthermore, our ZK membership proofs are based on the BBS full-disclosure protocol presented in [TZ23](https://link.springer.com/chapter/10.1007/978-3-031-30589-4_24), which does not require *any* pairing operation on the prover side;

- `entities`: implements the main roles defined in the [Swiss Trust Infrastructure](https://github.com/e-id-admin/open-source-community/blob/main/discussion-paper-tech-proposal/discussion-paper-tech-proposal.md) (i.e., *Issuer*, *Holder*, and *Verifier*) making use of the cryptographic functions implemented in the `accumulator` package; 

- `network`: provides basic server implementations for the *Base Registry* and the *Issuer*. It also contains wrappers around *Holder* and *Verifier* for conveniently querying the servers.

More details can be found in the respective folders.

## Benches
The `benches` folder contain the code used to produce the benchmarks in Section 4 of my thesis. 

Notably, the optimization in polynomial evaluation reduces by a log-factor the results achieved in [VB22](https://link.springer.com/chapter/10.1007/978-3-030-95312-6_17), while the aggregation method presented in Section 4.3 *eliminates* the need of computing update polynomials.

## Credits
The accumulator package is built on top of the ALLOSAUR [single-server implementation](https://github.com/sam-jaques/allosaurust) developed by Mike Lodder and Sam Jaques. 