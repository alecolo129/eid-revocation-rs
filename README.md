# eID Revocation

This repository contains a proof-of-concept implementation of an accumulator-based proposal for revoking electronic identities in the context of Scenario B of the [Swiss eID Community](https://github.com/e-id-admin/open-source-community/blob/main/discussion-paper-tech-proposal/discussion-paper-tech-proposal.md).

## Structure of the Repository
This repository contains the following packages:

- `accumulator`: implements a pairing-based accumulator, mainly based on the theoretical works of [VB20](https://link.springer.com/chapter/10.1007/978-3-030-95312-6_17), and [KB21](https://ieeexplore.ieee.org/abstract/document/9505229);

- `entities`: implements the main roles defined in the [Swiss Trust Infrastructure](https://github.com/e-id-admin/open-source-community/blob/main/discussion-paper-tech-proposal/discussion-paper-tech-proposal.md) (i.e., *Issuer*, *Holder*, and *Verifier*) making use of the cryptographic functions implemented in the `accumulator` package; 

- `networking`: provides basic server implementations for the *Base Registry* and the *Issuer*. It also contains wrappers around *Holder* and *Verifier* for conveniently querying the servers.

More details can be found in the respective folders.

## Benches
Benches are currently manually crafted and not automated; the `benches` folder will be updated soon to make it more usable. 

## Credits
The accumulator package is built on top of the ALLOSAUR [implementation](https://github.com/sam-jaques/allosaurust) of Sam Jaques. 