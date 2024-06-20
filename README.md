# eID Revocation

This repository contains a proof-of-concept implementation of an accumulator-based proposal for revoking electronic identities in the context of Scenario B of the [Swiss eID Community](https://github.com/e-id-admin/open-source-community/blob/main/discussion-paper-tech-proposal/discussion-paper-tech-proposal.md).

## Structure of the Repository
This repository contains the following packages:

- `accumulator`: contains the implementation of a pairing-based accumulator, mainly based on the theoretical works of [VB20](https://link.springer.com/chapter/10.1007/978-3-030-95312-6_17), and [KB21](https://ieeexplore.ieee.org/abstract/document/9505229);

- `entities`: implements the main roles defined in the [Swiss Trust Infrastructure](https://github.com/e-id-admin/open-source-community/blob/main/discussion-paper-tech-proposal/discussion-paper-tech-proposal.md) (i.e., *Issuer*, *Holder*, and *Verifier*) making use of the cryptographic functions implemented in the `accumulator` package; 

- `networking`: provides basic server implementations for the *Base Registry* and the *Issuer*. It also contains wrappers around *Holder* and *Verifier* for conveniently querying the servers. **NOTE:** *this package is still a work-in-progress, at the moment it only supports periodic update of the holder witnessses and necessitate further testing.*


## Credits
The accumulator package is built on top of the ALLOSAUR [implementation](https://github.com/sam-jaques/allosaurust) of Sam Jaques. 