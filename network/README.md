# Network

This package contains a proof-of-concept which demonstrates a possible adoption of the revocation proposal in the Swiss e-ID setting.

## Content
This package contains the following files whithin the `./src` folder:

- `base_registry.rs`: represents the public repository where the update information are published by the issuer and available to every holder. Periodically (i.e., at the end of each revocation epoch) the issuer also publishes a new updated witness for every holder;

- `server.rs`: implements the issuer's core functionallitities and maintains the issuer's current state. Handles the issuance of new IDs and sends to the Base Registry updates to the accumulator value and revocation informations;

- `controller.rs`: communicates with the `Server` to order which operation needs to be performed (e.g., revoke users, re-issue witnesses, etc.); 

- `client.rs`: implements a generic `Client` that queries `Server` and `BaseRegistry`. An holder queries the `Server` on issuance, and the `BaseRegistry` to retrieve update information. A verifier queries the  `BaseRegistry` to retrieve the updated public parameters.

## Example Scenario

An example of scenario can be found in the `.src/main.rs` file
To run it execute: 

`cargo run`

For the optimized release mode execute:

`cargo run --release`

A trace of the execution will be output to the terminal.

## Features

### Provided Features
Among the features provided by the library, we highlight the following:

- interfaces for single (`Server::revoke`), batch (`Server::revoke_batch`), and periodic revocation (`Server::update_periodic`);

- support for instant revocation (`Controller::revoke_now`, `Controller::revoke_batch_now`), and for accumulating a batch of deletions (`Controller::revoke`, `Controller::revoke_batch`) to be enforced on-demand (`Controller::update`);

- support for retrieving and computing holder updates after normal revocations (`Client::poly_upd`), and witness updates (`Client::wit_upd`).

### Non Provided Features
This library does not provide the following features as they are considered outside of the scope:

- permanent storage of the Issuer's and Base Registry's state in a Database;

- client authentication when retreiving the respective updated witness;

- initial authentication of the client and actual issuance of e-ID credentials with BBS+ signatures;

- adoption of an encryption layer to secure communication;

- anonymous communication between holder and verifier.


