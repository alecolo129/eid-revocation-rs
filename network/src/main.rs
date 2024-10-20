use entities::{Holder, Verifier};
use network::{
    base_registry, client::Client, controller::Controller, log_with_time, log_with_time_ln, server,
};
use std::thread;

const NUM_CLIENTS: usize = 100;

#[tokio::main]
async fn main() {
    // Index of the only client that will not be revoked in this example
    let non_revoked_index = NUM_CLIENTS - 1;

    // Initialise Servers
    let reg = thread::spawn(|| base_registry::run());
    let serv = thread::spawn(|| server::run());
    Controller::send_public_params().await.unwrap();

    // Get Public Parameters
    let mut pp = Client::ask_pp().await.unwrap();

    // Initialise holders
    let mut holders = Vec::with_capacity(NUM_CLIENTS);
    for i in 0..NUM_CLIENTS {
        let client_pseudo = format!("Client{i}");
        let client_rh = Client::ask_issuance(client_pseudo.clone()).await.unwrap();
        holders.push(Holder::new(client_pseudo, client_rh, pp));
    }

    // Initialise Verifier
    let mut ver = Verifier::new(pp);

    // Verify two proofs
    assert!(ver.verify(holders[0].proof_membership(None)));
    assert!(ver.verify(holders[non_revoked_index].proof_membership(None)));

    // Instantly revoke first client
    assert!(Controller::revoke_now(&holders[0].get_pseudo())
        .await
        .unwrap()
        .status()
        .is_success());

    pp = Client::ask_pp().await.unwrap();

    // Check revocation status of first client
    assert!(!holders[0].test_membership(Some(pp)));

    // Try updating first client and test revocation
    assert!(Client::poly_upd(&mut holders[0]).await.is_err());
    assert!(!holders[0].test_membership(Some(pp)));

    // Update non-revoked client and test memebership
    assert!(Client::poly_upd(&mut holders[non_revoked_index])
        .await
        .unwrap());
    assert!(holders[non_revoked_index].test_membership(None));

    // Batch revoke half of the clients
    let revoked = holders[1..NUM_CLIENTS / 2]
        .iter()
        .map(|h| h.get_pseudo())
        .collect();
    assert!(Controller::revoke_batch_now(&revoked)
        .await
        .expect("Cannot revoke batch")
        .status()
        .is_success());

    // Batch update non-revoked client and test memebership
    assert!(Client::poly_upd(&mut holders[non_revoked_index])
        .await
        .unwrap());
    assert!(holders[non_revoked_index].test_membership(None));

    // Simulate we have all other clients to revoke except for last client
    let revoked = holders[NUM_CLIENTS / 2..non_revoked_index]
        .iter()
        .map(|h| h.get_pseudo())
        .collect();
    assert!(Controller::revoke_batch(&revoked)
        .await
        .expect("Cannot revoke batch")
        .status()
        .is_success());

    // Issuer performs periodic update
    Controller::update_periodic_and_send()
        .await
        .expect("Cannot perform periodc update");

    // Non-revoked client gets periodic witness update which includes revocation of all remaining holders
    assert!(Client::wit_upd(&mut holders[non_revoked_index])
        .await
        .expect("Cannot get updated witness"));

    // Ensure all revoked clients cannot get updated witness
    let pp = Client::ask_pp().await.unwrap();
    for hol in holders[0..non_revoked_index].iter_mut() {
        assert!(!Client::wit_upd(hol)
            .await
            .expect("Cannot get updated witness"));
        assert!(!hol.test_membership(Some(pp)));
    }

    //Finally non revoked client proofs membership to verifier
    Client::update_accumulator(&mut ver).await.unwrap();
    log_with_time!("Creating and verifying membership proof for non-revoked client ...",);
    assert!(ver.verify(holders[non_revoked_index].proof_membership(None)));
    log_with_time_ln!("Done.");

    log_with_time!("Finished.");
    let _ = (reg.join(), serv.join());
}
