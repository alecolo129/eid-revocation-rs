use std::thread;
use client::Client;
use controller::Controller;
use entities::{Holder, Verifier};


mod client;
mod base_registry;
mod server;
mod controller;

const NUM_CLIENTS: usize = 100;

#[tokio::main]
async fn main() {
    
    // Initialise Servers
    let reg = thread::spawn(|| self::base_registry::run());
    let serv = thread::spawn(|| self::server::run());
    Controller::send_public_params().await.unwrap();

    // Get Public Parameters
    let mut pp = Client::ask_pp().await.unwrap();

    // Initialise holders
    let mut holders = Vec::with_capacity(NUM_CLIENTS);
    for i in 0..NUM_CLIENTS{
        let client_pseudo = format!("Client {i}");
        let client_rh = Client::ask_issuance(client_pseudo.clone()).await.unwrap();
        holders.push(Holder::new(client_pseudo, client_rh, pp));
    };
    
    // Initialise Verifier
    let ver = Verifier::new(pp);

    // Verify two proofs
    assert!(ver.verify(holders[0].proof_membership(None)));
    assert!(ver.verify(holders[NUM_CLIENTS-1].proof_membership(None)));

    // Instantly evoke first client
    assert!(Controller::revoke_now(&holders[0].get_pseudo()).await.unwrap().status().is_success());
    
    
    // Check revocation status of first client
    pp = Client::ask_pp().await.unwrap();
    assert!(!ver.verify(holders[0].proof_membership(Some(pp))));
    assert!(!holders[0].test_membership(Some(pp)));
    
    // Try updating first client and test revocation
    assert!(Client::poly_upd(&mut holders[0]).await.is_err());
    assert!(!holders[0].test_membership(Some(pp)));

    // Update second client and test memebership
    assert!(Client::poly_upd(&mut holders[1]).await.unwrap());
    let pp = Client::ask_accumulator().await.unwrap();
    assert!(holders[1].test_membership(Some(pp)));
    
    /* 
    //Check first client doesn't receive update
    assert!(!Client::ask_update(&mut cl1).await.expect("Communication error"));
    */
    println!("Finished");
    let _ = (reg.join(), serv.join());
}