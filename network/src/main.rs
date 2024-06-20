use std::thread;
use client::Client;
use controller::Controller;
use entities::{Holder, Verifier};

mod client;
mod base_registry;
mod server;
mod controller;

#[tokio::main]
async fn main() {
    
    //Initialise Servers
    let reg = thread::spawn(|| self::base_registry::run());
    let serv = thread::spawn(|| self::server::run());
    Controller::send_public_params().await.unwrap();

    //Get Public Parameters
    let mut pp = Client::ask_pp().await.unwrap();

    //Initialise holders
    let rh1 = Client::ask_issuance("test1".to_string()).await.unwrap();
    let rh2 = Client::ask_issuance("test2".to_string()).await.unwrap();
    let mut cl1 = Holder::new("test1".to_string(), rh1, pp);
    let mut cl2 = Holder::new("test2".to_string(), rh2, pp);

    
    //Initialise Verifier
    let mut ver = Verifier::new(pp);

    //Verify both proofs
    assert!(ver.verify(cl1.proof_membership(None)));
    assert!(ver.verify(cl2.proof_membership(None)));

    //Revoke first client
    assert!(Controller::revoke("test1").await.unwrap().status().is_success());
    assert!(Controller::update().await.unwrap().status().is_success());
    Controller::send_public_params().await.unwrap();
    Controller::send_witnesses().await.unwrap();

    //Check revocation status of first client
    pp = Client::ask_pp().await.unwrap();
    assert!(!cl1.test_membership(Some(pp)));

    //Update second client
    assert!(Client::ask_update(&mut cl2).await.expect("Communication error"));
    assert!(cl2.test_membership(Some(pp)));
    
    //Check first client doesn't receive update
    assert!(!Client::ask_update(&mut cl1).await.expect("Communication error"));

    let _ = (reg.join(), serv.join());
}