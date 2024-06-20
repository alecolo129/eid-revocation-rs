use accumulator::Accumulator;
use axum::{
    extract::{State,Json}, http::StatusCode, response::IntoResponse, routing::{get, delete, post, put}, Router
};
use entities::{issuer::Issuer, UpdatePolynomials};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use crate::base_registry::{BASE_REGISTRY_BACK, WIT_URL, PARAMS_URL, POLYS_URL};

pub const WEBSERVER: &str = "127.0.0.1:1234";
pub const ISSUE_URL: &str = "/accumulator/issue";
pub const REVOKE_URL: &str = "/controller/accumulator/revoke";
pub const REVOKE_BATCH_URL: &str = "/controller/accumulator/revoke_batch";
pub const UPD_URL: &str = "/controller/witnesses/update";
pub const UPD_PERIODIC_URL: &str = "/controller/witnesses/update_periodic";
pub const SEND_WIT_URL: &str = "/controller/witnesses/send";
pub const SEND_PARAMS_URL: &str = "/controller/params/send";

#[derive(Serialize, Deserialize)]
pub struct Update(pub Accumulator, pub Vec<UpdatePolynomials>);

#[derive(Clone)]
struct AppState {
    iss: Arc<Mutex<Issuer>>,
    update_polys: Arc<Mutex<Vec<UpdatePolynomials>>>,
}


async fn issue(State(state): State<AppState>, pseudo: String) -> impl IntoResponse{
    let mut iss = state.iss.lock().unwrap();
    //check validity of pseudo against some Issuer's policy

    let rh = iss.add(pseudo);
    match rh {    
        Some(rh) => (StatusCode::CREATED, bincode::serialize(&rh).expect("Serialization error").into_response()),
        None => (StatusCode::BAD_REQUEST, "Cannot issue already accumulated element".to_string().into_response())
    }  
}   

async fn revoke(State(state): State<AppState>, pseudo: String)-> (StatusCode, String){
    let mut iss = state.iss.lock().unwrap();
    iss.revoke(&pseudo);
    (StatusCode::OK, "ok".to_string())
}

async fn revoke_batch(State(state): State<AppState>, pseudo: Json<Vec<String>>)-> (StatusCode, String){
    let mut iss = state.iss.lock().unwrap();
    iss.revoke_elements(pseudo.0.as_slice());
    (StatusCode::OK, "ok".to_string())
}


async fn update(State(state): State<AppState>)->impl IntoResponse{

    let mut iss = state.iss.lock().expect("Posoned mutex");
    let upd_poly = iss.update();
    let new_id = iss.get_accumulator_id();
    drop(iss);

    match upd_poly{
        Some(upd_poly) => {
            let mut polys = state.update_polys.lock().expect("Posioned mutex");
            polys.push(upd_poly);
            (StatusCode::OK, "ok".to_string())
        },
        None =>  (StatusCode::BAD_REQUEST, "Cannot create update poly".to_string())
    }
   
}

async fn update_periodic(State(state): State<AppState>)->impl IntoResponse{
    let mut iss = state.iss.lock().expect("Posoned mutex");
    iss.update_periodic();
    (StatusCode::OK, "ok".to_string())
}

async fn send_updates(State(state): State<AppState>)->impl IntoResponse{
    let updates= state.update_polys.lock().expect("Poisoned mutex").to_owned();
    let url = format!("http://{}{}", BASE_REGISTRY_BACK, POLYS_URL);
    let body = bincode::serialize(&updates).unwrap();
    let _resp = reqwest::Client::new().put(url).body(body).send().await;
    (StatusCode::OK, "ok".to_string())
}

async fn send_witnesses(State(state): State<AppState>)->impl IntoResponse{
    let updates;
    {
        let iss = state.iss.lock().expect("Poisoned mutex");
        updates = iss.get_witnesses();
        println!("{:?}", updates);
    }
    let url = format!("http://{}{}", BASE_REGISTRY_BACK, WIT_URL);
    let body = bincode::serialize(&updates).unwrap();
    let _resp = reqwest::Client::new().put(url).body(body).send().await;
    (StatusCode::OK, "ok".to_string())
}

async fn send_params(State(state): State<AppState>)->impl IntoResponse{
    let iss = state.iss.lock().unwrap().to_owned();
    let pp = iss.get_proof_pa