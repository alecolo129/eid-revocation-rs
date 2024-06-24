use accumulator::Accumulator;
use axum::{
    body::Bytes, extract::State, http::StatusCode, response::IntoResponse, routing::{get, delete, post, put}, Router
};
use entities::{issuer::Issuer, UpdatePolynomials};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use crate::{base_registry::{BASE_REGISTRY_BACK, PARAMS_URL, POLYS_URL, WIT_URL}, log_with_time, log_with_time_ln};

pub const WEBSERVER: &str = "127.0.0.1:1234";
pub const ISSUE_URL: &str = "/accumulator/issue";
pub const REVOKE_URL: &str = "/controller/accumulator/revoke";
pub const REVOKE_BATCH_URL: &str = "/controller/accumulator/revoke_batch";
pub const UPD_URL: &str = "/controller/witnesses/update";
pub const UPD_PERIODIC_URL: &str = "/controller/witnesses/update_periodic";
pub const SEND_WIT_URL: &str = "/controller/witnesses/send";
pub const SEND_PARAMS_URL: &str = "/controller/params/send";

#[derive(Serialize, Deserialize)]
pub struct Update(pub Accumulator, pub UpdatePolynomials);

#[derive(Clone)]
struct AppState {
    iss: Arc<Mutex<Issuer>>,
}


async fn issue(State(state): State<AppState>, pseudo: String) -> axum::response::Response{
    let mut iss = state.iss.lock().unwrap();
    //check validity of pseudo against some Issuer's policy

    let rh = iss.add(pseudo);
    match rh {    
        Some(rh) => (StatusCode::CREATED, bincode::serialize(&rh).expect("Serialization error")).into_response(),
        None => (StatusCode::BAD_REQUEST, "Cannot issue already accumulated element").into_response()
    }  
}   

async fn revoke(State(state): State<AppState>, pseudo: String) -> axum::response::Response{
    let mut iss = state.iss.lock().unwrap();
    match iss.revoke(&pseudo){
        Some(_) => (StatusCode::OK, "ok").into_response(), 
        None => (StatusCode::NOT_FOUND, "Cannot revoke non accumulated element").into_response()
    }
}

async fn revoke_batch(State(state): State<AppState>, payload: Bytes)-> axum::response::Response{
    let pseudos = bincode::deserialize::<Vec<String>>(&payload);
    match pseudos{
        Ok(pseudos) =>{
            let mut iss = state.iss.lock().unwrap();
            iss.revoke_elements(pseudos.as_slice());
            StatusCode::OK.into_response()
        }
        Err(_) => {
            (StatusCode::BAD_REQUEST, "Cannot parse request").into_response()
        }
    }
}


async fn update(State(state): State<AppState>)->impl IntoResponse{

    let upd_poly;
    let new_acc;
    
    log_with_time!(
        "Server starts computation of update poly...",
    );

    {
        let mut iss = state.iss.lock().expect("Posoned mutex");
        upd_poly = iss.update();
        new_acc = iss.get_accumulator();
    }
    
    match upd_poly{
        Some(upd_poly) => {  
            
            log_with_time_ln!(
                "Server finished computing update poly for {} revocations.",
                upd_poly.deletions.len()
            );  
            
            let url = format!("http://{}{}", BASE_REGISTRY_BACK, POLYS_URL);
            let body = bincode::serialize(&Update(new_acc, upd_poly)).expect("Error while serializing update");        
            match reqwest::Client::new().put(url).body(body).send().await {
                Ok(_) => (StatusCode::OK, "ok".to_string()),
                Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
        },
        None =>  (StatusCode::BAD_REQUEST, "Cannot create update poly".to_string())
    }
}

async fn update_periodic(State(state): State<AppState>)->impl IntoResponse{
    let mut iss = state.iss.lock().expect("Posoned mutex");
    log_with_time!(
        "Server starts computing updated witnesses for {} elemets.",
        iss.get_witnesses().len()
    );
    iss.update_periodic();
    log_with_time_ln!(
        "Done.",
    );

    (StatusCode::OK, "ok".to_string())
}


async fn send_witnesses(State(state): State<AppState>)->impl IntoResponse{
    let updates;
    {
        let iss = state.iss.lock().expect("Poisoned mutex");
        updates = iss.get_witnesses();
    }
    let url = format!("http://{}{}", BASE_REGISTRY_BACK, WIT_URL);
    let body = bincode::serialize(&updates).unwrap();
    let _resp = reqwest::Client::new().put(url).body(body).send().await;
    (StatusCode::OK, "ok".to_string())
}

async fn send_params(State(state): State<AppState>)->impl IntoResponse{
    let iss = state.iss.lock().unwrap().to_owned();
    let pp = iss.get_proof_params();
    let url = format!("http://{BASE_REGISTRY_BACK}{PARAMS_URL}");
    match bincode::serialize(&pp){
        Ok(payload) => {
            let resp = reqwest::Client::new().put(url).body(payload).send().await.unwrap();
            match resp.status().is_success(){
                true => (StatusCode::OK, "ok".to_string()),
                false => (StatusCode::INTERNAL_SERVER_ERROR, "Not accepted".to_string())
            }
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    }
    
}

#[tokio::main]
pub async fn run() {
    let iss = Issuer::new(Some(b"test"));
    let shared_state = AppState{iss: Arc::new(Mutex::new(iss))};

    // build our application with a single route
    let app = Router::new()
        .route(ISSUE_URL, post(issue)).with_state(shared_state.clone())
        .route(REVOKE_URL, delete(revoke)).with_state(shared_state.clone())
        .route(REVOKE_BATCH_URL, delete(revoke_batch)).with_state(shared_state.clone())
        .route(UPD_URL, put(update)).with_state(shared_state.clone())
        .route(UPD_PERIODIC_URL, put(update_periodic)).with_state(shared_state.clone())
        .route(SEND_PARAMS_URL, get(send_params)).with_state(shared_state.clone())
        .route(SEND_WIT_URL, get(send_witnesses)).with_state(shared_state.clone())
    ;

    // run our app with hyper, listening globally on port 1234
    let listener = tokio::net::TcpListener::bind(WEBSERVER).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}