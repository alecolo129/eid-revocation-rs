use accumulator::{
    accumulator::Element,
    proof::ProofParamsPublic, MembershipWitness,
};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, put},
    Router,
};
use std::{
    collections::HashMap, fmt::Debug, sync::{Arc, Mutex}
};
use serde::Deserialize;

pub const BASE_REGISTRY_FRONT: &str = "127.0.0.1:3000";
pub const PARAMS_URL: &str = "/parameteres/proof-params";
pub const ACC_URL: &str = "/parameteres/accumulator";
pub const PUBKEY_URL: &str = "/parameteres/public-key";


pub const BASE_REGISTRY_BACK: &str = "127.0.0.1:3000";
pub const PARAMS_UPDATE_URL: &str = "/parameteres/update";
pub const WIT_UPD_URL: &str = "/witnesses/update";

#[derive(Deserialize, Debug)]
struct ExampleParams {
    pseudo: String,
}

#[derive(Clone)]
struct AppState {
    pp: Arc<Mutex<Option<ProofParamsPublic>>>,
    wit: Arc<Mutex<HashMap<String, MembershipWitness>>>,
}

async fn upd_public_params(
    State(state): State<AppState>,
    payload: Bytes,
) -> impl IntoResponse {
    match bincode::deserialize::<ProofParamsPublic>(&payload.to_owned()) {
        Ok(pp) => {
            println!("Public Params Received");
            state.pp.lock().unwrap().replace(pp);
            return (StatusCode::CREATED, "Ok".to_string());
        }
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid payload".to_string()),
    }
}


async fn upd_witnesses(
    State(state): State<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    match bincode::deserialize::<HashMap<String,MembershipWitness>>(&body.to_owned()){
        Ok(map) => {
            println!("New Witnesses Received");
            let mut wit = state.wit.lock().unwrap();
            wit.clear();
            wit.extend(map.into_iter());
            return (StatusCode::OK, "ok");
        },
        Err(e) => {
            eprintln!("Deserialization error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Deserialization error")
        }
    }
}

async fn get_proof_params(State(state): State<AppState>) -> impl IntoResponse {
   println!("Called get pp");
    match state.pp.lock().unwrap().to_owned() {
        Some(pp) => return (StatusCode::OK, serde_json::to_string(&pp).unwrap()),
        None => return (StatusCode::NOT_FOUND, "Paremeters not found".to_string()),
    }
}

async fn get_accumulator(State(state): State<AppState>) -> impl IntoResponse {
    match state.pp.lock().unwrap().to_owned() {
        Some(pp) => {
            return (
                StatusCode::OK,
                serde_json::to_string(&pp.get_accumulator()).unwrap(),
            )
        }
        None => return (StatusCode::NOT_FOUND, "Paremeters not found".to_string()),
    }
}

async fn get_public_key(State(state): State<AppState>) -> impl IntoResponse {
    match state.pp.lock().unwrap().to_owned() {
        Some(pp) => {
            return (
                StatusCode::OK,
                serde_json::to_string(&pp.get_public_key()).unwrap(),
            )
        }
        None => return (StatusCode::NOT_FOUND, "Paremeters not found".to_string()),
    }
}

async fn get_update(State(state): State<AppState>, query: Query<ExampleParams>)->impl IntoResponse{
    println!("Called get update");
    let ret : Vec<u8> = Vec::new();
    match state.wit.lock().expect("Poisoned mutex").get(&query.pseudo){
        Some(wit) => {
            match bincode::serialize(wit) {
                Ok(bytes) => (StatusCode::OK, bytes),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, ret),
            }
        },
        None => {
            (StatusCode::UNAUTHORIZED, ret)
        }
    }

}

#[tokio::main]
pub async fn run() {
    let shared_state = AppState {
        pp: Arc::new(Mutex::new(None)),
        wit: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route(PARAMS_URL, get(get_proof_params))
        .with_state(shared_state.clone())
        .route(WIT_UPD_URL, get(get_update))
        .with_state(shared_state.clone())
        .route(ACC_URL, get(get_accumulator)
        .with_state(shared_state.clone()))
        .route(PUBKEY_URL, get(get_public_key))
        .with_state(shared_state.clone())
        .route(WIT_UPD_URL, put(upd_witnesses))
        .with_state(shared_state.clone())
        .route(PARAMS_UPDATE_URL, put(upd_public_params))
        .with_state(shared_state.clone());
    
    let listener = tokio::net::TcpListener::bind(BASE_REGISTRY_BACK).await.unwrap();   
    axum::serve(listener, app).await.unwrap();


}
