use accumulator::{
    proof::ProofParamsPublic, MembershipWitness 
};
use entities::issuer::UpdatePolynomials;
use bls12_381_plus::Scalar;
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, put},
    Router,
};
use std::{
    collections::{BTreeMap, HashMap}, fmt::Debug, sync::{Arc, Mutex}
};
use serde::Deserialize;
use crate::server::Update;

pub const BASE_REGISTRY_FRONT: &str = "127.0.0.1:3000";
pub const PARAMS_URL: &str = "/parameteres/proof-params";
pub const ACC_URL: &str = "/parameteres/accumulator";
pub const PUBKEY_URL: &str = "/parameteres/public-key";
pub const BASE_REGISTRY_BACK: &str = "127.0.0.1:3000";
pub const WIT_URL: &str = "/witnesses";
pub const POLYS_URL: &str = "/update_polys";

#[derive(Deserialize, Debug)]
struct ExampleParams {
    pseudo: String,
}

#[derive(Clone)]
struct AppState {
    pp: Arc<Mutex<Option<ProofParamsPublic>>>,
    wit: Arc<Mutex<HashMap<String, MembershipWitness>>>,
    current_acc_version: Arc<Mutex<usize>>,
    id_to_usize: Arc<Mutex<HashMap<Scalar, usize>>>,
    update_polys: Arc<Mutex<BTreeMap<usize, Vec<UpdatePolynomials>>>>,
}


async fn upd_public_params(
    State(state): State<AppState>,
    payload: Bytes,
) -> impl IntoResponse {
    match bincode::deserialize::<ProofParamsPublic>(&payload.to_owned()) {
        Ok(pp) => {
            println!("Public Params Received");
            
            state.pp.lock().unwrap().replace(pp);
                        
            let mut acc_version = state.current_acc_version.lock().unwrap();
            *acc_version += 1;
            let mut id_to_usize = state.id_to_usize.lock().unwrap();
            id_to_usize.insert(pp.get_accumulator().get_id(), acc_version.clone());

            return (StatusCode::CREATED, "Ok".to_string());
        }
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid payload".to_string()),
    }
}

async fn upd_update_polys(
    State(state): State<AppState>,
    payload: Bytes,
) -> impl IntoResponse {
    match bincode::deserialize::<Update>(&payload.to_owned()) {
        Ok(update) => {
            println!("Upd Poly Received");
            
            let acc = update.0;
            let polys = update.1;

            let acc_id = acc.get_id();
            state.pp.lock().unwrap().unwrap().update_accumulator(acc);
            
            let mut state_version = state.current_acc_version.lock().unwrap();
            *state_version += 1;
            let acc_version = state_version.clone();
            drop(state_version);

            state.id_to_usize.lock().unwrap().insert(acc_id, acc_version);
            state.update_polys.lock().unwrap().insert(acc_version, polys);

            return (StatusCode::CREATED, "Ok".to_string());
        }
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid payload".to_string()),
    }
}


async fn get_update_polys(
    State(state): State<AppState>,
    payload: Bytes,
) -> impl IntoResponse {
    println!("Base Registry: get_update_polys called");

    match bincode::deserialize::<Scalar>(&payload.to_owned()) {
        Ok(acc_id) => {
            match state.id_to_usize.lock().unwrap().get(&acc_id){
                Some(id) => {
                    let update_polys = state.update_polys.lock().unwrap();
                    let upd_poly = update_polys.get(id).unwrap();
                    let payload = serde_json::to_string(upd_poly).unwrap();
                    return (StatusCode::CREATED, payload);
                }
                None => {
                    return (StatusCode::BAD_REQUEST, "Invalid accumulator id".to_string())
                }
            }
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
    println!("Base Registry: get_proof_params called");
    match state.pp.lock().unwrap().to_owned() {
        Some(pp) => return (StatusCode::OK, serde_json::to_string(&pp).unwrap()),
        None => return (StatusCode::NOT_FOUND, "Paremeters not found".to_string()),
    }
}

async fn get_accumulator(State(state): State<AppState>) -> impl IntoResponse {
    println!("Base Registry: get_accumulator");
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
    println!("Base Registry: get_public_key called");
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
    println!("Base Registry: get_update called");
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
        current_acc_version: Arc::new(Mutex::new(0)),
        id_to_usize:  Arc::new(Mutex::new(HashMap::new())),
        update_polys: Arc::new(Mutex::new(BTreeMap::new()))
    };

    let app = Router::new()
        .route(PARAMS_URL, get(get_proof_params).put(upd_public_params))
        .with_state(shared_state.clone())
        .route(POLYS_URL, put(upd_update_polys).get(get_update_polys))
        .with_state(shared_state.clone())
        .route(WIT_URL, get(get_update).put(upd_witnesses))
        .with_state(shared_state.clone())
        .route(ACC_URL, get(get_accumulator)
        .with_state(shared_state.clone()))
        .route(PUBKEY_URL, get(get_public_key))
        .with_state(shared_state.clone());

    
    let listener = tokio::net::TcpListener::bind(BASE_REGISTRY_BACK).await.unwrap();   
    axum::serve(listener, app).await.unwrap();


}
