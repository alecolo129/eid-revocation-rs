use accumulator::{proof::ProofParamsPublic, Accumulator, MembershipWitness};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, put},
    Router,
};
use blsful::inner_types::Scalar;
use entities::issuer::UpdatePolynomials;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Debug,
    sync::{Arc, Mutex},
};

use crate::{log_with_time, log_with_time_ln};

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

#[derive(Serialize, Deserialize, Debug)]
pub struct Update(pub Accumulator, pub Vec<UpdatePolynomials>);

#[derive(Serialize, Deserialize, Debug)]
pub struct PeriodicUpdate(pub Accumulator, pub MembershipWitness);

#[derive(Clone)]
struct AppState {
    pp: Arc<Mutex<Option<ProofParamsPublic>>>,
    wit: Arc<Mutex<HashMap<String, MembershipWitness>>>,
    current_acc_version: Arc<Mutex<usize>>,
    id_to_usize: Arc<Mutex<HashMap<Scalar, usize>>>,
    update_polys: Arc<Mutex<BTreeMap<usize, UpdatePolynomials>>>,
}

/// Updates the state public parameters with public parameters in the request payload
async fn replace_public_params(State(state): State<AppState>, payload: Bytes) -> Response {
    match bincode::deserialize::<ProofParamsPublic>(&payload) {
        Ok(pp) => {
            log_with_time_ln!(
                "Base Registry: public params received"
            );

            // Replace public parameters
            state.pp.lock().unwrap().replace(pp);

            // Increase accumulator version
            let mut acc_version = state.current_acc_version.lock().unwrap();
            *acc_version += 1;
            // Map new version to new accumulator id
            let mut id_to_usize = state.id_to_usize.lock().unwrap();
            id_to_usize.insert(pp.get_accumulator().get_id(), acc_version.clone());

            return StatusCode::CREATED.into_response();
        }
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid payload").into_response(),
    }
}

/// Uses the revocation updates contained in the request payload 
/// to update the accumulator state and store new update polynomials
async fn update_after_revocation(State(state): State<AppState>, payload: Bytes) -> Response {
    match bincode::deserialize::<crate::server::Update>(&payload) {
        Ok(update) => {

            // Get inputs
            let acc = update.0;
            let polys = update.1;
            let acc_id = acc.get_id();

            log_with_time!(
                "Base Registry: update polys of degree {} received",
                polys.deletions.len()
            );

            // Update public params
            let mut pp = state.pp.lock().unwrap().unwrap();
            pp.update_accumulator(acc);
            state.pp.lock().unwrap().replace(pp);

            // Update accumulator version
            let mut state_version = state.current_acc_version.lock().unwrap();
            *state_version += 1;
            let acc_version = state_version.clone();
            drop(state_version);

            // Update state maps
            state
                .id_to_usize
                .lock()
                .unwrap()
                .insert(acc_id, acc_version);
            state
                .update_polys
                .lock()
                .unwrap()
                .insert(acc_version, polys);

            log_with_time_ln!( 
               "Base Registry: state updated.",
            );

            return StatusCode::CREATED.into_response();
        }
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid payload").into_response(),
    }
}

/// Returns all the update polynomials needed to get up-to-date starting from the accumulator id 
/// that is passed in the payload
async fn get_update_polys(State(state): State<AppState>, payload: Bytes) -> Response {

    match bincode::deserialize::<Scalar>(&payload) {
        Ok(acc_id) => {
            log_with_time_ln!(
                "Base Registry: get update polynomials called",
            );
            match state.id_to_usize.lock().unwrap().get(&acc_id) {
                Some(id) => {
                    // Fill vector of updates from input accumulator id
                    let mut poly_vec = Vec::new();
                    state
                        .update_polys
                        .lock()
                        .unwrap()
                        .range(id + 1..)
                        .for_each(|(_, poly)| poly_vec.push(poly.clone()));

                    // Check if some updates are available
                    if poly_vec.is_empty() {
                        return (StatusCode::NOT_FOUND, "No updates available").into_response();
                    }

                    let acc = state.pp.lock().expect("Poisoned mutex").unwrap().get_accumulator();

                    // Return updates
                    let payload = bincode::serialize(&Update(acc, poly_vec)).unwrap();
                    return (StatusCode::OK, payload).into_response();
                }
                None => return (StatusCode::BAD_REQUEST, "Invalid accumulator id").into_response(),
            }
        }
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Cannot parse payload").into_response()
        }
    }
}

/// Updates the list of witnesses in the state with those included in the payload
async fn upd_witnesses(State(state): State<AppState>, body: Bytes) -> Response {
    match bincode::deserialize::<HashMap<String, MembershipWitness>>(&body) {
        Ok(map) => {
            
            log_with_time!(
                "Base Registry: {} new witnesses received",
                map.len()
            );

            // Create new updated witnesses
            {
                let mut wit = state.wit.lock().unwrap();
                wit.clear();
                wit.extend(map.into_iter());
            }

            // Clean update info as we have up-to-date witnesses
            {
                state.update_polys.lock().unwrap().clear();
                state.id_to_usize.lock().unwrap().clear();
                *state.current_acc_version.lock().unwrap() = 0;
            }

            log_with_time_ln!(
                "Base Registry: finished updating state",
            );
            
            return StatusCode::OK.into_response();
        }
        Err(e) => {
            eprintln!("Deserialization error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Deserialization error").into_response()
        }
    }
}


async fn get_proof_params(State(state): State<AppState>) -> Response {
    match state.pp.lock().unwrap().to_owned() {
        Some(pp) => {
            
            log_with_time_ln!(
                "Base Registry: get proof params called",
            );

            return (StatusCode::OK, bincode::serialize(&pp).unwrap()).into_response();
        }
        None => return (StatusCode::NOT_FOUND, "Paremeters not found").into_response(),
    }
}

async fn get_accumulator(State(state): State<AppState>) -> Response {
    match state.pp.lock().unwrap().to_owned() {
        Some(pp) => {

            log_with_time_ln!(
                "Base Registry: get accumulator called",
            );

            return (
                StatusCode::OK,
                bincode::serialize(&pp.get_accumulator()).unwrap(),
            ).into_response();
        }
        None => return (StatusCode::NOT_FOUND, "Accumulator not found").into_response(),
    }
}

async fn get_public_key(State(state): State<AppState>) -> Response {
    match state.pp.lock().unwrap().to_owned() {
        Some(pp) => {

            log_with_time_ln!(
                "Base Registry: get public key called",
            );

            return (
                StatusCode::OK,
                bincode::serialize(&pp.get_public_key()).unwrap(),
            ).into_response()
        }
        None => return (StatusCode::NOT_FOUND, "Public Key not found").into_response(),
    }
}

/// Returns the most up-to-date witness for the holder's pseudonym passed in the payload
async fn get_wit_update(
    State(state): State<AppState>,
    query: Query<ExampleParams>,
) -> Response {
    let ret: Vec<u8> = Vec::new();
    match state.wit.lock().expect("Poisoned mutex").get(&query.pseudo) {
        Some(&wit) => {
            log_with_time_ln!(
                "Base Registry: up-to-date witness request by {}",
                query.pseudo
            );
            let acc = state.pp.lock().expect("Poisoned mutex").unwrap().get_accumulator();
            let bytes = bincode::serialize(&PeriodicUpdate(acc, wit)).unwrap();
            (StatusCode::OK, bytes).into_response()
        },
        None => (StatusCode::UNAUTHORIZED, ret).into_response(),
    }
}

#[tokio::main]
pub async fn run() {
    let shared_state = AppState {
        pp: Arc::new(Mutex::new(None)),
        wit: Arc::new(Mutex::new(HashMap::new())),
        current_acc_version: Arc::new(Mutex::new(0)),
        id_to_usize: Arc::new(Mutex::new(HashMap::new())),
        update_polys: Arc::new(Mutex::new(BTreeMap::new())),
    };

    let app = Router::new()
        .route(PARAMS_URL, get(get_proof_params).put(replace_public_params))
        .with_state(shared_state.clone())
        .route(POLYS_URL, put(update_after_revocation).get(get_update_polys))
        .with_state(shared_state.clone())
        .route(WIT_URL, get(get_wit_update).put(upd_witnesses))
        .with_state(shared_state.clone())
        .route(
            ACC_URL,
            get(get_accumulator).with_state(shared_state.clone()),
        )
        .route(PUBKEY_URL, get(get_public_key))
        .with_state(shared_state.clone());

    let listener = tokio::net::TcpListener::bind(BASE_REGISTRY_BACK)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
