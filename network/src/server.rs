use axum::{
    extract::State, http::StatusCode, response::IntoResponse, routing::{get, delete, post, put}, Router
};
use entities::issuer::Issuer;
use std::sync::{Arc, Mutex};
use crate::base_registry::{BASE_REGISTRY_BACK, PARAMS_UPDATE_URL, WIT_UPD_URL};
pub const WEBSERVER: &str = "127.0.0.1:1234";
pub const ISSUE_URL: &str = "/accumulator/issue";
pub const REVOKE_URL: &str = "/controller/accumulator/revoke";
pub const UPD_URL: &str = "/controller/witnesses/update";
pub const SEND_WIT_URL: &str = "/controller/witnesses/send";
pub const SEND_PARAMS_URL: &str = "/controller/params/send";



#[derive(Clone)]
struct AppState {
    iss: Arc<Mutex<Issuer>>,
}


async fn revoke(State(state): State<AppState>, pseudo: String)-> (StatusCode, String){
    let mut iss = state.iss.lock().unwrap();
    /*match iss.delete_elements(&[pseudo]){
        Some(_) => (StatusCode::OK, "ok".to_string()),
        None => (StatusCode::BAD_REQUEST, "Cannot revoke non-accumulated element".to_string())
    }*/
    iss.delete_elements(&[pseudo]);
    (StatusCode::OK, "ok".to_string())
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

async fn update(State(state): State<AppState>)->impl IntoResponse{
    let mut iss = state.iss.lock().expect("Posoned mutex");
    iss.update();   
    (StatusCode::OK, "ok".to_string())
}

async fn send_witnesses(State(state): State<AppState>)->impl IntoResponse{
    let updates;
    {
        let iss = state.iss.lock().expect("Poisoned mutex");
        updates = iss.get_witnesses();
        println!("{:?}", updates);
    }
    let url = format!("http://{}{}", BASE_REGISTRY_BACK, WIT_UPD_URL);
    let body = bincode::serialize(&updates).unwrap();
    let _resp = reqwest::Client::new().put(url).body(body).send().await;
    (StatusCode::OK, "ok".to_string())
}

async fn send_params(State(state): State<AppState>)->impl IntoResponse{
    let iss = state.iss.lock().unwrap().to_owned();
    let pp = iss.get_proof_params();
    let url = format!("http://{BASE_REGISTRY_BACK}{PARAMS_UPDATE_URL}");
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
        .route(UPD_URL, put(update)).with_state(shared_state.clone())
        .route(SEND_PARAMS_URL, get(send_params)).with_state(shared_state.clone())
        .route(SEND_WIT_URL, get(send_witnesses)).with_state(shared_state.clone())
    ;

    // run our app with hyper, listening globally on port 1234
    let listener = tokio::net::TcpListener::bind(WEBSERVER).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}