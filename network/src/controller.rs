use reqwest::{Error, RequestBuilder, Response};
use crate::server::{WEBSERVER, REVOKE_URL, REVOKE_BATCH_URL, UPD_URL, UPD_PERIODIC_URL, SEND_WIT_URL, SEND_PARAMS_URL};
use std::{thread::sleep, time::Duration}; 

const POLL_RETRIES: u8 = 3;

pub struct Controller;
impl Controller{
    async fn poll(req: &RequestBuilder) ->Result<Response, Error>{
        let mut resp = req.try_clone().expect("Request cannot be cloned").send().await;
        for _ in 0..POLL_RETRIES-1{
            if resp.is_ok(){
                break;
            }
            else{
                sleep(Duration::from_millis(200));
                resp = req.try_clone().expect("Request cannot be cloned").send().await;
            }
        }
        return resp;
    }

    pub async fn revoke(pseudo: &str)->Result<Response, Error>{
        let url = format!("http://{WEBSERVER}{REVOKE_URL}");
        let req = reqwest::Client::new().delete(url).body(pseudo.to_string());
        return Self::poll(&req).await;         
    }

    pub async fn revoke_batch(pseudos: Vec<String>)->Result<Response, Error>{
        let url = format!("http://{WEBSERVER}{REVOKE_BATCH_URL}");
        let body = bincode::serialize(&pseudos).expect("Error while serializing list of revoked pseudos"); 
        let req = reqwest::Client::new().delete(url).body(body);
        return Self::poll(&req).await;         
    }

    pub async fn revoke_now(pseudo: &str)->Result<Response, Error>{
        /*TODO: Add endpoint in Server.rs to do this with one query*/
        let resp = Self::revoke(pseudo).await?;
        if !resp.status().is_success(){
            return Ok(resp);
        }
        Self::update().await
    }

    pub async fn revoke_batch_now(pseudos: Vec<String>)->Result<Response, Error>{
        /*TODO: Add endpoint in Server.rs to do this with one query*/
        let resp = Self::revoke_batch(pseudos).await?;
        if !resp.status().is_success(){
            return Ok(resp);
        }
        Self::update().await
    }

    pub async fn send_public_params()->Result<Response, Error>{
        let url = format!("http://{WEBSERVER}{SEND_PARAMS_URL}");
        let req = reqwest::Client::new().get(url);        
        return Self::poll(&req).await;
    }

    pub async fn send_witnesses()->Result<Response, Error>{
        let url = format!("http://{WEBSERVER}{SEND_WIT_URL}");
        let req = reqwest::Client::new().get(url);        
        return Self::poll(&req).await;
    }

    pub async fn update()->Result<Response, Error>{
        let url = format!("http://{WEBSERVER}{UPD_URL}");
        let req = reqwest::Client::new().put(url);
        return Self::poll(&req).await;
    }

    pub async fn update_periodic()->Result<Response,Error>{
        let url = format!("http://{WEBSERVER}{UPD_PERIODIC_URL}");
        let req = reqwest::Client::new().put(url);        
        return Self::poll(&req).await;
    }

    
}
