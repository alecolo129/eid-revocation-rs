use accumulator::accumulator::Element;
use reqwest::{Error, RequestBuilder, Response};
use crate::server::{WEBSERVER, REVOKE_URL, UPD_URL, SEND_WIT_URL, SEND_PARAMS_URL};
use std::{thread::sleep, time::Duration}; 

 
pub struct Controller;
impl Controller{
    async fn poll(req: &RequestBuilder) ->Result<Response, Error>{
        let mut resp = req.try_clone().expect("Request cannot be cloned").send().await;
        for _ in 0..3{
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
        return req.send().await;         
    }

    pub async fn send_public_params()->Result<Response, Error>{
        let url = format!("http://{WEBSERVER}{SEND_PARAMS_URL}");
        let req = reqwest::Client::new().get(url);        
        return Self::poll(&req).await;
    }

    pub async fn send_witnesses()->Result<Response, Error>{
        let url = format!("http://{WEBSERVER}{SEND_WIT_URL}");
        let req = reqwest::Client::new().get(url);        
        return req.send().await;
    }

    pub async fn update()->Result<Response,Error>{
        let url = format!("http://{WEBSERVER}{UPD_URL}");
        let req = reqwest::Client::new().put(url);        
        return req.send().await;
    }
}
