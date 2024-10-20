use crate::server::{
    REVOKE_BATCH_URL, REVOKE_URL, SEND_PARAMS_URL, SEND_WIT_URL, UPD_PERIODIC_URL, UPD_URL,
    WEBSERVER,
};
use reqwest::{Error, RequestBuilder, Response};
use std::{thread::sleep, time::Duration};

const POLL_RETRIES: u8 = 3;

pub struct Controller;
impl Controller {
    async fn poll(req: &RequestBuilder) -> Result<Response, Error> {
        let mut resp = req
            .try_clone()
            .expect("Request cannot be cloned")
            .send()
            .await;
        for _ in 0..POLL_RETRIES - 1 {
            if resp.is_ok() {
                break;
            } else {
                sleep(Duration::from_millis(200));
                resp = req
                    .try_clone()
                    .expect("Request cannot be cloned")
                    .send()
                    .await;
            }
        }
        return resp;
    }

    /// Ask server to add a pseudnym `pseudo` to the revocation batch.
    ///
    /// NOTE: the respective holder is not instantly revoked. Revocation will be enforced as
    /// soon as the `Controller::update` function is called.
    pub async fn revoke(pseudo: &str) -> Result<Response, Error> {
        let url = format!("http://{WEBSERVER}{REVOKE_URL}");
        let req = reqwest::Client::new().delete(url).body(pseudo.to_string());
        return Self::poll(&req).await;
    }

    /// Ask server to add a list of pseudnyms `pseudos` to the revocation batch.
    ///
    /// NOTE: the respective holders are not instantly revoked. Revocation will be enforced as
    /// soon as the `Controller::update` function is called.
    pub async fn revoke_batch(pseudos: &Vec<String>) -> Result<Response, Error> {
        let url = format!("http://{WEBSERVER}{REVOKE_BATCH_URL}");
        let body =
            bincode::serialize(&pseudos).expect("Error while serializing list of revoked pseudos");
        let req = reqwest::Client::new().delete(url).body(body);
        return Self::poll(&req).await;
    }

    /// Ask server to instantly revoke the holder associated with pseudonym `pseudo`.
    ///
    /// NOTE: the computed update polynomials and the updated accumulator value
    /// are NOT automatically sent to the BaseRegistry.
    pub async fn revoke_now(pseudo: &str) -> Result<Response, Error> {
        /*TODO: Add endpoint in Server.rs to do this with one query*/
        Self::revoke(pseudo).await?.error_for_status()?;
        Self::update().await
    }

    /// Ask server to instantly revoke a list of holders associated with pseudonyms `pseudos`.
    ///
    /// NOTE: the computed update polynomials and the updated accumulator value
    /// are NOT automatically sent to the BaseRegistry.
    pub async fn revoke_batch_now(pseudos: &Vec<String>) -> Result<Response, Error> {
        /*TODO: Add endpoint in Server.rs to do this with one query*/
        Self::revoke_batch(pseudos).await?.error_for_status()?;
        Self::update().await
    }

    /// Ask server to compute update polynomials for all holders in the revocation batch.
    pub async fn update() -> Result<Response, Error> {
        let url = format!("http://{WEBSERVER}{UPD_URL}");
        let req = reqwest::Client::new().put(url);
        return Self::poll(&req).await;
    }

    /// Ask server to compute periodic witness update for all non-revoked holders.
    pub async fn update_periodic() -> Result<Response, Error> {
        let url = format!("http://{WEBSERVER}{UPD_PERIODIC_URL}");
        let req = reqwest::Client::new().put(url);
        return Self::poll(&req).await;
    }

    /// Ask server to compute periodic witness update for all non-revoked holders.
    ///
    /// After the update, sends new witnesses and public parameters to the Base Registry.
    pub async fn update_periodic_and_send() -> Result<(), Box<dyn std::error::Error>> {
        /*TODO: Add endpoint in Server.rs to do this with one query*/
        Self::update_periodic().await?.error_for_status()?;
        Self::send_witnesses().await?.error_for_status()?;
        Self::send_public_params().await?.error_for_status()?;
        Ok(())
    }

    /// Ask server to send up-to-date list of witnesses to the Base Registry.
    pub async fn send_witnesses() -> Result<Response, Error> {
        let url = format!("http://{WEBSERVER}{SEND_WIT_URL}");
        let req = reqwest::Client::new().get(url);
        return Self::poll(&req).await;
    }

    /// Ask server to send up-to-date public parameters to the Base Registry.
    pub async fn send_public_params() -> Result<Response, Error> {
        let url = format!("http://{WEBSERVER}{SEND_PARAMS_URL}");
        let req = reqwest::Client::new().get(url);
        return Self::poll(&req).await;
    }
}
