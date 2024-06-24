use crate::{
    base_registry::{BASE_REGISTRY_FRONT, PARAMS_URL, POLYS_URL, WIT_URL},
    server::{Update, ISSUE_URL, WEBSERVER},
};
use accumulator::{
    proof::ProofParamsPublic, witness::MembershipWitness
};

use entities::{
    holder::Holder, issuer::RevocationHandle, UpdatePolynomials, 
};

pub struct Client;

impl Client {

    /// Ask the issuer to add new holder associated with psuedonym `pseudo` and return respective revocation handle
    pub async fn ask_issuance(pseudo: String) -> Result<RevocationHandle, Box<dyn std::error::Error>> {
        let url = format!("http://{WEBSERVER}{ISSUE_URL}");
        let resp = reqwest::Client::new()
            .post(url)
            .body(pseudo.clone())
            .send()
            .await?
            .error_for_status()?;
        let rh: RevocationHandle = bincode::deserialize(&resp.bytes().await?)?;
        Ok(rh)
    }

    /// Get proof public parameters from the Base Registry
    pub async fn ask_pp() -> Result<ProofParamsPublic, Box<dyn std::error::Error>> {
        let url = format!("http://{BASE_REGISTRY_FRONT}{PARAMS_URL}");
        let req = reqwest::Client::new().get(url);
        let body = req.send().await?.bytes().await?;
        let pp: ProofParamsPublic = bincode::deserialize(&body)?;
        return Ok(pp);
    }

    /// Get proof public parameters from the Base Registry
    pub async fn ask_accumulator() -> Result<ProofParamsPublic, Box<dyn std::error::Error>> {
        let url = format!("http://{BASE_REGISTRY_FRONT}{PARAMS_URL}");
        let req = reqwest::Client::new().get(url);
        let body = req.send().await?.bytes().await?;
        let pp: ProofParamsPublic = bincode::deserialize(&body)?;
        return Ok(pp);
    }

    /// Update witness of the input `Holder` instance `holder`. 
    /// It uses `holder`'s last accumulator id to query the Base Register 
    /// and get the respective update polynomials.
    pub async fn poly_upd(holder: &mut Holder) -> Result<bool, Box<dyn std::error::Error>> {
        let url = format!("http://{BASE_REGISTRY_FRONT}{POLYS_URL}");

        // Get last valid accumulator id and ask update poly
        let acc_id = holder.get_accumulator_id();
        let body = bincode::serialize(&acc_id)?;
        let req = reqwest::Client::new().get(url).body(body);
        let resp = req.send().await?.error_for_status()?;

        let body = resp.bytes().await?;
        let updates: Vec<UpdatePolynomials> = bincode::deserialize(&body)?;
        holder.batch_updates(updates.as_slice())?;
        return Ok(true);
    }

    pub async fn wit_upd(hol: &mut Holder) -> Result<bool, Box<dyn std::error::Error>> {
        let url = format!("http://{BASE_REGISTRY_FRONT}{WIT_URL}");
        let req = reqwest::Client::new()
            .get(url)
            .query(&[("pseudo", hol.get_pseudo())]);
        let resp = req.send().await?;
        match resp.status().is_success() {
            true => {
                let body = resp.bytes().await?;
                let c : MembershipWitness = bincode::deserialize(&body)?;
                hol.replace_witness(c);
                return Ok(true);
            }
            false => {
                return Ok(false);
            }
        }
    }


}
