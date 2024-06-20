use crate::{
    base_registry::{BASE_REGISTRY_FRONT, PARAMS_URL, WIT_URL},
    server::{ISSUE_URL, WEBSERVER},
};
use accumulator::{
    proof::ProofParamsPublic, witness::MembershipWitness
};

use entities::{
    holder::Holder, issuer::RevocationHandle, 
};

pub struct Client;

impl Client {

    pub async fn ask_pp() -> Result<ProofParamsPublic, Box<dyn std::error::Error>> {
        let url = format!("http://{BASE_REGISTRY_FRONT}{PARAMS_URL}");
        let req = reqwest::Client::new().get(url);

        let body = req.send().await?.text().await?;
        let pp: ProofParamsPublic = serde_json::from_str(&body)?;
        return Ok(pp);
    }

    pub async fn ask_update(hol: &mut Holder) -> Result<bool, Box<dyn std::error::Error>> {
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

    pub async fn ask_issuance(pseudo: String) -> Result<RevocationHandle, Box<dyn std::error::Error>> {
        let url = format!("http://{WEBSERVER}{ISSUE_URL}");
        let resp = reqwest::Client::new()
            .post(url)
            .body(pseudo.clone())
            .send()
            .await?;
        let rh: RevocationHandle = bincode::deserialize(&resp.bytes().await?)?;
        //self.holder = Holder::new(rh.get_elem(), self.holder.pp, Some(rh.get_witness()));
        Ok(rh)
    }

}
