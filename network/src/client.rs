use crate::{
    base_registry::{
        PeriodicUpdate, Update, ACC_URL, BASE_REGISTRY_FRONT, PARAMS_URL, POLYS_URL, WIT_URL,
    },
    log_with_time, log_with_time_ln,
    server::{ISSUE_URL, WEBSERVER},
};
use accumulator::{proof::ProofParamsPublic, Accumulator};

use entities::{holder::Holder, issuer::RevocationHandle, Updatable};

pub struct Client;

impl Client {
    /// Ask the issuer to add new holder associated with psuedonym `pseudo` and return respective revocation handle
    pub async fn ask_issuance(
        pseudo: String,
    ) -> Result<RevocationHandle, Box<dyn std::error::Error>> {
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
    /// Get proof accumulator from the Base Registry and update the input client's accumulator
    pub async fn update_pp(
        client: &mut impl Updatable,
    ) -> Result<ProofParamsPublic, Box<dyn std::error::Error>> {
        let pp = Client::ask_pp().await?;
        client.update_public_params(pp);
        return Ok(pp);
    }

    /// Get proof accumulator from the Base Registry
    pub async fn ask_accumulator() -> Result<Accumulator, Box<dyn std::error::Error>> {
        let url = format!("http://{BASE_REGISTRY_FRONT}{ACC_URL}");
        let req = reqwest::Client::new().get(url);
        let body = req.send().await?.bytes().await?;
        let acc: Accumulator = bincode::deserialize(&body)?;
        return Ok(acc);
    }

    /// Get proof accumulator from the Base Registry and update the input client's accumulator
    pub async fn update_accumulator(
        client: &mut impl Updatable,
    ) -> Result<Accumulator, Box<dyn std::error::Error>> {
        let acc = Client::ask_accumulator().await?;
        client.update_accumulator(acc);
        return Ok(acc);
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

        // Parse update
        let body = resp.bytes().await?;
        let updates: Update = bincode::deserialize(&body)?;
        let new_acc = updates.0;
        let update_polys = updates.1;

        // Update holder witness and accumulator
        log_with_time!(
            "{} starts batch update of {} elements ...",
            holder.get_pseudo(),
            update_polys
                .iter()
                .fold(0, |acc, el| acc + el.deletions.len())
        );
        holder.update(update_polys.as_slice())?;
        holder.update_accumulator(new_acc);
        log_with_time_ln!("Done.",);
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
                // Parse update
                let body = resp.bytes().await?;
                let update: PeriodicUpdate = bincode::deserialize(&body)?;

                // Update witness and accumulator
                hol.apply_update(update.1);
                hol.update_accumulator(update.0);

                return Ok(true);
            }
            false => {
                return Ok(false);
            }
        }
    }
}
