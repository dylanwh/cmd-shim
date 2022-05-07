use axum::{routing::get, Router, extract::Query};
extern crate keyring;
extern crate serde;
extern crate serde_json;
use anyhow::{Context, Result, anyhow};
use oauth2::CsrfToken;


use std::{net::SocketAddr, collections::HashMap};
use tokio::sync::mpsc::{channel, unbounded_channel};

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthInfo {
    pub auth_code: String,
    pub state: String,
}

impl AuthInfo {
    pub fn validate(&self, token: CsrfToken) -> Result<()> {
        if &self.state == token.secret() {
            Ok(())
        } else {
            Err(anyhow!("state mismatch"))
        }
    }
}
    

fn auth_info_from_params(params: &HashMap<String, String>) -> Option<AuthInfo> {
    let auth_info = AuthInfo {
        auth_code: params.get("code")?.to_string(),
        state: params.get("state")?.to_string(),
    };
    Some(auth_info)
}


pub async fn run(bind: String) -> Result<AuthInfo> {
    // create a future to signal when we should stop
    let (stop_tx, mut stop_rx) = unbounded_channel::<()>();
    let (callback_tx, mut callback_rx) = channel::<Option<AuthInfo>>(1);

    // build our application with a single route
    let app = Router::new().route(
        "/callback",
        get(|Query(params): Query<HashMap<String, String>>| async move {
            // get query parameters
            let auth_info = auth_info_from_params(&params);
            let _ = callback_tx.send(auth_info).await;
            "You can close this window now".to_string()
        }),
    );


    // create a future to signal when we should stop

    // run it with hyper on localhost:3000
    let server = axum::Server::bind(&bind.parse::<SocketAddr>()?)
        .serve(app.into_make_service())
        .with_graceful_shutdown(async move {
            stop_rx.recv().await;
        });
    tokio::spawn(server);

    let auth_info = callback_rx.recv().await.flatten().context("Failed to get auth info")?;
    stop_tx.send(())?;

    log::debug!("auth_info {:?}", auth_info);

    Ok(auth_info)
}