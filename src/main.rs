mod build_config;
mod callback;
use std::collections::HashMap;

use build_config::BUILD_CONFIG;

use chrono::prelude::*;

use anyhow::{anyhow, Context, Result};
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    PkceCodeChallenge, RedirectUrl, Scope, StandardTokenResponse, TokenResponse, TokenUrl,
};
use portpicker::pick_unused_port;

#[macro_use]
extern crate serde_derive;

#[derive(Serialize, Deserialize, Debug)]
struct CachedTokens {
    access_token: String,
    refresh_token: Option<String>,
    expires: Option<DateTime<Local>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Command {
    name: String,
    args: Vec<String>,
    stdin: Option<String>,
    uploads: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct CommandResult {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let entry = keyring::Entry::new(
        &BUILD_CONFIG.keyring_service,
        &BUILD_CONFIG.keyring_username,
    );
    let tokens = match load_tokens(&entry) {
        Ok(tokens) => tokens,
        Err(_) => request_tokens(&entry).await?,
    };

    let args = std::env::args().collect::<Vec<String>>();
    let (name, args) = args
        .split_first()
        .context("something wrong with the arguments")?;

    let cmd = Command {
        name: name.to_string(),
        args: args.to_vec(),
        stdin: None,
        uploads: None,
    };

    // request GET https://api.github.com/user
    let client = reqwest::Client::new();
    let res = client
        .post(BUILD_CONFIG.shim_endpoint_url.as_ref())
        .header("User-Agent", "cmd-shim/0.1.0")
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .json(&cmd)
        .send()
        .await?
        .json::<CommandResult>()
        .await;
    match res {
        Ok(res) => {
            print!("{}", res.stderr);
            print!("{}", res.stdout);
            std::process::exit(res.exit_code);
        }
        Err(err) => {
            println!("{}", err);
            std::process::exit(1);
        }
    }
}

async fn request_tokens(entry: &keyring::Entry) -> Result<CachedTokens> {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let port = pick_unused_port().context("failed to pick port")?;
    let client = BasicClient::new(
        ClientId::new(BUILD_CONFIG.client_id.clone()),
        Some(ClientSecret::new(BUILD_CONFIG.client_secret.clone())),
        AuthUrl::new(BUILD_CONFIG.auth_uri.clone())?,
        Some(TokenUrl::new(BUILD_CONFIG.token_uri.clone())?),
    )
    .set_redirect_uri(RedirectUrl::new(format!(
        "http://127.0.0.1:{}/callback",
        port
    ))?);

    let mut auth_req = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge);

    // add each scope
    for scope in BUILD_CONFIG.scopes.clone() {
        auth_req = auth_req.add_scope(Scope::new(scope));
    }

    let (auth_url, csrf_token) = auth_req.url();
    println!("Browse to: {}", auth_url);
    let auth_info = callback::run(format!("127.0.0.1:{}", port)).await?;
    auth_info.validate(csrf_token)?;

    let token_result = client
        .exchange_code(AuthorizationCode::new(auth_info.auth_code))
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    store_tokens(entry, &token_result)
}

fn load_tokens(entry: &keyring::Entry) -> Result<CachedTokens> {
    let tokens = entry.get_password()?;
    let tokens: CachedTokens = serde_json::from_str(&tokens)?;

    match tokens.expires {
        Some(expires) if expires < Local::now() => {
            entry.delete_password()?;
            return Err(anyhow!("Token expired"));
        }
        _ => {}
    }

    Ok(tokens)
}

fn store_tokens(
    entry: &keyring::Entry,
    tokens_result: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
) -> Result<CachedTokens> {
    let access_token = tokens_result.access_token().secret().to_string();
    let refresh_token = tokens_result
        .refresh_token()
        .map(|r| r.secret().to_string());
    let expires = tokens_result
        .expires_in()
        .map(|e| Some(Local::now() + chrono::Duration::from_std(e).ok()?))
        .flatten();
    let tokens = CachedTokens {
        access_token,
        refresh_token,
        expires,
    };

    let tokens_json = serde_json::to_string(&tokens)?;
    entry.set_password(&tokens_json)?;
    Ok(tokens)
}
