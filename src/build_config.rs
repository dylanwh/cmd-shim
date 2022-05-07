extern crate keyring;
extern crate serde;
extern crate serde_json;
use reqwest::Url;

use lazy_static::lazy_static; // for lazy_static!

#[derive(Serialize, Deserialize, Debug)]
pub enum IdentityProvider {
    GitHub,
    Okta,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BuildConfig {
   pub client_id: String,
   pub client_secret: String,
   pub auth_uri: String,
   pub token_uri: String,
   pub scopes: Vec<String>,
   pub keyring_service: String,
   pub keyring_username: String,
   pub identity_provider: IdentityProvider,
   pub shim_endpoint_url: Url,
}

const BUILD_CONFIG_JSON: &'static str = include_str!("build-config.json");

lazy_static! {
    pub static ref BUILD_CONFIG: BuildConfig = serde_json::from_str(BUILD_CONFIG_JSON).unwrap();
}
