//! Print the OpenAPI spec to stdout as pretty JSON.
//!
//! Used by `just generate-rest-openapi` to refresh the committed
//! `crates/dark-wallet-rest/openapi.json`. CI diffs the output against the
//! committed spec so drift fails builds.

use dark_wallet_rest::ApiDoc;
use utoipa::OpenApi;

fn main() {
    let spec = ApiDoc::openapi();
    let json = serde_json::to_string_pretty(&spec).expect("serialize OpenAPI");
    println!("{json}");
}
