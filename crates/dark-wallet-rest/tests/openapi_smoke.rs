//! Smoke tests for the generated OpenAPI surface.
//!
//! These tests do not require a running `dark` server — they only exercise
//! the static spec assembly. For end-to-end round-trips that hit a live
//! server, run `./scripts/e2e-test.sh` with the REST daemon started
//! alongside dark.

use dark_wallet_rest::ApiDoc;
use utoipa::OpenApi;

fn spec_json() -> serde_json::Value {
    serde_json::to_value(ApiDoc::openapi()).expect("serialize OpenAPI spec")
}

/// Every route declared in the v1 design must land in the generated spec.
#[test]
fn openapi_has_expected_paths() {
    let spec = spec_json();
    let paths = spec
        .pointer("/paths")
        .and_then(|v| v.as_object())
        .expect("paths object");

    let expected = [
        "/ping",
        "/v1/info",
        "/v1/vtxos",
        "/v1/vtxos/{outpoint}/chain",
        "/v1/rounds",
        "/v1/rounds/{id}",
        "/v1/rounds/{id}/tree",
        "/v1/rounds/{id}/commitment-tx",
        "/v1/txs",
        "/v1/txs/query",
        "/v1/txs/{id}",
        "/v1/txs/{id}/finalize",
        "/v1/intents",
        "/v1/intents/{id}",
        "/v1/intents/{id}/confirm",
        "/v1/intents/{id}/fee",
        "/v1/exits",
        "/v1/events",
        "/v1/transactions/events",
        "/v1/playground/session",
        "/v1/playground/session/{id}",
        "/v1/playground/faucet",
    ];

    for path in expected {
        assert!(
            paths.contains_key(path),
            "expected path {path} missing from OpenAPI spec (has {} paths)",
            paths.len()
        );
    }
}

/// Bearer security scheme must be registered so generators emit auth stubs.
#[test]
fn openapi_has_bearer_security() {
    let spec = spec_json();
    let schemes = spec
        .pointer("/components/securitySchemes/bearer")
        .expect("bearer security scheme");

    assert_eq!(
        schemes.pointer("/scheme").and_then(|v| v.as_str()),
        Some("bearer")
    );
    assert_eq!(
        schemes.pointer("/bearerFormat").and_then(|v| v.as_str()),
        Some("macaroon")
    );
}

/// Components (schemas) must include the DTOs used by the core flow.
#[test]
fn openapi_has_expected_schemas() {
    let spec = spec_json();
    let schemas = spec
        .pointer("/components/schemas")
        .and_then(|v| v.as_object())
        .expect("schemas object");

    for name in [
        "ServerInfoDto",
        "VtxoDto",
        "RoundInfoDto",
        "SubmitTxRequestDto",
        "RegisterIntentRequestDto",
        "RequestExitRequestDto",
        "BatchEventDto",
        "TxEventDto",
        "CreateSessionResponse",
        "FaucetResponse",
        "ProblemDetails",
    ] {
        assert!(
            schemas.contains_key(name),
            "schema {name} missing from OpenAPI spec"
        );
    }
}

/// `/ping` must be unauthenticated (empty security object).
#[test]
fn openapi_ping_has_empty_security() {
    let spec = spec_json();
    let security = spec
        .pointer("/paths/~1ping/get/security")
        .and_then(|v| v.as_array())
        .expect("ping has security override");
    assert_eq!(
        security.len(),
        1,
        "ping should have a single security entry"
    );
    assert!(
        security[0]
            .as_object()
            .map(|o| o.is_empty())
            .unwrap_or(false),
        "ping should override security to empty"
    );
}
