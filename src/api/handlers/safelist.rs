use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;
use utoipa::ToSchema;

use crate::AppState;
use crate::api::auth::{require_auth, require_role};
use crate::auth::AuthSession;
use crate::error::PrefixdError;

use super::{MAX_STRING_LEN, MAX_USERNAME_LEN, validate_string_len};

fn validate_cidr(prefix: &str) -> Result<(), PrefixdError> {
    if prefix.contains('/') {
        prefix
            .parse::<ipnet::IpNet>()
            .map_err(|_| PrefixdError::InvalidRequest(format!("invalid prefix: '{}'", prefix)))?;
    } else {
        prefix
            .parse::<IpAddr>()
            .map_err(|_| PrefixdError::InvalidRequest(format!("invalid prefix: '{}'", prefix)))?;
    }
    Ok(())
}

#[derive(Deserialize, ToSchema)]
pub struct AddSafelistRequest {
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "Caller-supplied actor is ignored; request authentication determines the actor"
    )]
    operator_id: String,
    prefix: String,
    #[serde(default)]
    reason: Option<String>,
}

pub async fn list_safelist(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let entries = state
        .repo
        .list_safelist()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(entries))
}

/// Add a prefix to the safelist (admin only)
#[utoipa::path(
    post,
    path = "/v1/safelist",
    tag = "safelist",
    request_body = AddSafelistRequest,
    responses(
        (status = 201, description = "Safelist entry created"),
        (status = 400, description = "Invalid prefix"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions")
    )
)]
pub async fn add_safelist(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<AddSafelistRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;
    let operator_id = operator.username;

    validate_cidr(&req.prefix).map_err(|_| StatusCode::BAD_REQUEST)?;
    validate_string_len(&operator_id, "operator_id", MAX_USERNAME_LEN)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(ref reason) = req.reason {
        validate_string_len(reason, "reason", MAX_STRING_LEN)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    }

    state
        .repo
        .insert_safelist(&req.prefix, &operator_id, req.reason.as_deref())
        .await
        .map_err(|e| {
            tracing::error!(target: "prefixd::api::handlers", error = %e, "add_safelist failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!(target: "prefixd::api::handlers", prefix = %req.prefix, operator = %operator_id, "safelist entry added");
    Ok(StatusCode::CREATED)
}

/// Remove a prefix from the safelist (admin only)
#[utoipa::path(
    delete,
    path = "/v1/safelist/{prefix}",
    tag = "safelist",
    params(
        ("prefix" = String, Path, description = "CIDR prefix to remove")
    ),
    responses(
        (status = 204, description = "Safelist entry removed"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Prefix not in safelist")
    )
)]
pub async fn remove_safelist(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Path(prefix): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let _operator = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    let removed = state.repo.remove_safelist(&prefix).await.map_err(|e| {
        tracing::error!(target: "prefixd::api::handlers", error = %e, "remove_safelist failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_validate_cidr_accepts_valid_values() {
        assert!(super::validate_cidr("203.0.113.0/24").is_ok());
        assert!(super::validate_cidr("2001:db8::/64").is_ok());
        assert!(super::validate_cidr("203.0.113.10").is_ok());
    }

    #[test]
    fn test_validate_cidr_rejects_invalid_masks() {
        assert!(super::validate_cidr("203.0.113.0/33").is_err());
        assert!(super::validate_cidr("2001:db8::/129").is_err());
        assert!(super::validate_cidr("203.0.113.0/not-a-mask").is_err());
    }
}
