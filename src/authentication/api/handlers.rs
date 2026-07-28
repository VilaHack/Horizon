use std::sync::Arc;

use axum::extract::State;
use axum_extra::extract::{CookieJar, cookie::Cookie};

use mongodb::bson::Uuid;

use crate::{
    Json, State as Horizon,
    authentication::Session,
    error::{Context, Error},
    user::Credentials,
};

/// Checks the credentials and adds a session cookie if valid
///
/// # Errors
/// Described in utoipa macro
#[utoipa::path(
    post,
    path = "/api/v0/auth/login",
    params(
        Credentials,
    ),
    responses(
        (
            status = 200,
            description = "
                Horizon added the session cookie to the cookie jar.
            "
        ),
        (
            status = 400,
            description = "The JSON was not correctly formatted",
            body = [Error],
            example = json!({
                "kind": "bad_request",
                "message": "Failed to deserialize the JSON body into the target type: missing field `email` at line 1 column 85",
                "request_id": "d44102b5-1e93-42ae-99fe-c208be4a958a"
            })
        ),
        (
            status = 401,
            description = "The credentials don't evaluate to any user",
            body = [Error],
            example = json!({
                "kind": "invalid_credentials",
                "message": "Incorrect email or password",
                "request_id": "d44102b5-1e93-42ae-99fe-c208be4a958a"
            })
        ),
        (
            status = 500,
            description = "Something went wrong and it's not the caller's fault",
            body = [Error],
            example = json!({
                "kind": "unexpected",
                "message": "Something unexpected happened",
                "request_id": "d44102b5-1e93-42ae-99fe-c208be4a958a"
            })
        )
    )
)]
pub async fn login(
    jar: CookieJar,
    state: State<Arc<Horizon>>,
    Json(credentials): Json<Credentials>,
) -> Result<CookieJar, Error> {
    let request_id = Uuid::new();

    let user_id = credentials
        .verify(&state.database)
        .await
        .root_context("Verifying credentials", request_id)?;

    let session_id = Session::new(
        user_id,
        &state.configuration.authentication.key,
        &state.database,
    )
    .await
    .root_context("Creating new session", request_id)?;

    let cookie = Cookie::build(("sessin_id", session_id))
        .domain(state.configuration.authentication.domain.clone())
        .path("/api")
        .secure(true)
        .http_only(true)
        .build();

    Ok(jar.add(cookie))
}
