use std::sync::Arc;

use axum::extract::State;
use axum_extra::extract::{CookieJar, cookie::Cookie};
use lettre::message::Mailbox;

use crate::{
    Json, State as Horizon,
    authentication::{Credentials, Session, api::SESSION_COOKIE},
    email::Email,
    error::{Context, Error},
    user::User,
};

/// Creates the user's account and sends a verification email
#[utoipa::path(
    post,
    tag = "Authentication",
    path = "/auth/signup",
    request_body = Credentials,
    responses(
        (
            status = 200,
            description = "\
                The user has been created and the verification email has been sent. \n\n\
                If the user already exists, the response will sill be 200 OK. This is to make \
                it indistinguishable to the user that an account with that email already exists. \
                They should be told that a verification email has been sent, even if it really \
                wasn't.
            "
        ),
        (
            status = 400,
            description = "The JSON was not correctly formatted or the email address is invalid",
            body = [Error],
            example = json!({
                "kind": "bad_request",
                "message": "Failed to deserialize the JSON body into the target type: missing field `email` at line 1 column 85",
                "request_id": "d44102b5-1e93-42ae-99fe-c208be4a958a"
            })
        ),
        (
            status = 422,
            description = "\
                The SMTP relay gave a negative response, meaning it could not forward the message. \
                While this could be the relay's fault, it most likely is because the address doesn't point \
                to any valid smtp server. \
            ",
            body = [Error],
            example = json!({
                "kind": "email_failed",
                "message": "Could not send email",
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
pub async fn signup(
    state: State<Arc<Horizon>>,
    Json(credentials): Json<Credentials>,
) -> Result<(), Error> {
    let recipient = Mailbox::new(
        None,
        credentials
            .email
            .trim()
            .parse()
            .context("Parsing email address")?,
    );

    let mut user = User::try_from(credentials).context("Building user from credentials")?;

    let token = user
        .insert(&state.database, &state.configuration.authentication.key)
        .await
        .context("Inserting new user")?;

    let Some(token) = token else {
        // There is a side-channel attack possible here.
        // Sending an email takes time, and since this returns significantly earlier, it could be
        // used as an indicator for an enumeration exploit.
        return Ok(());
    };

    let email = Email::new(
        &state.configuration.smtp.templates.verification,
        &liquid::object!({"token": &token,}),
        &state.configuration.smtp,
        recipient,
    )
    .context("Creating verification email")?;

    email.send().await.context("Sending verification email")
}

/// Checks the credentials and adds a session cookie if valid
#[utoipa::path(
    post,
    tag = "Authentication",
    path = "/auth/login",
    request_body = Credentials,
    responses(
        (
            status = 200,
            description = "Horizon added the session cookie to the cookie jar."
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
    state: State<Arc<Horizon>>,
    jar: CookieJar,
    Json(credentials): Json<Credentials>,
) -> Result<CookieJar, Error> {
    let user_id = credentials
        .verify(&state.database)
        .await
        .context("Verifying credentials")?;

    let session_id = Session::new(
        user_id,
        &state.configuration.authentication.key,
        &state.database,
    )
    .await
    .context("Creating new session")?;

    let cookie = Cookie::build((SESSION_COOKIE, session_id))
        .domain(state.configuration.authentication.domain.clone())
        .path("/api")
        .secure(true)
        .http_only(true)
        .build();

    Ok(jar.add(cookie))
}

/// Logs out the passed session
#[utoipa::path(
    post,
    tag = "Authentication",
    path = "/auth/logout",
    params(
        ("X-CSRF-Token" = String, Header, description = "Anti-CSRF token. Looks like 32 bytes encoded in hex"),
        ("session_id" = String, Cookie, description = "Session ID. Looks like 32 bytes encoded in hex")
    ),
    responses(
        (
            status = 200,
            description = "The session has been logged out, and the cookie removed from the jar."
        ),
        (
            status = 401,
            description = "The passed cookie jar did not include a `session_id` cookie",
            body = [Error],
            example = json!({
                "kind": "session_cookie_missing",
                "message": "A session cookie was not provided for an operation requiring authentication",
                "request_id": "d44102b5-1e93-42ae-99fe-c208be4a958a"
            })
        ),
        (
            status = 401,
            description = "The session did not include the `X-CSRF-Token` header",
            body = [Error],
            example = json!({
                "kind": "csrf_header_missing",
                "message": "An anti-CSRF token was not provided for an operation requiring authentication",
                "request_id": "d44102b5-1e93-42ae-99fe-c208be4a958a"
            })
        ),
        (
            status = 401,
            description = "The `session_id` and `csrf-token` don't evaluate to any active session",
            body = [Error],
            example = json!({
                "kind": "session_not_found",
                "message": "No valid session found for the provided token",
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
pub async fn logout(
    state: State<Arc<Horizon>>,
    jar: CookieJar,
    session: Session,
) -> Result<CookieJar, Error> {
    session.delete(&state.database).await?;

    Ok(jar.remove(Cookie::from(SESSION_COOKIE)))
}

/// Logs out all the user's sessions
#[utoipa::path(
    post,
    tag = "Authentication",
    path = "/auth/logout_all",
    params(
        ("X-CSRF-Token" = String, Header, description = "Anti-CSRF token. Looks like 32 bytes encoded in hex"),
        ("session_id" = String, Cookie, description = "Session ID. Looks like 32 bytes encoded in hex")
    ),
    responses(
        (
            status = 200,
            description = "\
                All the sessions have been logged out, and the caller's cookie removed from the jar. \
                Cookies in other clients will still be present, but invalid. \
            "
        ),
        (
            status = 401,
            description = "The passed cookie jar did not include a `session_id` cookie",
            body = [Error],
            example = json!({
                "kind": "session_cookie_missing",
                "message": "A session cookie was not provided for an operation requiring authentication",
                "request_id": "d44102b5-1e93-42ae-99fe-c208be4a958a"
            })
        ),
        (
            status = 401,
            description = "The session did not include the `X-CSRF-Token` header",
            body = [Error],
            example = json!({
                "kind": "csrf_header_missing",
                "message": "An anti-CSRF token was not provided for an operation requiring authentication",
                "request_id": "d44102b5-1e93-42ae-99fe-c208be4a958a"
            })
        ),
        (
            status = 401,
            description = "The `session_id` and `csrf-token` don't evaluate to any active session",
            body = [Error],
            example = json!({
                "kind": "session_not_found",
                "message": "No valid session found for the provided token",
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
pub async fn logout_all(
    state: State<Arc<Horizon>>,
    jar: CookieJar,
    session: Session,
) -> Result<CookieJar, Error> {
    session.delete_all(&state.database).await?;

    Ok(jar.remove(Cookie::from(SESSION_COOKIE)))
}
