use axum::response::Json;
use utoipa::OpenApi;

use crate::{
    authentication::{AuthApiDocs, AuthModelDocs},
    error::Error,
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Horizon API",
        contact(),
    ),
    servers(
        (url = "https://vilahack.com/api/v0", description = "Production"),
        (url = "https://staging.vilahack.com/api/v0", description = "Staging"),
    ),
    paths(openapi_json),
    components(schemas(Error)),
)]
struct ApiDoc;

fn build_openapi() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();
    doc.merge(AuthApiDocs::openapi());
    doc.merge(AuthModelDocs::openapi());
    doc
}

#[utoipa::path(
    get,
    tag = "OpenAPI",
    path = "/openapi.json",
    responses(
        (
            status = 200,
            description = "Returns the openapi spec as a json response"
        ),
    )
)]
pub async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(build_openapi())
}
