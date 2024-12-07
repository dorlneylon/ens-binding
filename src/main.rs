use anyhow::Result;
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use ethers_ccip_read::CCIPReadMiddleware;
use ethers_providers::{Http, Middleware, Provider};
use serde::{Deserialize, Serialize};
use thiserror::Error;

impl IntoResponse for ServerError {
    fn into_response(self) -> axum::response::Response {
        let body = Json(serde_json::json!({
            "error": self.to_string()
        }));

        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

#[derive(Debug, Deserialize)]
struct ResolveQuery {
    name: String,
}

#[derive(Debug, Serialize)]
struct ResolveResponse {
    ens_name: String,
    resolver_address: String,
    supports_wildcard: bool,
    resolved_address: String,
}

#[derive(Error, Debug)]
enum ServerError {
    #[error("Provider configuration error: {0}")]
    ProviderConfigError(String),

    #[error("ENS resolution error: {0}")]
    ResolutionError(String),
}

impl From<anyhow::Error> for ServerError {
    fn from(err: anyhow::Error) -> Self {
        ServerError::ResolutionError(err.to_string())
    }
}

async fn resolve_ens_name(
    Query(params): Query<ResolveQuery>,
) -> Result<Json<ResolveResponse>, ServerError> {
    let provider_url = dotenv::var("ETHEREUM_PROVIDER_URL").map_err(|_| {
        ServerError::ProviderConfigError("ETHEREUM_PROVIDER_URL not set".to_string())
    })?;

    let provider = Provider::<Http>::try_from(provider_url)
        .map_err(|e| ServerError::ProviderConfigError(e.to_string()))?;

    let provider = CCIPReadMiddleware::new(provider);

    let ens_name = &params.name;

    let resolver_address = provider
        .get_resolver(ens_name)
        .await
        .map_err(|e| ServerError::ResolutionError(format!("Resolver lookup error: {}", e)))?;

    let supports_wildcard = provider
        .supports_wildcard(resolver_address)
        .await
        .map_err(|e| {
            ServerError::ResolutionError(format!("Wildcard support check error: {}", e))
        })?;

    let resolved_address = provider
        .resolve_name(ens_name)
        .await
        .map_err(|e| ServerError::ResolutionError(format!("Name resolution error: {}", e)))?;

    Ok(Json(ResolveResponse {
        ens_name: ens_name.to_string(),
        resolver_address: format!("{:?}", resolver_address),
        supports_wildcard,
        resolved_address: format!("{:?}", resolved_address),
    }))
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    tracing_subscriber::fmt::init();

    let app = Router::new().route("/resolve", get(resolve_ens_name));

    let port = dotenv::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .unwrap_or(3000);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Listening on: {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
