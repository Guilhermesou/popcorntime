use anyhow::Result;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Deserialize, Clone)]
struct Jwks {
  keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
  pub sub: Uuid,
  #[serde(rename(deserialize = "exp"))]
  pub expiration: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Consent {
  #[serde(with = "time::serde::rfc3339::option")]
  pub tos: Option<time::OffsetDateTime>,
  pub newsletter: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Preferences {
  pub country: String,
  pub language: String,
}

/// Minimum delay between two forced JWKS refreshes triggered by an unknown `kid`.
/// Prevents a stream of tokens with random `kid`s from hammering the auth server.
const FORCED_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct JwksClient {
  client: reqwest::Client,
  issuer: String,
  cache: Arc<Mutex<Option<(Jwks, Instant)>>>,
  /// Last token that passed full signature validation, with its expiration.
  /// Every Tauri command validates the session; caching the result avoids
  /// re-parsing the RSA key and re-verifying the signature on each call.
  validated: Arc<std::sync::Mutex<Option<(String, i64, Uuid)>>>,
  ttl: Duration,
}

impl JwksClient {
  pub fn new(issuer: &str) -> Self {
    tracing::info!("Creating JwksClient for issuer: {}", issuer);
    let client = reqwest::Client::builder()
      .connect_timeout(Duration::from_secs(5))
      .timeout(Duration::from_secs(10))
      .redirect(reqwest::redirect::Policy::none())
      .build()
      .unwrap_or_default();
    Self {
      client,
      issuer: issuer.trim_end_matches('/').to_string(),
      cache: Arc::new(Mutex::new(None)),
      validated: Arc::new(std::sync::Mutex::new(None)),
      ttl: Duration::from_secs(3600), // 1 hour cache
    }
  }

  async fn fetch_jwks(&self) -> Result<Jwks> {
    Ok(
      self
        .client
        .get(&self.issuer)
        .send()
        .await?
        .error_for_status()?
        .json::<Jwks>()
        .await?,
    )
  }

  /// Returns the JWK for `kid`. The cache lock is held across the refresh so
  /// concurrent callers don't all hit the network when the cache expires.
  async fn get_jwk(&self, kid: &str) -> Result<Jwk> {
    let find = |jwks: &Jwks| {
      jwks
        .keys
        .iter()
        .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))
        .cloned()
    };

    let mut cache = self.cache.lock().await;

    if let Some((jwks, fetched_at)) = &*cache {
      let fresh = fetched_at.elapsed() < self.ttl;
      if let Some(jwk) = find(jwks).filter(|_| fresh) {
        return Ok(jwk);
      }
      // unknown kid on a fresh cache: the server may have rotated its keys,
      // but only force a refresh if the cooldown has elapsed
      if fresh && fetched_at.elapsed() < FORCED_REFRESH_COOLDOWN {
        anyhow::bail!("JWK not found");
      }
    }

    let jwks = self.fetch_jwks().await?;
    let jwk = find(&jwks);
    *cache = Some((jwks, Instant::now()));
    jwk.ok_or(anyhow::anyhow!("JWK not found"))
  }

  fn cached_validation(&self, token: &str) -> Option<Uuid> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let guard = self.validated.lock().ok()?;
    match &*guard {
      Some((cached, exp, sub)) if cached == token && *exp > now => Some(*sub),
      _ => None,
    }
  }

  pub async fn validate_token(&self, token: &str) -> Result<Uuid> {
    if let Some(sub) = self.cached_validation(token) {
      return Ok(sub);
    }

    let header = jsonwebtoken::decode_header(token)?;
    if header.alg != Algorithm::RS256 {
      anyhow::bail!("Unsupported token algorithm");
    }
    let kid = header.kid.ok_or(anyhow::anyhow!("Missing KID"))?;

    // Get matching JWK
    let jwk = self.get_jwk(&kid).await?;

    // Create decoding key
    let decoding_key = match jwk.algorithm {
      AlgorithmParameters::RSA(rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e)?,
      _ => anyhow::bail!("Unsupported algorithm"),
    };

    // Configure validation
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 60;

    // FIXME: would worth attaching the audience to kratos
    // and the internal service API token
    validation.validate_aud = false;
    // FIXME: resign internal API service token with the issuer
    //validation.set_issuer(&[self.issuer.clone()]);

    // Validate token
    tracing::debug!("Validating token with KID: {}", kid);
    let claims = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)?.claims;

    if let Ok(mut guard) = self.validated.lock() {
      // keep the leeway out of the cache: expire it at the real `exp`
      *guard = Some((token.to_string(), claims.expiration, claims.sub));
    }

    Ok(claims.sub)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn cached_validation_respects_expiration() {
    let client = JwksClient::new("https://example.invalid/jwks.json");
    let sub = Uuid::nil();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    *client.validated.lock().unwrap() = Some(("valid".into(), now + 60, sub));
    assert_eq!(client.cached_validation("valid"), Some(sub));
    assert_eq!(client.cached_validation("other"), None);

    *client.validated.lock().unwrap() = Some(("expired".into(), now - 1, sub));
    assert_eq!(client.cached_validation("expired"), None);
  }
}
