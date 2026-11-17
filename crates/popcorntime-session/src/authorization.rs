use crate::server::{CallbackResult, run_local_oauth_server};
use anyhow::Result;
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::{AuthUrl, ClientId, RedirectUrl, TokenUrl};
use oauth2::{
  CsrfToken, EmptyExtraTokenFields, PkceCodeChallenge, RefreshToken, Scope, StandardTokenResponse,
  TokenResponse, reqwest,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use url::Url;

const PORT: u16 = 8085;
// Thread timeout in seconds
const THREAD_TIMEOUT: u64 = 300;

pub type HydraClient = oauth2::Client<
  oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
  oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
  oauth2::StandardTokenIntrospectionResponse<
    oauth2::EmptyExtraTokenFields,
    oauth2::basic::BasicTokenType,
  >,
  oauth2::StandardRevocableToken,
  oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
  oauth2::EndpointSet,
  oauth2::EndpointNotSet,
  oauth2::EndpointNotSet,
  oauth2::EndpointNotSet,
  oauth2::EndpointSet,
>;

pub type HydraAccessToken = StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>;

#[derive(Clone, Debug)]
pub struct AuthorizationBroker {
  reqwest_client: Arc<reqwest::Client>,
  oauth2_client: Arc<HydraClient>,
  server_running: Arc<AtomicBool>,
}

pub struct AuthorizationBrokerResponse {
  pub access_token: String,
  pub expires_in: Option<Duration>,
  pub refresh_token: String,
}

impl From<HydraAccessToken> for AuthorizationBrokerResponse {
  fn from(token: HydraAccessToken) -> Self {
    Self {
      access_token: token.access_token().secret().to_string(),
      expires_in: token.expires_in(),
      refresh_token: token
        .refresh_token()
        .map(|t| t.secret().to_string())
        .unwrap_or_default(),
    }
  }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationBrokerEvent {
  pub authorize_url: String,
}

impl Default for AuthorizationBrokerEvent {
  fn default() -> Self {
    Self {
      authorize_url: format!("http://127.0.0.1:{PORT}"),
    }
  }
}

impl AuthorizationBroker {
  pub fn new(client_id: &str, uri: impl TryInto<Url>) -> Result<Self> {
    tracing::info!("Creating new authorization broker for {}", client_id);
    let uri: Url = uri
      .try_into()
      .map_err(|_| anyhow::anyhow!("Invalid oauth2 uri"))?;
    let auth_url = AuthUrl::new(uri.join("oauth2/auth").unwrap_or(uri.clone()).to_string())?;
    let token_url = TokenUrl::new(uri.join("oauth2/token").unwrap_or(uri).to_string())?;

    let reqwest_client = reqwest::ClientBuilder::new()
      // following redirects opens the client up to SSRF vulnerabilities
      .redirect(reqwest::redirect::Policy::none())
      .https_only(!cfg!(debug_assertions))
      .connect_timeout(Duration::from_secs(5))
      .timeout(Duration::from_secs(15))
      .build()?;

    let client = BasicClient::new(ClientId::new(client_id.to_string()))
      .set_auth_uri(auth_url)
      .set_token_uri(token_url)
      .set_redirect_uri(RedirectUrl::new(format!(
        "http://127.0.0.1:{PORT}/callback"
      ))?);

    Ok(Self {
      reqwest_client: Arc::new(reqwest_client),
      oauth2_client: Arc::new(client),
      server_running: Arc::new(AtomicBool::new(false)),
    })
  }

  pub async fn exchange_refresh_token(
    &self,
    refresh_token: &RefreshToken,
  ) -> Result<AuthorizationBrokerResponse> {
    self
      .oauth2_client
      .exchange_refresh_token(refresh_token)
      .request_async(self.reqwest_client.as_ref())
      .await
      .map(Into::into)
      .map_err(Into::into)
  }

  pub async fn authorize_in_background(
    &self,
    on_ready: impl Fn(AuthorizationBrokerEvent) -> Result<()> + Send + Sync + 'static,
    send_event: impl Fn(AuthorizationBrokerResponse) -> Result<()> + Send + Sync + 'static,
  ) -> Result<()> {
    let server_running = self.server_running.clone();
    // atomically claim the server slot; if a login is already pending, just
    // re-open the browser on the existing local server
    if server_running
      .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
      .is_err()
    {
      return on_ready(AuthorizationBrokerEvent::default());
    }

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (tx, mut rx) = mpsc::channel::<CallbackResult>(1);
    let http_client = self.reqwest_client.clone();
    let oauth2_client = self.oauth2_client.clone();
    let (authorize_url, csrf_state) = oauth2_client
      .authorize_url(CsrfToken::new_random)
      .add_scope(Scope::new("openid".to_string()))
      .add_scope(Scope::new("offline".to_string()))
      .add_scope(Scope::new("profile".to_string()))
      .set_pkce_challenge(pkce_challenge)
      .url();
    let send_event = Arc::new(send_event);
    let csrf_state = csrf_state.into_secret();

    tauri::async_runtime::spawn({
      let send_event = Arc::clone(&send_event);
      async move {
        match timeout(Duration::from_secs(THREAD_TIMEOUT), rx.recv()).await {
          Ok(Some(Err(error))) => {
            tracing::warn!("Authorization was not granted: {error}");
          }
          // the CSRF state has already been validated by the local server
          Ok(Some(Ok(code))) => {
            match oauth2_client
              .exchange_code(code)
              .set_pkce_verifier(pkce_verifier) // Now safely moved
              .request_async(http_client.as_ref())
              .await
            {
              Ok(token) => {
                if let Err(err) = send_event(token.into()) {
                  tracing::error!("Failed to handle token: {:?}", err);
                }
              }
              Err(err) => {
                tracing::error!("Failed to exchange code: {:?}", err);
              }
            }
          }
          Ok(None) => {
            tracing::error!("Channel closed before receiving a response.");
          }
          Err(_) => {
            tracing::warn!("Authorization code exchange timed out.");
          }
        }
      }
    });

    tauri::async_runtime::spawn(async move {
      // emit once the server task is about to bind; the browser only hits
      // the server after the user interacts, so this ordering is safe
      if let Err(err) = on_ready(AuthorizationBrokerEvent::default()) {
        tracing::error!("Failed to send authorize url: {:?}", err);
        server_running.store(false, Ordering::SeqCst);
        return;
      }

      // blocks until a valid callback is received or the timeout elapses,
      // then releases the port so a new login can start cleanly
      if let Err(err) = run_local_oauth_server(
        authorize_url,
        csrf_state,
        PORT,
        tx,
        Duration::from_secs(THREAD_TIMEOUT),
      )
      .await
      {
        tracing::error!("Local OAuth server failed: {:?}", err);
      }

      server_running.store(false, Ordering::SeqCst);
    });

    Ok(())
  }
}
