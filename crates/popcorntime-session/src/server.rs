use oauth2::AuthorizationCode;
use poem::{
  EndpointExt, IntoResponse, Request, Response, Route, Server, get, handler,
  http::StatusCode,
  listener::TcpListener,
  web::{Data, Query, Redirect},
};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use url::Url;

const SUCCESS_URL: &str = "https://watch.popcorntime.app/auth/success";

/// Result delivered to the broker once the browser hits `/callback`
/// with a valid `state`.
pub(crate) type CallbackResult = Result<AuthorizationCode, String>;

#[derive(Deserialize)]
struct CallbackQuery {
  code: Option<String>,
  state: Option<String>,
  error: Option<String>,
}

#[derive(Clone)]
struct ServerContext {
  authorize_url: String,
  csrf_state: String,
  expected_hosts: [String; 2],
  code_tx: mpsc::Sender<CallbackResult>,
  shutdown: CancellationToken,
}

impl ServerContext {
  /// Reject requests whose Host header is not our loopback address.
  /// Protects the local server against DNS-rebinding attacks from web pages.
  fn is_trusted_host(&self, req: &Request) -> bool {
    req
      .header("host")
      .is_some_and(|host| self.expected_hosts.iter().any(|h| h == host))
  }
}

/// Constant-time comparison to avoid leaking the CSRF state via timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false;
  }
  a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[handler]
async fn redirect_handler(req: &Request, Data(ctx): Data<&Arc<ServerContext>>) -> Response {
  if !ctx.is_trusted_host(req) {
    return StatusCode::FORBIDDEN.into_response();
  }
  Redirect::temporary(&ctx.authorize_url).into_response()
}

#[handler]
async fn callback_handler(
  req: &Request,
  Query(q): Query<CallbackQuery>,
  Data(ctx): Data<&Arc<ServerContext>>,
) -> Response {
  if !ctx.is_trusted_host(req) {
    return StatusCode::FORBIDDEN.into_response();
  }

  // Validate the CSRF state *before* doing anything else. A request with a
  // wrong/missing state must not shut the server down, otherwise any web page
  // could abort a pending login by hitting this endpoint.
  let state_ok = q
    .state
    .as_deref()
    .is_some_and(|s| constant_time_eq(s.as_bytes(), ctx.csrf_state.as_bytes()));
  if !state_ok {
    tracing::warn!("Rejected OAuth callback with invalid state");
    return (StatusCode::BAD_REQUEST, "Invalid state").into_response();
  }

  let result = match (q.code, q.error) {
    (Some(code), None) => Ok(AuthorizationCode::new(code)),
    (_, Some(error)) => Err(error),
    (None, None) => Err("missing_code".to_string()),
  };
  let is_ok = result.is_ok();

  if let Err(err) = ctx.code_tx.send(result).await {
    tracing::error!("Failed to send authorization code: {}", err);
  }

  ctx.shutdown.cancel();

  if is_ok {
    Redirect::temporary(SUCCESS_URL).into_response()
  } else {
    (
      StatusCode::BAD_REQUEST,
      "Authorization failed, you can close this window.",
    )
      .into_response()
  }
}

/// Runs the local OAuth callback server until a valid callback is received
/// or `timeout` elapses. Returns an error if the port could not be bound.
pub(crate) async fn run_local_oauth_server(
  authorize_url: Url,
  csrf_state: String,
  port: u16,
  code_tx: mpsc::Sender<CallbackResult>,
  timeout: Duration,
) -> anyhow::Result<()> {
  let shutdown = CancellationToken::new();
  let ctx = Arc::new(ServerContext {
    authorize_url: authorize_url.to_string(),
    csrf_state,
    expected_hosts: [format!("127.0.0.1:{port}"), format!("localhost:{port}")],
    code_tx,
    shutdown: shutdown.clone(),
  });

  let app = Route::new()
    .at("/", get(redirect_handler))
    .at("/callback", get(callback_handler))
    .data(ctx);

  let addr = SocketAddr::from(([127, 0, 0, 1], port));
  let listener = TcpListener::bind(addr);

  // stop the server after `timeout` so the port is always released
  let timeout_guard = shutdown.clone();
  let timer = tokio::spawn(async move {
    tokio::time::sleep(timeout).await;
    timeout_guard.cancel();
  });

  let result = Server::new(listener)
    .run_with_graceful_shutdown(
      app,
      shutdown.cancelled_owned(),
      Some(Duration::from_secs(2)),
    )
    .await;

  timer.abort();
  result.map_err(Into::into)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test(flavor = "multi_thread")]
  async fn callback_server_hardening() {
    let port = 18085;
    let (tx, mut rx) = mpsc::channel::<CallbackResult>(1);
    let authorize_url = Url::parse("https://auth.example/oauth2/auth?state=s3cret").unwrap();
    let server = tokio::spawn(run_local_oauth_server(
      authorize_url,
      "s3cret".into(),
      port,
      tx,
      Duration::from_secs(10),
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;

    let http = reqwest::Client::builder()
      .redirect(reqwest::redirect::Policy::none())
      .build()
      .unwrap();
    let base = format!("http://127.0.0.1:{port}");

    // DNS rebinding: foreign Host header is rejected
    let res = http
      .get(format!("{base}/"))
      .header("host", "evil.example")
      .send()
      .await
      .unwrap();
    assert_eq!(res.status(), 403);

    // wrong state is rejected and does NOT shut the server down
    let res = http
      .get(format!("{base}/callback?code=x&state=wrong"))
      .send()
      .await
      .unwrap();
    assert_eq!(res.status(), 400);
    let res = http
      .get(format!("{base}/callback?code=x"))
      .send()
      .await
      .unwrap();
    assert_eq!(res.status(), 400);

    // root still redirects to the authorize url
    let res = http.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(res.status(), 307);

    // valid callback delivers the code and stops the server
    let res = http
      .get(format!("{base}/callback?code=good&state=s3cret"))
      .send()
      .await
      .unwrap();
    assert_eq!(res.status(), 307);
    let code = rx.recv().await.unwrap().unwrap();
    assert_eq!(code.secret(), "good");

    tokio::time::timeout(Duration::from_secs(5), server)
      .await
      .expect("server should shut down after a valid callback")
      .unwrap()
      .unwrap();
  }

  #[tokio::test(flavor = "multi_thread")]
  async fn callback_server_times_out() {
    let (tx, _rx) = mpsc::channel::<CallbackResult>(1);
    let url = Url::parse("https://auth.example/").unwrap();
    let res = tokio::time::timeout(
      Duration::from_secs(5),
      run_local_oauth_server(url, "s".into(), 18086, tx, Duration::from_millis(200)),
    )
    .await;
    assert!(res.is_ok(), "server must stop on its own after the timeout");
  }

  #[test]
  fn constant_time_eq_works() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"abcd"));
    assert!(!constant_time_eq(b"", b"a"));
  }
}
