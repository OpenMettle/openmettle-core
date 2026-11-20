//! HTTP adapter for the native service, mounted by the API from a `native` profile (ADR 0029).
//! TLS and authority filtering belong to ingress.
use super::*;
use crate::browser_auth::router::{self, Budget, Rate};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::Request,
    routing::any,
};
use serde::Deserialize;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    grant_type: String,
    iss: String,
    client_id: String,
    redirect_uri: String,
    code: String,
    code_verifier: String,
}

fn single(request: &Parts, name: header::HeaderName) -> Option<&str> {
    let mut values = request.headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

impl NativeAuth {
    /// [`Self::router_shared`] for a service the caller does not otherwise keep.
    pub fn router(self, rate: Rate) -> Result<Router, Error> {
        Arc::new(self).router_shared(rate)
    }
    /// Build one router per process over this shared service, which the caller may keep, for
    /// example to validate bearers elsewhere (ADR 0029). Each route and accepted method has its
    /// own bucket at the supplied rate, so the authorization preview `GET` and the starting
    /// `POST` spend separately. Any other method is refused before it takes a slot or spends
    /// a unit. Request slots number the configured in-flight cap.
    pub fn router_shared(self: &Arc<Self>, rate: Rate) -> Result<Router, Error> {
        let bodies = Arc::new(Semaphore::new(self.in_flight));
        let auth = self.clone();
        let mut router = Router::new();
        let callback = auth.callback[auth.issuer.len()..].to_owned();
        for (path, methods) in [
            (START, &[Method::GET, Method::POST][..]),
            (&callback, &[Method::GET]),
            (TOKEN, &[Method::POST]),
            (SESSION, &[Method::GET]),
            (LOGOUT, &[Method::POST]),
        ] {
            let mut budgets = Vec::with_capacity(methods.len());
            for method in methods {
                let budget = Budget::new(rate, Instant::now()).map_err(|_| Error::Configuration)?;
                budgets.push((method.clone(), budget));
            }
            let budgets = Arc::new(budgets);
            let auth = auth.clone();
            let bodies = bodies.clone();
            router = router.route(
                path,
                any(move |request: Request| {
                    let auth = auth.clone();
                    let budgets = budgets.clone();
                    let bodies = bodies.clone();
                    async move {
                        let (parts, body) = request.into_parts();
                        if router::target_bytes(&parts.uri) > router::MAX_TARGET_BYTES
                            || parts.headers.len() > router::MAX_HEADER_FIELDS
                            || router::header_bytes(&parts.headers) > router::MAX_HEADER_BYTES
                        {
                            return refused().map(Body::from);
                        }
                        let Some((_, budget)) =
                            budgets.iter().find(|(method, _)| *method == parts.method)
                        else {
                            return refused().map(Body::from);
                        };
                        // The confirmed start follows the browser initiation body rules
                        // (ADR 0022). Its profile is decided from metadata alone, before a
                        // slot is taken or a unit is spent, and nothing is read here.
                        let form = if parts.uri.path() == START && parts.method == Method::POST {
                            let Some(declared) = router::form_body(&parts.headers, &body) else {
                                return handoff::respond(
                                    StatusCode::PAYLOAD_TOO_LARGE,
                                    "native sign-in request body not accepted\n",
                                )
                                .map(Body::from);
                            };
                            Some(declared)
                        } else {
                            None
                        };
                        let Ok(_slot) = bodies.try_acquire() else {
                            return handoff::respond(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "native sign-in busy\n",
                            )
                            .map(Body::from);
                        };
                        if !budget.admit(Instant::now()) {
                            return handoff::respond(
                                StatusCode::TOO_MANY_REQUESTS,
                                "native request rate exceeded\n",
                            )
                            .map(Body::from);
                        }
                        auth.dispatch(&parts, body, form).await
                    }
                }),
            );
        }
        Ok(router)
    }

    /// The confirmed start. `declared` is the length of its form, already accepted from
    /// metadata: zero, or at most [`handoff::MAX_FORM_BYTES`]. The form is read here, while
    /// the caller holds the request slot and after its rate unit is spent. The declared
    /// length bounds the read, and the timeout bounds a client that stalls.
    async fn start(&self, parts: &Parts, body: Body, declared: usize) -> Response<&'static str> {
        let form = if declared == 0 {
            Bytes::new()
        } else {
            let read = to_bytes(body, handoff::MAX_FORM_BYTES);
            match tokio::time::timeout(router::FORM_READ_TIMEOUT, read).await {
                Ok(Ok(form)) if form.len() == declared => form,
                _ => {
                    return handoff::respond(
                        StatusCode::REQUEST_TIMEOUT,
                        "native sign-in request body not received\n",
                    );
                }
            }
        };
        self.authorize(parts, &form).await
    }

    /// `form` is the declared form length of a confirmed start, and `None` on every other
    /// route and method.
    async fn dispatch(&self, parts: &Parts, body: Body, form: Option<usize>) -> Response<Body> {
        let path = parts.uri.path();
        if let Some(declared) = form {
            return self.start(parts, body, declared).await.map(Body::from);
        }
        if path != TOKEN && !router::empty_body(&parts.headers, &body) {
            return refused().map(Body::from);
        }
        if path == START {
            return self.authorize(parts, &[]).await.map(Body::from);
        }
        if path == &self.callback[self.issuer.len()..] {
            return self.callback(parts).await.map(Body::from);
        }
        // These endpoints accept only app back-channel requests. Browser cookies never select a credential.
        if parts.uri.query().is_some()
            || parts.headers.contains_key(header::COOKIE)
            || parts.headers.contains_key(header::ORIGIN)
        {
            return refused().map(Body::from);
        }
        if path == TOKEN {
            if parts.method != Method::POST
                || parts.headers.contains_key(header::AUTHORIZATION)
                || single(parts, header::CONTENT_TYPE) != Some("application/json")
            {
                return refused().map(Body::from);
            }
            let Ok(Ok(bytes)) =
                tokio::time::timeout(Duration::from_secs(2), to_bytes(body, 8192)).await
            else {
                return refused().map(Body::from);
            };
            // Serde also accepts a positional array for a derived struct. This protocol
            // requires the six named members of one JSON object.
            if !bytes.trim_ascii_start().starts_with(b"{") {
                return refused().map(Body::from);
            }
            let Ok(input) = serde_json::from_slice::<TokenRequest>(&bytes) else {
                return refused().map(Body::from);
            };
            if input.grant_type != "authorization_code" {
                return refused().map(Body::from);
            }
            let result = self
                .redeem(Redemption {
                    issuer: &input.iss,
                    client: &input.client_id,
                    redirect: &input.redirect_uri,
                    code: &input.code,
                    verifier: &input.code_verifier,
                })
                .await;
            let bearer = match result {
                Ok(bearer) => bearer,
                Err(error) => return session_failure(error).map(Body::from),
            };
            let mut response = handoff::respond(StatusCode::OK, "").map(Body::from);
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json"),
            );
            *response.body_mut() = Body::from(
                serde_json::json!({"access_token":bearer.expose(),"token_type":"Bearer"})
                    .to_string(),
            );
            return response;
        }
        let Some(bearer) =
            single(parts, header::AUTHORIZATION).and_then(|v| v.strip_prefix("Bearer "))
        else {
            return refused().map(Body::from);
        };
        let result = match (path, &parts.method) {
            (SESSION, &Method::GET) => self.validate(bearer).await.map(|_| ()),
            (LOGOUT, &Method::POST) => self.logout(bearer).await,
            _ => Err(Error::Rejected),
        };
        match result {
            Ok(()) => handoff::respond(StatusCode::NO_CONTENT, "").map(Body::from),
            Err(error) => session_failure(error).map(Body::from),
        }
    }
}
