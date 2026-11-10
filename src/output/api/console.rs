// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The web console: static files the REST API listener serves under
//! `/console/` when `--api-console` (or `[api] console = true`) is given.
//!
//! # What it is
//!
//! An HTML page, one style sheet and two scripts, compiled into the binary.
//! The page is a client of the `/v1/` routes: the operator pastes the bearer
//! token the API already requires and the browser sends it on each request.
//! There is no build step, no framework and nothing fetched from another
//! origin.
//!
//! # What it is not
//!
//! It is not a second listener and it holds no authority. The routes are
//! added to the API router itself, so the `Host` allowlist, TLS and
//! client-certificate settings, the routable-bind refusal, the in-flight cap
//! and the request hardening middleware apply to them unchanged.
//!
//! # Why the files are served before authentication
//!
//! A browser navigation cannot carry an `Authorization` header, so a page
//! behind the bearer check could never be opened. The files hold no captured
//! data and are the same bytes in every copy of the release, so serving them
//! discloses nothing a download of the binary does not. Every byte of capture
//! data the page shows comes from a `/v1/` request that passes the token
//! check. The files are still charged to the per-IP rate limiter, as every
//! request to this listener is except `/health`.
//!
//! # Response headers
//!
//! Every response under `/console`, the errors included, carries the headers
//! in [`SECURITY_HEADERS`]: a Content-Security-Policy that allows only
//! same-origin scripts, styles and requests and no inline code (OWASP ASVS
//! V3.4), `nosniff`, no referrer and `no-store`.

use std::net::SocketAddr;

use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;

use super::{ApiState, Problem, check_rate_limit};

/// The Content-Security-Policy on every console response.
///
/// `default-src 'none'` refuses every kind of load the later directives do
/// not name. Scripts, styles and requests are allowed from this origin only;
/// no directive allows inline code, `eval` or another origin. The page cannot
/// be framed, cannot change its base URL and cannot submit a form anywhere.
pub(super) const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; \
     style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; \
     form-action 'none'";

/// The headers on every console response, as `(name, value)`.
pub(super) const SECURITY_HEADERS: [(HeaderName, &str); 6] = [
    (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (header::REFERRER_POLICY, "no-referrer"),
    (header::CACHE_CONTROL, "no-store"),
    (header::X_FRAME_OPTIONS, "DENY"),
    (
        HeaderName::from_static("cross-origin-resource-policy"),
        "same-origin",
    ),
];

/// One embedded file: where it is served, its media type and its text.
#[derive(Debug, Clone, Copy)]
pub(super) struct Asset {
    /// The request path that serves it.
    pub(super) path: &'static str,
    /// The `Content-Type` it is served with.
    pub(super) content_type: &'static str,
    /// The file, as compiled in.
    pub(super) body: &'static str,
}

/// The page.
const INDEX: Asset = Asset {
    path: "/console/",
    content_type: "text/html; charset=utf-8",
    body: include_str!("console/index.html"),
};

/// The style sheet.
const STYLE: Asset = Asset {
    path: "/console/console.css",
    content_type: "text/css; charset=utf-8",
    body: include_str!("console/console.css"),
};

/// The functions with no DOM access: request paths, time and error text.
const CORE_SCRIPT: Asset = Asset {
    path: "/console/console-core.js",
    content_type: "text/javascript; charset=utf-8",
    body: include_str!("console/console-core.js"),
};

/// The script that draws the page.
const PAGE_SCRIPT: Asset = Asset {
    path: "/console/console.js",
    content_type: "text/javascript; charset=utf-8",
    body: include_str!("console/console.js"),
};

/// Every file the console serves.
pub(super) const ASSETS: [Asset; 4] = [INDEX, STYLE, CORE_SCRIPT, PAGE_SCRIPT];

/// `router` with the console routes added.
///
/// # Arguments
///
/// * `router` — the API router, before its state is supplied.
pub(super) fn mount(router: Router<ApiState>) -> Router<ApiState> {
    let mut console = Router::new()
        .route("/console", get(redirect))
        .route("/console/{*rest}", get(not_found));
    for asset in ASSETS {
        console =
            console.route(
                asset.path,
                get(
                    move |State(state): State<ApiState>,
                          ConnectInfo(addr): ConnectInfo<SocketAddr>| async move {
                        file(&state, addr, asset)
                    },
                ),
            );
    }
    // A layer covers the routes it is added after, the `405` a route answers
    // to another method included, and none of the API routes.
    router.merge(console.layer(axum::middleware::map_response(with_security_headers)))
}

/// One embedded file, after the request is charged to the rate limiter.
///
/// # Errors
///
/// `503` when the client address is over its request budget.
fn file(
    state: &ApiState,
    addr: SocketAddr,
    asset: Asset,
) -> Result<Response<axum::body::Body>, Problem> {
    check_rate_limit(state, addr.ip())?;
    Ok(([(header::CONTENT_TYPE, asset.content_type)], asset.body).into_response())
}

/// `GET /console`: a redirect to `/console/`, where the page's relative file
/// names resolve. The target is a path, so it holds behind a reverse proxy
/// whatever name the proxy answers by.
async fn redirect(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, Problem> {
    check_rate_limit(&state, addr.ip())?;
    Ok((
        StatusCode::PERMANENT_REDIRECT,
        [(header::LOCATION, INDEX.path)],
    ))
}

/// Any other path under `/console/`: `404`, charged to the rate limiter as a
/// file is. No path segment is ever read as a file name.
async fn not_found(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Problem {
    match check_rate_limit(&state, addr.ip()) {
        Ok(()) => Problem::new(StatusCode::NOT_FOUND),
        Err(refusal) => refusal,
    }
}

/// `response` with every header in [`SECURITY_HEADERS`] set.
async fn with_security_headers(
    mut response: Response<axum::body::Body>,
) -> Response<axum::body::Body> {
    for (name, value) in &SECURITY_HEADERS {
        response
            .headers_mut()
            .insert(name.clone(), HeaderValue::from_static(value));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        body_to_string, make_state, make_state_with_key, test_request, test_request_with_header,
    };
    use super::super::{RateLimiter, build_router, build_router_with_console, with_host_allowlist};
    use super::*;
    use crate::host_allowlist::HostAllowlist;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use parking_lot::Mutex;
    use std::sync::Arc;
    use tower::ServiceExt;

    type TestError = Box<dyn std::error::Error>;

    /// The loopback address the allowlist tests pretend the API is bound to.
    const BOUND: &str = "127.0.0.1:8080";

    /// `GET uri` against a router with the console on and no credentials
    /// configured.
    async fn get_console(uri: &str) -> Result<Response<Body>, TestError> {
        send(build_router_with_console(make_state()), test_request(uri)?).await
    }

    /// One request through `app`.
    async fn send(app: Router, req: Request<Body>) -> Result<Response<Body>, TestError> {
        app.oneshot(req)
            .await
            .map_err(|e| format!("oneshot: {e:?}").into())
    }

    /// `uri` with `method`, from loopback.
    fn request_with_method(method: Method, uri: &str) -> Result<Request<Body>, TestError> {
        let mut req = test_request(uri)?;
        *req.method_mut() = method;
        Ok(req)
    }

    /// The value of response header `name`, or an error naming it.
    fn header_value<'a>(resp: &'a Response<Body>, name: &str) -> Result<&'a str, TestError> {
        Ok(resp
            .headers()
            .get(name)
            .ok_or_else(|| format!("no {name} header"))?
            .to_str()?)
    }

    /// Fails unless `resp` carries every header in [`SECURITY_HEADERS`].
    fn assert_security_headers(resp: &Response<Body>) -> Result<(), TestError> {
        for (name, value) in &SECURITY_HEADERS {
            assert_eq!(header_value(resp, name.as_str())?, *value, "{name}");
        }
        Ok(())
    }

    /// The text of the asset served at `path`.
    fn asset(path: &str) -> Result<&'static str, TestError> {
        Ok(ASSETS
            .iter()
            .find(|a| a.path == path)
            .ok_or_else(|| format!("no asset at {path}"))?
            .body)
    }

    /// The two scripts, joined: a rule about script text holds for both.
    fn scripts() -> Result<String, TestError> {
        Ok(format!(
            "{}\n{}",
            asset("/console/console-core.js")?,
            asset("/console/console.js")?
        ))
    }

    // ── Success ──────────────────────────────────────────────────────────

    /// The page is served as UTF-8 HTML at `/console/`.
    #[tokio::test]
    async fn the_page_is_served_as_html() -> Result<(), TestError> {
        let resp = get_console("/console/").await?;
        assert_eq!(resp.status(), StatusCode::OK, "the page is served");
        assert_eq!(
            header_value(&resp, "content-type")?,
            "text/html; charset=utf-8",
            "the page is HTML in UTF-8"
        );
        let body = body_to_string(resp.into_body()).await?;
        assert!(body.starts_with("<!DOCTYPE html>"), "{:.40}", body);
        Ok(())
    }

    /// The style sheet is served as CSS, so `nosniff` does not block it.
    #[tokio::test]
    async fn the_style_sheet_is_served_as_css() -> Result<(), TestError> {
        let resp = get_console("/console/console.css").await?;
        assert_eq!(resp.status(), StatusCode::OK, "the style sheet is served");
        assert_eq!(
            header_value(&resp, "content-type")?,
            "text/css; charset=utf-8",
            "the style sheet is CSS, or nosniff blocks it"
        );
        Ok(())
    }

    /// Both scripts are served as JavaScript, so `nosniff` does not block
    /// them.
    #[tokio::test]
    async fn the_scripts_are_served_as_javascript() -> Result<(), TestError> {
        for path in ["/console/console.js", "/console/console-core.js"] {
            let resp = get_console(path).await?;
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
            assert_eq!(
                header_value(&resp, "content-type")?,
                "text/javascript; charset=utf-8",
                "{path}"
            );
        }
        Ok(())
    }

    /// Each response body is the embedded file, byte for byte.
    #[tokio::test]
    async fn each_file_is_served_unchanged() -> Result<(), TestError> {
        for a in &ASSETS {
            let resp = get_console(a.path).await?;
            assert_eq!(
                body_to_string(resp.into_body()).await?,
                a.body,
                "{}",
                a.path
            );
        }
        Ok(())
    }

    /// `/console` without the slash redirects to `/console/`, so the page's
    /// relative file names resolve under `/console/`.
    #[tokio::test]
    async fn the_bare_path_redirects_to_the_page() -> Result<(), TestError> {
        let resp = get_console("/console").await?;
        assert_eq!(
            resp.status(),
            StatusCode::PERMANENT_REDIRECT,
            "the bare path redirects"
        );
        assert_eq!(
            header_value(&resp, "location")?,
            "/console/",
            "the redirect target is the page path"
        );
        Ok(())
    }

    /// The files are served without a credential on a server that requires
    /// one: a navigation cannot send an `Authorization` header.
    #[tokio::test]
    async fn the_files_need_no_token() -> Result<(), TestError> {
        for a in &ASSETS {
            let app = build_router_with_console(make_state_with_key("console-test-key"));
            let resp = send(app, test_request(a.path)?).await?;
            assert_eq!(resp.status(), StatusCode::OK, "{}", a.path);
        }
        Ok(())
    }

    /// `HEAD` answers as `GET` does, with the same headers.
    #[tokio::test]
    async fn head_answers_with_the_same_headers() -> Result<(), TestError> {
        let app = build_router_with_console(make_state());
        let resp = send(app, request_with_method(Method::HEAD, "/console/")?).await?;
        assert_eq!(resp.status(), StatusCode::OK, "HEAD is answered as GET is");
        assert_security_headers(&resp)
    }

    /// Every file is served with the whole header set.
    #[tokio::test]
    async fn every_file_carries_the_security_headers() -> Result<(), TestError> {
        for a in &ASSETS {
            assert_security_headers(&get_console(a.path).await?)?;
        }
        Ok(())
    }

    /// The policy is the one the design names, directive for directive.
    #[tokio::test]
    async fn the_policy_names_each_directive() -> Result<(), TestError> {
        let resp = get_console("/console/").await?;
        let policy = header_value(&resp, "content-security-policy")?;
        let directives: Vec<&str> = policy.split(';').map(str::trim).collect();
        assert_eq!(
            directives,
            [
                "default-src 'none'",
                "script-src 'self'",
                "style-src 'self'",
                "connect-src 'self'",
                "frame-ancestors 'none'",
                "base-uri 'none'",
                "form-action 'none'",
            ],
            "the policy is the seven directives, in this order"
        );
        Ok(())
    }

    /// A query string does not change which file is served.
    #[tokio::test]
    async fn a_query_string_still_serves_the_page() -> Result<(), TestError> {
        let resp = get_console("/console/?view=list").await?;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a query string does not hide the page"
        );
        Ok(())
    }

    /// The page is served to a `Host` the allowlist accepts.
    #[tokio::test]
    async fn an_allowed_host_gets_the_page() -> Result<(), TestError> {
        let hosts = HostAllowlist::new(BOUND.parse()?, &[]);
        let app = with_host_allowlist(build_router_with_console(make_state()), hosts);
        let req = test_request_with_header("/console/", "host", "localhost:8080")?;
        assert_eq!(
            send(app, req).await?.status(),
            StatusCode::OK,
            "a loopback name is on the allowlist"
        );
        Ok(())
    }

    /// A name added with `--api-allowed-host` gets the page, as behind a
    /// reverse proxy.
    #[tokio::test]
    async fn a_host_added_to_the_allowlist_gets_the_page() -> Result<(), TestError> {
        let hosts = HostAllowlist::new(BOUND.parse()?, &["sipnab.example.com".to_string()]);
        let app = with_host_allowlist(build_router_with_console(make_state()), hosts);
        let req = test_request_with_header("/console/", "host", "sipnab.example.com")?;
        assert_eq!(
            send(app, req).await?.status(),
            StatusCode::OK,
            "the added name is on the allowlist"
        );
        Ok(())
    }

    /// Turning the console on leaves the API routes in place.
    #[tokio::test]
    async fn the_api_still_answers_with_the_console_on() -> Result<(), TestError> {
        let resp = get_console("/v1/dialogs/tail").await?;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the API route answers with the console on"
        );
        Ok(())
    }

    // ── Failure ──────────────────────────────────────────────────────────

    /// Without the flag no console path exists.
    #[tokio::test]
    async fn the_console_is_off_by_default() -> Result<(), TestError> {
        for path in ["/console", "/console/"] {
            let resp = send(build_router(make_state()), test_request(path)?).await?;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
        }
        Ok(())
    }

    /// Without the flag the files are not served either.
    #[tokio::test]
    async fn the_files_are_off_by_default() -> Result<(), TestError> {
        for a in &ASSETS {
            let resp = send(build_router(make_state()), test_request(a.path)?).await?;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{}", a.path);
        }
        Ok(())
    }

    /// The server configuration leaves the console off unless told.
    #[test]
    fn the_server_configuration_defaults_to_off() {
        assert!(
            !super::super::ApiServerConfig::default().console,
            "the console is off unless asked for"
        );
    }

    /// A file name the console does not have is `404`.
    #[tokio::test]
    async fn an_unknown_file_is_not_found() -> Result<(), TestError> {
        let resp = get_console("/console/missing.js").await?;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "no such file under /console/"
        );
        Ok(())
    }

    /// A path that tries to climb out of `/console/` reads no file.
    #[tokio::test]
    async fn a_traversal_path_is_not_found() -> Result<(), TestError> {
        for path in [
            "/console/..%2F..%2Fetc%2Fpasswd",
            "/console/%2e%2e/Cargo.toml",
            "/console/sub/console.js",
        ] {
            let resp = get_console(path).await?;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
        }
        Ok(())
    }

    /// The page takes no writes.
    #[tokio::test]
    async fn a_post_to_the_page_is_refused() -> Result<(), TestError> {
        let app = build_router_with_console(make_state());
        let resp = send(app, request_with_method(Method::POST, "/console/")?).await?;
        assert_eq!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "the page takes GET and HEAD only"
        );
        Ok(())
    }

    /// Nor does a file.
    #[tokio::test]
    async fn a_put_to_a_script_is_refused() -> Result<(), TestError> {
        let app = build_router_with_console(make_state());
        let req = request_with_method(Method::PUT, "/console/console.js")?;
        assert_eq!(
            send(app, req).await?.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "a script takes GET and HEAD only"
        );
        Ok(())
    }

    /// The files are charged to the per-IP rate limiter: past the budget the
    /// answer is the API's `503`.
    #[tokio::test]
    async fn a_file_request_over_the_rate_limit_is_refused() -> Result<(), TestError> {
        let mut state = make_state();
        state.rate_limiter = Arc::new(Mutex::new(RateLimiter::new(1, 1024)));
        let app = build_router_with_console(state);
        let first = send(app.clone(), test_request("/console/")?).await?;
        assert_eq!(
            first.status(),
            StatusCode::OK,
            "the first request is inside the budget"
        );
        let second = send(app, test_request("/console/console.css")?).await?;
        assert_eq!(
            second.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "the second request is over the budget"
        );
        Ok(())
    }

    /// A `Host` the allowlist does not hold is refused before the page.
    #[tokio::test]
    async fn a_foreign_host_does_not_get_the_page() -> Result<(), TestError> {
        let hosts = HostAllowlist::new(BOUND.parse()?, &[]);
        let app = with_host_allowlist(build_router_with_console(make_state()), hosts);
        let req = test_request_with_header("/console/", "host", "rebind.example.com")?;
        assert_eq!(
            send(app, req).await?.status(),
            StatusCode::FORBIDDEN,
            "the page is behind the Host allowlist"
        );
        Ok(())
    }

    /// Nor does it get a script.
    #[tokio::test]
    async fn a_foreign_host_does_not_get_a_script() -> Result<(), TestError> {
        let hosts = HostAllowlist::new(BOUND.parse()?, &[]);
        let app = with_host_allowlist(build_router_with_console(make_state()), hosts);
        let req = test_request_with_header("/console/console.js", "host", "rebind.example.com")?;
        assert_eq!(
            send(app, req).await?.status(),
            StatusCode::FORBIDDEN,
            "a script is behind the Host allowlist"
        );
        Ok(())
    }

    /// A request with no `Host` is refused, as on `/v1/`.
    #[tokio::test]
    async fn a_missing_host_does_not_get_the_page() -> Result<(), TestError> {
        let hosts = HostAllowlist::new(BOUND.parse()?, &[]);
        let app = with_host_allowlist(build_router_with_console(make_state()), hosts);
        let resp = send(app, test_request("/console/")?).await?;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a request without a Host is refused before the page"
        );
        Ok(())
    }

    /// The console adds no way around the token: an API route with the
    /// console on and no credential is still `401`.
    #[tokio::test]
    async fn the_api_still_requires_the_token() -> Result<(), TestError> {
        let app = build_router_with_console(make_state_with_key("console-test-key"));
        let resp = send(app, test_request("/v1/dialogs/tail")?).await?;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "the API route needs the token with the console on"
        );
        Ok(())
    }

    /// A wrong token is refused on an API route with the console on.
    #[tokio::test]
    async fn the_api_still_refuses_a_wrong_token() -> Result<(), TestError> {
        let app = build_router_with_console(make_state_with_key("console-test-key"));
        let req = test_request_with_header("/v1/runtime", "authorization", "Bearer wrong")?;
        assert_eq!(
            send(app, req).await?.status(),
            StatusCode::UNAUTHORIZED,
            "a wrong token is refused with the console on"
        );
        Ok(())
    }

    /// The password-in-URL refusal applies to console paths as to `/v1/`.
    #[tokio::test]
    async fn a_password_in_the_url_is_refused() -> Result<(), TestError> {
        let resp = get_console("/console/?password=hunter2").await?;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a password-like query parameter is refused on a console path"
        );
        Ok(())
    }

    // ── Edge ─────────────────────────────────────────────────────────────

    /// A `404` under `/console/` carries the headers too.
    #[tokio::test]
    async fn a_not_found_carries_the_security_headers() -> Result<(), TestError> {
        let resp = get_console("/console/missing.js").await?;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "no such file under /console/"
        );
        assert_security_headers(&resp)
    }

    /// So does a `405`.
    #[tokio::test]
    async fn a_refused_method_carries_the_security_headers() -> Result<(), TestError> {
        let app = build_router_with_console(make_state());
        let resp = send(app, request_with_method(Method::POST, "/console/")?).await?;
        assert_eq!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "the page takes GET and HEAD only"
        );
        assert_security_headers(&resp)
    }

    /// So does the redirect.
    #[tokio::test]
    async fn the_redirect_carries_the_security_headers() -> Result<(), TestError> {
        assert_security_headers(&get_console("/console").await?)
    }

    /// So does the rate limiter's `503`.
    #[tokio::test]
    async fn a_rate_limited_answer_carries_the_security_headers() -> Result<(), TestError> {
        let mut state = make_state();
        state.rate_limiter = Arc::new(Mutex::new(RateLimiter::new(1, 1024)));
        let app = build_router_with_console(state);
        send(app.clone(), test_request("/console/")?).await?;
        let resp = send(app, test_request("/console/")?).await?;
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "the second request is over the budget"
        );
        assert_security_headers(&resp)
    }

    /// The console headers stay off the API routes: `no-store` and the page
    /// policy are statements about console responses.
    #[tokio::test]
    async fn the_api_routes_do_not_take_the_page_policy() -> Result<(), TestError> {
        let resp = get_console("/v1/dialogs/tail").await?;
        assert!(
            resp.headers().get("content-security-policy").is_none(),
            "the page policy is for console responses only"
        );
        Ok(())
    }

    /// The policy allows no inline code, no `eval`, no wildcard and no other
    /// origin.
    #[test]
    fn the_policy_allows_nothing_inline_or_foreign() {
        for banned in [
            "unsafe-inline",
            "unsafe-eval",
            "*",
            "http:",
            "https:",
            "data:",
        ] {
            assert!(!CONTENT_SECURITY_POLICY.contains(banned), "{banned}");
        }
    }

    /// The page has no inline script, style element, style attribute or
    /// event-handler attribute: the policy would block each, and each is a
    /// place captured text could run.
    #[test]
    fn the_page_has_no_inline_code() -> Result<(), TestError> {
        let page = asset("/console/")?.to_ascii_lowercase();
        assert!(!page.contains("<style"), "style element");
        assert!(!page.contains(" style="), "style attribute");
        assert!(!page.contains("javascript:"), "javascript: URL");
        let handler = regex::Regex::new(r#"\son[a-z]+\s*="#)?;
        assert!(!handler.is_match(&page), "event-handler attribute");
        let script = regex::Regex::new(r"<script\b([^>]*)>([^<]*)</script>")?;
        let mut seen = 0;
        for cap in script.captures_iter(&page) {
            seen += 1;
            assert!(cap[1].contains("src="), "script without src: {}", &cap[0]);
            assert!(cap[2].trim().is_empty(), "inline script: {}", &cap[0]);
        }
        assert_eq!(
            seen,
            page.matches("<script").count(),
            "every script element was checked"
        );
        assert!(seen > 0, "the page loads no script");
        Ok(())
    }

    /// Every file the page loads is one the console serves, by a relative
    /// name: nothing comes from another origin.
    #[test]
    fn the_page_loads_only_its_own_files() -> Result<(), TestError> {
        let page = asset("/console/")?;
        let reference = regex::Regex::new(r#"(?:src|href)="([^"]*)""#)?;
        let mut seen = 0;
        for cap in reference.captures_iter(page) {
            // A fragment names a place in this page, not a file.
            if cap[1].starts_with('#') {
                continue;
            }
            seen += 1;
            let served = format!("/console/{}", &cap[1]);
            assert!(
                ASSETS.iter().any(|a| a.path == served),
                "{} is not a console file",
                &cap[1]
            );
        }
        assert!(seen >= 2, "the page loads its style sheet and its script");
        Ok(())
    }

    /// No file names another origin: no CDN, no font or analytics host.
    #[test]
    fn no_file_names_another_origin() {
        for a in &ASSETS {
            for scheme in ["http://", "https://", "//cdn", "ws://", "wss://"] {
                assert!(!a.body.contains(scheme), "{} holds {scheme}", a.path);
            }
        }
    }

    /// The scripts never build markup from a string. Captured SIP text is
    /// attacker-controlled, and `textContent` is the only way it is written.
    #[test]
    fn the_scripts_never_write_markup() -> Result<(), TestError> {
        let scripts = scripts()?;
        for sink in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "DOMParser",
            "createContextualFragment",
            "eval(",
            "Function(",
            "setAttribute(",
            ".href",
            ".srcdoc",
            ".style",
        ] {
            assert!(!scripts.contains(sink), "{sink}");
        }
        assert!(scripts.contains("textContent"), "values go in as text");
        Ok(())
    }

    /// The scripts keep the token in memory only: no storage, no cookie and
    /// no URL.
    #[test]
    fn the_scripts_never_store_the_token() -> Result<(), TestError> {
        let scripts = scripts()?;
        for store in [
            "localStorage",
            "sessionStorage",
            "indexedDB",
            "document.cookie",
            "pushState",
            "replaceState",
            "location.hash",
            "location.search",
            "console.log",
            "console.debug",
        ] {
            assert!(!scripts.contains(store), "{store}");
        }
        Ok(())
    }

    /// The token field is a labeled password field the browser is told not
    /// to remember.
    #[test]
    fn the_token_field_is_a_labeled_password_field() -> Result<(), TestError> {
        let page = asset("/console/")?;
        let input = regex::Regex::new(r"<input\b[^>]*>")?
            .find(page)
            .ok_or("no input")?
            .as_str();
        assert!(input.contains(r#"type="password""#), "{input}");
        assert!(input.contains(r#"autocomplete="off""#), "{input}");
        assert!(input.contains(r#"id="token""#), "{input}");
        assert!(page.contains(r#"<label for="token""#), "no label for it");
        Ok(())
    }

    /// The page has the landmarks and the one top-level heading a screen
    /// reader navigates by, and names its language.
    #[test]
    fn the_page_has_landmarks_and_one_heading() -> Result<(), TestError> {
        let page = asset("/console/")?;
        assert!(page.contains(r#"<html lang="en""#), "lang");
        for landmark in ["<header", "<main", "<footer"] {
            assert_eq!(page.matches(landmark).count(), 1, "{landmark}");
        }
        assert_eq!(page.matches("<h1").count(), 1, "h1");
        assert!(page.contains(r#"aria-live="polite""#), "status region");
        assert!(page.contains(r#"role="alert""#), "error region");
        assert!(page.contains(r#"name="viewport""#), "viewport");
        Ok(())
    }

    /// Every table header cell states its scope, and every table has a
    /// caption.
    #[test]
    fn every_table_has_a_caption_and_scoped_headers() -> Result<(), TestError> {
        let page = asset("/console/")?;
        let tables = page.matches("<table").count();
        assert!(tables >= 2, "the list and the legs are tables");
        assert_eq!(
            page.matches("<caption").count(),
            tables,
            "every table has a caption"
        );
        let th = regex::Regex::new(r"<th\b[^>]*>")?;
        for cell in th.find_iter(page) {
            assert!(cell.as_str().contains("scope="), "{}", cell.as_str());
        }
        Ok(())
    }

    /// The style sheet has a dark scheme, honors reduced motion and draws a
    /// focus ring.
    #[test]
    fn the_style_sheet_covers_dark_motion_and_focus() -> Result<(), TestError> {
        let css = asset("/console/console.css")?;
        assert!(css.contains("prefers-color-scheme: dark"), "dark scheme");
        assert!(css.contains("prefers-reduced-motion: reduce"), "motion");
        assert!(css.contains(":focus-visible"), "focus ring");
        assert!(!css.contains("outline: none"), "focus ring removed");
        assert!(!css.contains("outline:none"), "focus ring removed");
        assert!(!css.contains("@import"), "a style sheet from elsewhere");
        assert!(!css.contains("url("), "a load the policy would refuse");
        Ok(())
    }

    /// The browser tests answer the console files themselves, with a copy of
    /// the server's headers. Each value there is the one the server sends, so
    /// a script the real policy refuses is refused in those tests too.
    #[test]
    fn the_browser_tests_use_the_server_headers() -> Result<(), TestError> {
        let spec = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("e2e/tests/console.spec.js"),
        )?;
        assert!(
            spec.contains(&format!("\"{CONTENT_SECURITY_POLICY}\"")),
            "e2e/tests/console.spec.js does not carry the server's policy"
        );
        for (name, value) in &SECURITY_HEADERS[1..] {
            assert!(
                spec.contains(&format!("'{name}': '{value}'")),
                "e2e/tests/console.spec.js does not carry {name}: {value}"
            );
        }
        Ok(())
    }

    /// The files together stay small: they ride in every binary.
    #[test]
    fn the_files_stay_under_their_size_budget() {
        let total: usize = ASSETS.iter().map(|a| a.body.len()).sum();
        assert!(total > 0, "the files are empty");
        assert!(total <= 64 * 1024, "{total} bytes of console files");
    }
}
