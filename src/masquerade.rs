//! Decoy web responses for requests that are not authenticated tunnel sessions.
//!
//! A MASQUE proxy that answers an unauthenticated probe with `405 Method Not
//! Allowed` or `407 Proxy Authentication Required` has told the prober exactly
//! what it is. Censors that active-probe suspected proxies — so far only the
//! GFW, at scale — need nothing more than that to blocklist the address, and
//! unlike SNI-triggered filtering an IP blocklisting does not expire.
//!
//! So every request that does not become a tunnel session is answered from
//! here instead, as an ordinary web server would. The two rejection paths that
//! matter — "this is not an extended CONNECT" and "your token is wrong" — must
//! be indistinguishable, which is why both funnel through [`Masquerade::respond`]
//! rather than returning statuses of their own.
//!
//! This mirrors what Trojan (fall back to a real nginx), Hysteria 2
//! (`masquerade:` block), and VLESS+REALITY (borrow a real site's handshake)
//! do. It only covers active probing; it does nothing about traffic analysis.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bytes::Bytes;
use h3::server::RequestStream;

use crate::common::percent_decode;

/// Response stream type used by the H3 server for a single request.
pub type H3Stream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Largest decoy file served from `--masquerade-dir`. Anything bigger is
/// treated as absent: the whole body is buffered in memory, and a decoy site
/// has no business shipping large assets over this path.
const MAX_FILE_SIZE: u64 = 8 * 1024 * 1024;

/// What to serve to requests that are not authenticated tunnel sessions.
#[derive(Clone, Debug)]
pub enum Masquerade {
    /// Serve files from a directory, `index.html` for directory paths.
    Dir(PathBuf),
    /// Redirect every request to an absolute URL.
    Redirect(String),
    /// Serve a built-in placeholder page at `/` and 404 elsewhere.
    Builtin,
}

impl Masquerade {
    /// Build from the mutually exclusive CLI options.
    pub fn from_options(
        dir: Option<String>,
        url: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match (dir, url) {
            (Some(_), Some(_)) => {
                Err("--masquerade-dir and --masquerade-url are mutually exclusive".into())
            }
            (Some(d), None) => {
                let path = PathBuf::from(&d);
                if !path.is_dir() {
                    return Err(format!("--masquerade-dir {d} is not a directory").into());
                }
                Ok(Self::Dir(path))
            }
            (None, Some(u)) => {
                if !u.starts_with("http://") && !u.starts_with("https://") {
                    return Err("--masquerade-url must be an absolute http(s) URL".into());
                }
                Ok(Self::Redirect(u))
            }
            (None, None) => Ok(Self::Builtin),
        }
    }

    /// Answer `req` as a plain web server would, and close the stream.
    ///
    /// Errors are swallowed: the peer here is an unauthenticated stranger, and
    /// a failed write on a decoy response is not worth surfacing.
    pub async fn respond(
        &self,
        req: &http::Request<()>,
        stream: &mut H3Stream,
        server_header: Option<&str>,
    ) {
        let (status, content_type, body, location) = self.resolve(req.uri().path());

        // A HEAD gets the headers of the equivalent GET with no body, so
        // content-length still describes what a GET would have returned.
        let is_head = req.method() == http::Method::HEAD;

        let mut builder = http::Response::builder()
            .status(status)
            .header("date", httpdate::fmt_http_date(SystemTime::now()))
            .header("content-length", body.len().to_string());
        if let Some(loc) = location {
            builder = builder.header("location", loc);
        } else {
            builder = builder.header("content-type", content_type);
        }
        if let Some(value) = server_header {
            builder = builder.header("server", value);
        }

        let resp = match builder.body(()) {
            Ok(r) => r,
            Err(e) => {
                log::error!("[server] decoy response build failed: {e}");
                return;
            }
        };
        if stream.send_response(resp).await.is_err() {
            return;
        }
        if !is_head && !body.is_empty() {
            let _ = stream.send_data(body).await;
        }
        let _ = stream.finish().await;
    }

    /// Pick the status, content type, body, and optional redirect target for a
    /// request path. Split out from `respond` so it is testable without a
    /// live H3 stream.
    fn resolve(&self, path: &str) -> (u16, &'static str, Bytes, Option<String>) {
        match self {
            Self::Redirect(url) => (302, "text/html; charset=utf-8", Bytes::new(), Some(url.clone())),
            Self::Dir(root) => match safe_join(root, path).and_then(|p| read_capped(&p)) {
                Some((body, content_type)) => (200, content_type, body, None),
                None => not_found(),
            },
            Self::Builtin => {
                if path == "/" {
                    (
                        200,
                        "text/html; charset=utf-8",
                        Bytes::from_static(INDEX_PAGE),
                        None,
                    )
                } else {
                    not_found()
                }
            }
        }
    }
}

fn not_found() -> (u16, &'static str, Bytes, Option<String>) {
    (
        404,
        "text/html; charset=utf-8",
        Bytes::from_static(NOT_FOUND_PAGE),
        None,
    )
}

/// Resolve a URL path against the decoy root, refusing anything that could
/// escape it. Percent-decoding happens per segment and the decoded result is
/// re-checked, so `%2e%2e%2f` and `%2f` cannot smuggle in a separator. The
/// final containment check is done on the canonicalized path, which also
/// catches symlinks pointing outside the root.
fn safe_join(root: &Path, url_path: &str) -> Option<PathBuf> {
    let mut out = root.to_path_buf();
    for segment in url_path.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        let decoded = percent_decode(segment);
        if decoded.is_empty()
            || decoded == "."
            || decoded == ".."
            || decoded.contains('/')
            || decoded.contains('\\')
            || decoded.contains('\0')
        {
            return None;
        }
        out.push(decoded);
    }
    if out.is_dir() {
        out.push("index.html");
    }

    let root = root.canonicalize().ok()?;
    let resolved = out.canonicalize().ok()?;
    resolved.starts_with(&root).then_some(resolved)
}

/// Read a decoy file, refusing anything that is not a regular file or is over
/// [`MAX_FILE_SIZE`]. Returns the body and a content type guessed from the
/// extension.
fn read_capped(path: &Path) -> Option<(Bytes, &'static str)> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_SIZE {
        return None;
    }
    let body = std::fs::read(path).ok()?;
    Some((Bytes::from(body), content_type_for(path)))
}

fn content_type_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("avif") => "image/avif",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// Placeholder served at `/` when no decoy content is configured. Deliberately
/// generic: it should read like an unremarkable parked domain, and must not
/// name this product.
const INDEX_PAGE: &[u8] = br#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;max-width:40rem;margin:6rem auto;padding:0 1.5rem;line-height:1.6;color:#2e3440}
h1{font-size:1.5rem;font-weight:600;margin:0 0 .75rem}
p{margin:0;color:#4c566a}
@media(prefers-color-scheme:dark){body{background:#22262e;color:#e5e9f0}p{color:#aeb8cc}}
</style>
</head>
<body>
<h1>Welcome</h1>
<p>This server is up and running. There is nothing to see here yet.</p>
</body>
</html>
"#;

const NOT_FOUND_PAGE: &[u8] = br#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>404 Not Found</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;max-width:40rem;margin:6rem auto;padding:0 1.5rem;line-height:1.6;color:#2e3440}
h1{font-size:1.5rem;font-weight:600;margin:0 0 .75rem}
p{margin:0;color:#4c566a}
@media(prefers-color-scheme:dark){body{background:#22262e;color:#e5e9f0}p{color:#aeb8cc}}
</style>
</head>
<body>
<h1>404 Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("masq-decoy-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn builtin_serves_index_at_root_and_404_elsewhere() {
        let m = Masquerade::Builtin;
        let (status, ct, body, loc) = m.resolve("/");
        assert_eq!(status, 200);
        assert_eq!(ct, "text/html; charset=utf-8");
        assert!(!body.is_empty());
        assert!(loc.is_none());

        assert_eq!(m.resolve("/anything").0, 404);
        // The tunnel's own path must look as absent as any other.
        assert_eq!(m.resolve("/.well-known/masque/ip/%2A/%2A/").0, 404);
    }

    #[test]
    fn builtin_pages_never_name_the_product() {
        for page in [INDEX_PAGE, NOT_FOUND_PAGE] {
            let text = std::str::from_utf8(page).unwrap().to_ascii_lowercase();
            assert!(!text.contains("masque"));
            assert!(!text.contains("tunnel"));
            assert!(!text.contains("proxy"));
        }
    }

    #[test]
    fn a_failed_auth_and_an_unknown_path_are_byte_identical() {
        // The whole point of the decoy: a prober sending a bogus token and a
        // prober fetching a random URL must not be able to tell the responses
        // apart. Both reach `respond` with paths that miss, so compare what
        // `resolve` produces for each.
        let m = Masquerade::Builtin;
        let auth_reject = m.resolve("/.well-known/masque/ip/%2A/%2A/");
        let random_probe = m.resolve("/wp-login.php");
        assert_eq!(auth_reject.0, random_probe.0);
        assert_eq!(auth_reject.1, random_probe.1);
        assert_eq!(auth_reject.2, random_probe.2);
    }

    #[test]
    fn redirect_sends_302_with_location_for_every_path() {
        let m = Masquerade::Redirect("https://example.com/".into());
        for path in ["/", "/x", "/.well-known/masque/ip/%2A/%2A/"] {
            let (status, _, body, loc) = m.resolve(path);
            assert_eq!(status, 302);
            assert!(body.is_empty());
            assert_eq!(loc.as_deref(), Some("https://example.com/"));
        }
    }

    #[test]
    fn dir_serves_files_and_directory_index() {
        let dir = tmpdir("serve");
        std::fs::write(dir.join("index.html"), "<h1>hi</h1>").unwrap();
        std::fs::write(dir.join("style.css"), "body{}").unwrap();
        let m = Masquerade::Dir(dir.clone());

        let (status, ct, body, _) = m.resolve("/");
        assert_eq!(status, 200);
        assert_eq!(ct, "text/html; charset=utf-8");
        assert_eq!(&body[..], b"<h1>hi</h1>");

        let (status, ct, _, _) = m.resolve("/style.css");
        assert_eq!(status, 200);
        assert_eq!(ct, "text/css; charset=utf-8");

        assert_eq!(m.resolve("/missing.html").0, 404);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dir_refuses_traversal_in_every_encoding() {
        let dir = tmpdir("traversal");
        std::fs::write(dir.join("index.html"), "ok").unwrap();
        let secret = dir.parent().unwrap().join("masq-decoy-secret.txt");
        std::fs::write(&secret, "SECRET").unwrap();
        let m = Masquerade::Dir(dir.clone());

        for path in [
            "/../masq-decoy-secret.txt",
            "/%2e%2e/masq-decoy-secret.txt",
            "/%2E%2E%2Fmasq-decoy-secret.txt",
            "/a/../../masq-decoy-secret.txt",
            "/..%2Fmasq-decoy-secret.txt",
            "/etc/passwd",
        ] {
            let (status, _, body, _) = m.resolve(path);
            assert_eq!(status, 404, "path {path} must not resolve");
            assert!(!body.windows(6).any(|w| w == b"SECRET"));
        }

        let _ = std::fs::remove_file(&secret);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dir_refuses_oversized_files() {
        let dir = tmpdir("oversize");
        std::fs::write(dir.join("big.bin"), vec![0u8; (MAX_FILE_SIZE + 1) as usize]).unwrap();
        let m = Masquerade::Dir(dir.clone());
        assert_eq!(m.resolve("/big.bin").0, 404);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn from_options_rejects_conflicting_and_invalid_input() {
        assert!(Masquerade::from_options(Some("/tmp".into()), Some("https://e.com".into())).is_err());
        assert!(Masquerade::from_options(None, Some("e.com".into())).is_err());
        assert!(Masquerade::from_options(Some("/nonexistent-xyz".into()), None).is_err());
        assert!(matches!(
            Masquerade::from_options(None, None).unwrap(),
            Masquerade::Builtin
        ));
    }
}
