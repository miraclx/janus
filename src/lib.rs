use std::fmt::Write;

use http::StatusCode;
use http_content_range::ContentRange;
use worker::*;
use xbytes::ByteSize;

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let upstream_url = env.var("UPSTREAM_URL")?.to_string();
    let mut upstream_url = upstream_url.parse::<Url>()?;

    let incoming_url = req.url()?;

    console_log!(
        "\x1b[34m{}\x1b[39m -> \x1b[36m{}\x1b[39m",
        &incoming_url[..url::Position::BeforePath],
        upstream_url
    );

    console_log!("  \x1b[1m> {}\x1b[0m {}", req.method(), incoming_url.path());

    let Ok(mut upstream_segments) = upstream_url.path_segments_mut() else {
        return Err(format!("invalid upstream url: {upstream_url}").into());
    };

    for segment in incoming_url.path_segments().into_iter().flatten() {
        upstream_segments.push(segment);
    }

    drop(upstream_segments);

    let headers = req.headers().clone();

    headers.set("X-Forwarded-Proto", &incoming_url.scheme())?;
    headers.set(
        "X-Forwarded-Host",
        &incoming_url[url::Position::BeforeHost..url::Position::AfterPort],
    )?;

    let mut init = RequestInit::new();
    init.with_method(req.method()).with_headers(headers);

    if let Some(body) = req.inner().body() {
        init.with_body(Some(body.into()));
    }

    let req = Request::new_with_init(upstream_url.as_ref(), &init)?;

    let res = Fetch::Request(req).send().await?;

    let status = res.status_code();
    let status = StatusCode::from_u16(status)
        .map_err(|_| format!("invalid status code in proxied response: {}", status))?;

    let range = res
        .headers()
        .get("content-range")
        .expect("this is guaranteed to be valid")
        .as_deref()
        .and_then(ContentRange::parse);

    let mut bytes = res
        .headers()
        .get("content-length")
        .expect("this is guaranteed to be valid")
        .and_then(|s| s.parse::<u64>().ok());

    let size = range.and_then(|r| match r {
        ContentRange::Bytes(b) => {
            bytes.get_or_insert(b.complete_length);
            Some((b.first_byte, b.last_byte))
        }
        ContentRange::UnboundBytes(b) => Some((b.first_byte, b.last_byte)),
        ContentRange::Unsatisfied(b) => {
            bytes.get_or_insert(b.complete_length);
            None
        }
    });

    let mut size_str = String::new();

    let size = size.map(|(a, b)| b - a + 1);

    if let Some(size) = size {
        let size = ByteSize::from_bytes(size as _);
        let _ignored = write!(&mut size_str, "{size}");
    }

    if size != bytes
        && let Some(bytes) = bytes
    {
        if size.is_some() {
            size_str.push_str(" / ");
        }

        let bytes = ByteSize::from_bytes(bytes as _);

        let _ignored = write!(size_str, "{bytes}");
    }

    console_log!(
        "  \x1b[1m< {}{}\x1b[22m {}\x1b[0m{}",
        if status.is_success() {
            "\x1b[32m"
        } else {
            "\x1b[33m"
        },
        status.as_u16(),
        status.canonical_reason().unwrap_or("<unknown status code>"),
        (!size_str.is_empty())
            .then(|| format!(" | {size_str}"))
            .unwrap_or_default()
    );

    Ok(res)
}
