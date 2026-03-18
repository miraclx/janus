use http::StatusCode;
use http_content_range::ContentRange;
use worker::wasm_bindgen::JsValue;
use worker::{
    Context, Env, Fetch, Headers, Method, Request, RequestInit, Response, Result, Url, event,
    js_sys, web_sys,
};
use xbytes::{ByteSize, Mode};

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let upstream_url = env.var("UPSTREAM_URL")?.to_string();
    let mut upstream_url = upstream_url.parse::<Url>()?;

    let incoming_url = req.url()?;

    let item = js_sys::Object::new();
    let mut message = String::new();

    let mut log = |mut a: Option<&_>, b: &[(&str, &JsValue)]| {
        for (k, v) in b {
            if a.take_if(|k_| k_ == k).is_some() {
                if !message.is_empty() {
                    message.push_str(" | ");
                }

                message.push_str(&v.as_string().expect("<expected string>"));
            }

            if k.starts_with('.') {
                continue;
            }

            let _ignored = js_sys::Reflect::set(&item, &(*k).into(), v);
        }
    };

    let res = proxy(
        &incoming_url,
        &mut upstream_url,
        req.method(),
        req.headers().clone(),
        req.inner().body(),
        &mut log,
    )
    .await;

    let path_decoded = js_sys::decode_uri(&incoming_url.path())?
        .as_string()
        .expect("must be a string");

    let path_args = &[
        (".path", &truncate_path(&path_decoded).into()),
        ("path", &path_decoded.into()),
    ];

    let res = match res {
        Ok(res) => res,
        Err(err) => {
            log(Some(".code"), &[(".code", &"ERR".into())]);
            log(Some("error"), &[("error", &err.to_string().into())]);
            log(Some(".path"), path_args);

            return Err(err);
        }
    };

    let status = res.status_code();
    log(None, &[("code", &status.into())]);

    if let Ok(status) = StatusCode::from_u16(status) {
        log(Some("status"), &[("status", &status.to_string().into())]);
    }

    let range = res
        .headers()
        .get("content-range")
        .expect("this is guaranteed to be valid")
        .as_deref()
        .and_then(|r| {
            if let Some(("bytes", r)) = r.split_once(" ") {
                log(None, &[("range", &r.into())]);
            }

            ContentRange::parse(r)
        });

    let mut bytes = res
        .headers()
        .get("content-length")
        .expect("this is guaranteed to be valid")
        .and_then(|s| s.parse().ok());

    let size = range
        .and_then(|r| match r {
            ContentRange::Bytes(b) => {
                bytes = Some(b.complete_length);
                Some((b.first_byte, b.last_byte))
            }
            ContentRange::UnboundBytes(b) => Some((b.first_byte, b.last_byte)),
            ContentRange::Unsatisfied(b) => {
                bytes = Some(b.complete_length);
                None
            }
        })
        .map(|(a, b)| b - a + 1);

    if let Some(bytes) = size {
        let size = ByteSize::from_bytes(bytes as _);

        let size_bytes =
            js_sys::Number::try_from(bytes).map_or_else(|_| bytes.to_string().into(), Into::into);

        log(
            Some("size_iec"),
            &[
                ("size_dec", &size.repr(Mode::Decimal).to_string().into()),
                ("size_iec", &size.to_string().into()),
                ("size_bytes", &size_bytes),
            ],
        );
    }

    let key = (size != bytes).then_some("total_iec");
    if let Some(bytes) = bytes {
        let size = ByteSize::from_bytes(bytes as _);

        let total_bytes =
            js_sys::Number::try_from(bytes).map_or_else(|_| bytes.to_string().into(), Into::into);

        log(
            key,
            &[
                ("total_dec", &size.repr(Mode::Decimal).to_string().into()),
                ("total_iec", &size.to_string().into()),
                ("total_bytes", &total_bytes),
            ],
        );
    }

    log(Some(".path"), path_args);

    js_sys::Reflect::set(&item, &"message".into(), &message.into())?;

    web_sys::console::log_1(&item);

    Ok(res)
}

pub async fn proxy(
    incoming_url: &Url,
    upstream_url: &mut Url,
    method: Method,
    headers: Headers,
    body: Option<web_sys::ReadableStream>,
    log: &mut impl for<'a> FnMut(Option<&'a str>, &[(&'a str, &'a JsValue)]),
) -> Result<Response> {
    log(Some("method"), &[("method", &method.as_ref().into())]);

    log(None, &[("from", &incoming_url.as_str().into())]);

    let Ok(mut upstream_segments) = upstream_url.path_segments_mut() else {
        return Err(format!("invalid upstream url: {upstream_url}").into());
    };

    for segment in incoming_url.path_segments().into_iter().flatten() {
        upstream_segments.push(segment);
    }

    drop(upstream_segments);

    log(None, &[("to", &upstream_url.as_str().into())]);

    let headers = headers.clone();

    let host = &incoming_url[url::Position::BeforeHost..url::Position::AfterPort];
    headers.set("Host", host)?; // workerd overwrites this :-(
    headers.set("X-Forwarded-Host", host)?;
    headers.set("X-Forwarded-Proto", &incoming_url.scheme())?;

    let mut init = RequestInit::new();
    init.with_method(method).with_headers(headers);

    if let Some(body) = body {
        init.with_body(Some(body.into()));
    }

    let req = Request::new_with_init(upstream_url.as_ref(), &init)?;

    Fetch::Request(req).send().await
}

fn truncate_path(p: &str) -> String {
    let (base, resource) = p.rfind("/").map_or(("", p), |i| p.split_at(i));

    let mut out = String::new();

    out.extend(base.chars().take(30 - 8));

    if base.len() > 30 - 8 {
        out.push_str("{..snip}");
    }

    let (name, extension) = resource
        .rfind(".")
        .map_or((resource, ""), |i| resource.split_at(i));

    out.extend(name.chars().take(70 - 8 - extension.len()));

    if name.len() > 70 - 8 - extension.len() {
        out.push_str("{..snip}");
    }

    out.push_str(extension);

    out
}
