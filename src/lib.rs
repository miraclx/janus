use http::StatusCode;
use http_content_range::ContentRange;
use sha2::{Digest, Sha256};
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

    let ip = req.headers().get("CF-Connecting-IP").ok().flatten();
    let ua = req.headers().get("User-Agent").ok().flatten();

    let cf = req.cf();

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

            let mut segments = k.split('.');
            let leaf = segments.next_back().unwrap();
            let mut cur: JsValue = item.clone().into();
            for seg in segments {
                let seg_key = JsValue::from(seg);
                let child = js_sys::Reflect::get(&cur, &seg_key)
                    .ok()
                    .filter(|v| v.is_object() && !v.is_null())
                    .unwrap_or_else(|| {
                        let obj: JsValue = js_sys::Object::new().into();
                        let _ = js_sys::Reflect::set(&cur, &seg_key, &obj);
                        obj
                    });
                cur = child;
            }
            let _ignored = js_sys::Reflect::set(&cur, &JsValue::from(leaf), v);
        }
    };

    if let Some(ref ip) = ip {
        log(None, &[("source.ip", &ip.as_str().into())]);
    }

    if let Some(ref ua) = ua {
        log(None, &[("ua", &ua.as_str().into())]);
    }

    let asn = cf.and_then(|cf| cf.asn());

    if let Some(cf) = cf {
        if let Some(country) = cf.country() {
            log(None, &[("location.country", &country.into())]);
        }
        if let Some(city) = cf.city() {
            log(None, &[("location.city", &city.into())]);
        }
        if let Some(org) = cf.as_organization() {
            log(None, &[("source.org", &org.into())]);
        }
    }

    // SHA-256 of ip:asn — changes with network/connection
    let network = match (ip.as_deref(), asn) {
        (Some(ip), Some(asn)) => Some(format!("{ip}:{asn}")),
        (Some(ip), None) => Some(ip.to_string()),
        _ => None,
    }
    .map(|raw| {
        let hash = Sha256::digest(raw.as_bytes());
        hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
    });
    if let Some(ref net) = network {
        log(None, &[("id.network", &net.as_str().into())]);
    }

    let raw_cf = js_sys::Reflect::get(req.inner().as_ref(), &"cf".into())
        .ok()
        .filter(|v| !v.is_undefined() && !v.is_null());

    let cf_str = |key: &str| {
        raw_cf
            .as_ref()
            .and_then(|cf| js_sys::Reflect::get(cf, &key.into()).ok())
            .and_then(|v| v.as_string())
    };

    // SHA-256 of tls_ciphers:tls_exts:tls_hello_len:ua — stable per OS/TLS stack + device type
    let fingerprint = {
        let mut parts: Vec<String> = Vec::new();
        if let Some(v) = cf_str("tlsClientCiphersSha1") {
            parts.push(v);
        }
        if let Some(v) = cf_str("tlsClientExtensionsSha1") {
            parts.push(v);
        }
        if let Some(v) = cf_str("tlsClientHelloLength") {
            parts.push(v);
        }
        if let Some(ref v) = ua {
            parts.push(v.clone());
        }
        (!parts.is_empty()).then(|| {
            let hash = Sha256::digest(parts.join(":").as_bytes());
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        })
    };
    if let Some(ref fp) = fingerprint {
        log(None, &[("id.device", &fp.as_str().into())]);
    }

    let headers_obj = js_sys::Object::new();
    for (name, value) in req.headers() {
        let _ = js_sys::Reflect::set(&headers_obj, &name.into(), &value.into());
    }
    let _ = js_sys::Reflect::set(&item, &"headers".into(), &headers_obj);

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
        ("url.path", &path_decoded.into()),
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
            Some("size.iec"),
            &[
                ("size.dec", &size.repr(Mode::Decimal).to_string().into()),
                ("size.iec", &size.to_string().into()),
                ("size.bytes", &size_bytes),
            ],
        );
    }

    let key = (size != bytes).then_some("total.iec");
    if let Some(bytes) = bytes {
        let size = ByteSize::from_bytes(bytes as _);

        let total_bytes =
            js_sys::Number::try_from(bytes).map_or_else(|_| bytes.to_string().into(), Into::into);

        log(
            key,
            &[
                ("total.dec", &size.repr(Mode::Decimal).to_string().into()),
                ("total.iec", &size.to_string().into()),
                ("total.bytes", &total_bytes),
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

    log(None, &[("url.from", &incoming_url.as_str().into())]);

    let Ok(mut upstream_segments) = upstream_url.path_segments_mut() else {
        return Err(format!("invalid upstream url: {upstream_url}").into());
    };

    for segment in incoming_url.path_segments().into_iter().flatten() {
        upstream_segments.push(segment);
    }

    drop(upstream_segments);

    log(None, &[("url.to", &upstream_url.as_str().into())]);

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
