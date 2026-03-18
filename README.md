# janus

> Cloudflare worker as a reverse proxy

## Usage

Define a `.dev.vars` file with the populated contents of `.dev.vars.sample`.

For local testing:

```console
npx wrangler dev
<..snip>
{
  method: 'GET',
  from: 'http://localhost:8787/path/to/resource',
  to: 'https://some-website.com/path/to/resource',
  code: 206,
  status: '206 Partial Content',
  range: '1045438755-1393918339/1742397926',
  size_dec: '348.47 MB',
  size_iec: '332.33 MiB',
  size_bytes: 348479585,
  total_dec: '1.74 GB',
  total_iec: '1.62 GiB',
  total_bytes: 1742397926,
  path: '/path/to/resource',
  message: 'GET | 206 Partial Content | 332.33 MiB | 1.62 GiB | /path/to/resource'
}
[wrangler:info] GET /path/to/resource 206 Partial Content (381ms)
```

Deployment:

```console
npx wrangler deploy
```

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as below, without any additional terms or conditions.

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license
  ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
