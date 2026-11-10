# bitbid landing page

Static HTML/CSS/JavaScript landing page, maintained separately from the Yew
browser console in `../webapp` and native/shared Rust project in `../bitsec`.
No build step or package manager is required. Serve locally, for example:

```sh
python3 -m http.server 8081 --bind 127.0.0.1
```

The source checkpoint preserves the existing visual design and assets.
The origin is `git@github.com:igmrrf/bitbid.git`, with this independent history
on the `web/main` branch. No deployment target has been configured.
