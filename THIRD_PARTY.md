# Third-party software and data

- The Rust dependencies and exact versions are recorded in `Cargo.lock`; each dependency retains its own license. Principal components are Tokio, Axum, Hickory DNS, SQLx/SQLite, Rustls, Reqwest, Argon2, and Clap.
- Browser tests use Microsoft Playwright under its upstream license. Node dependencies are development-only and are not bundled into the executable.
- Optional HaGeZi feeds are downloaded directly from [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists). No feed data is bundled in this repository. See the upstream repository for its license, constituent sources, list descriptions, and false-positive reporting.
- Quad9 is the default upstream resolver, independently operated by the [Quad9 Foundation](https://quad9.net/). Its service terms and privacy policy apply to DNS queries sent to it. It is configurable and does not sponsor this project.
- The logo and console graphics are original inline SVG/CSS assets in this repository; the console loads no external fonts or icon packages.
