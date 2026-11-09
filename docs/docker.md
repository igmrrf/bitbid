> Prospective packaging template only. This channel has not been published or verified.
> Package names, registry namespaces, taps, URLs, hashes and workflows below require
> separate selection, validation and publication authorization. Do not use the
> illustrated installation commands as available releases. Use [source installation](cargo.md).

# Docker Containerization & Image Deployment Guide

This guide covers building lightweight Docker container images for `bitbid`, publishing them to **Docker Hub** and **GitHub Container Registry (`ghcr.io`)**, and orchestrating local dev stacks with `docker compose`.

---

## 🛠 Multi-Stage `Dockerfile`

Create a multi-stage `Dockerfile` in the repository root:

```dockerfile
# --- Build Stage ---
FROM rust:1.98-alpine AS builder

RUN apk add --no-cache musl-dev gcc pkgconfig openssl-dev

WORKDIR /usr/src/bitbid
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --locked --release -p bitbid-cli --bin bitbid --target x86_64-unknown-linux-musl

# --- Final Runtime Stage ---
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /usr/src/bitbid/target/x86_64-unknown-linux-musl/release/bitbid /usr/local/bin/bitbid

ENTRYPOINT ["bitbid"]
CMD ["--help"]
```

---

## 🐳 Local Docker Building & Testing

### 1. Build Image

```bash
docker build -t bitbid:latest .
```

### 2. Run Container CLI Commands

```bash
# Display version
docker run --rm bitbid:latest --version

# Run bitbid mounted with local workspace
docker run --rm -v $(pwd):/app -w /app bitbid:latest status
```

---

## 🚀 Publishing Container Images

### 1. Publish to Docker Hub

```bash
docker login -u <DOCKER_HUB_USERNAME>
docker tag bitbid:latest <DOCKER_HUB_USERNAME>/bitbid:v0.1.0
docker tag bitbid:latest <DOCKER_HUB_USERNAME>/bitbid:latest

docker push <DOCKER_HUB_USERNAME>/bitbid:v0.1.0
docker push <DOCKER_HUB_USERNAME>/bitbid:latest
```

### 2. Publish to GitHub Container Registry (`ghcr.io`)

```bash
echo ${{ secrets.GITHUB_TOKEN }} | docker login ghcr.io -u igmrrf --password-stdin

docker tag bitbid:latest ghcr.io/igmrrf/bitbid:v0.1.0
docker tag bitbid:latest ghcr.io/igmrrf/bitbid:latest

docker push ghcr.io/igmrrf/bitbid:v0.1.0
docker push ghcr.io/igmrrf/bitbid:latest
```

---

## 🤖 GitHub Actions Workflow (`.github/workflows/docker.yml`)

```yaml
name: Publish Docker Image

on:
  release:
    types: [published]

jobs:
  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and Push GHCR Image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: |
            ghcr.io/igmrrf/bitbid:${{ github.ref_name }}
            ghcr.io/igmrrf/bitbid:latest
```

---

## 📦 Local Stack Orchestration (`docker-compose.yml`)

For local testing with an Anvil EVM node and IPFS gateway:

```bash
docker compose up -d
```
