# Build a fully static binary: Alpine's Rust targets musl, which links statically,
# and nothing here needs OpenSSL (no TLS inside the compose network).
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
# sqlx's query macros check SQL at compile time; there's no database during the
# build, so they read the committed `.sqlx/` data (`cargo sqlx prepare`) instead.
ENV SQLX_OFFLINE=true
WORKDIR /src

# Dependencies first, against a stub main.rs: this layer is only rebuilt when
# Cargo.toml or Cargo.lock change, not on every source edit.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked

COPY . .
# Cargo decides what's stale by mtime, and COPY keeps the files' (older) mtimes, so
# without this it could consider the stub's build up to date and ship the stub.
RUN touch src/main.rs \
    && cargo build --release --locked \
    && cp target/release/user-service /user-service

# Just the binary. No shell, no package manager, nothing to exploit.
FROM scratch
COPY --from=build /user-service /user-service
USER 10001:10001
EXPOSE 3000 3001
ENTRYPOINT ["/user-service"]
CMD ["serve"]
