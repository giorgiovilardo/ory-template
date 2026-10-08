# user-service

Owns the user: profile fields and roles, in its own Postgres database, keyed by the Kratos identity id (= the JWT `sub`). One binary with these jobs:

- **The hydrator** (`POST /internal/hydrate`). Oathkeeper calls it on every logged-in request, before it mints the JWT. It creates the user's row on first sight (with the `user` role), and adds `display_name` and `roles` to the token.
- **The public API** (`/api/users/me`). Users read and edit their own profile, reached only through Oathkeeper.
- **The admin CLI.** It's the one place to manage a user: list, inspect, create, grant roles, block, recover, delete. A user is a Kratos identity (login, sessions, whether they may log in) plus this service's row, and the CLI acts on both, through the Kratos admin API and the database.
- **Operations:** `migrate` (a one-shot job before `serve`) and `healthcheck` (for Docker, since the image has no curl).

Kratos owns identity: the email, credentials, verification and login state. This service never stores credentials and never talks to Kratos while serving. Only the CLI uses the Kratos admin API. See the [root README](../README.md) for how the stack fits together.

## Running it

**In the stack (normal case):** `just up` from the repo root builds the image and starts everything. On every `up`, the `user-service-migrate` service (same image, `migrate` subcommand) applies pending migrations and exits. `user-service` (`serve`) only starts after that succeeds. Neither listener is published on the host: `:3000` is reached through Oathkeeper (`/api/users/**`), and `:3001` only by Oathkeeper itself.

**Outside Docker** (Rust and `sqlx-cli` needed), against the stack's Postgres:

```bash
just up                                   # Postgres, Kratos and Oathkeeper must be running
cp .env.example .env                      # then fill in the passwords from the root .env
set -a; source .env; set +a               # the binary does not load .env itself
cargo run -- serve                        # or any other subcommand: cargo run -- users
```

Oathkeeper still calls the container, not your local process. The local server is for poking at endpoints with `curl` and tokens you mint yourself (`src/testing.rs`).

## Commands

Every command is a subcommand of the binary. In the stack, run them inside the container, where `DATABASE_URL` and `KRATOS_ADMIN_URL` are already set:

```bash
docker compose exec user-service /user-service --help
docker compose exec user-service /user-service grant-role me@x.com --help
```

From the repo root, the `just` recipes wrap the same commands:

| Command | `just` | What it does |
| --- | --- | --- |
| `serve` | (`just up`) | Runs the public API (`:3000`) and the hydrator (`:3001`) |
| `migrate` | (`just up`) | Applies pending migrations (embedded in the binary), then exits |
| `healthcheck` | | Exits 0 if the local server answers `/health` |
| `users` | `just users` | Table of every user: id, email, Kratos state, verified, roles, created |
| `user EMAIL` | `just user EMAIL` | JSON: the full Kratos identity (with linked social logins), active session count, this service's data |
| `add-user EMAIL PASSWORD` | `just add-user EMAIL PASSWORD` | Creates a Kratos identity with a password and a verified email, plus its row with the `user` role. For dev seeding |
| `grant-role EMAIL ROLE` | `just grant-role EMAIL ROLE` | Adds a role (`admin`, `user`). Creates the row if the user never made a request |
| `revoke-role EMAIL ROLE` | `just revoke-role EMAIL ROLE` | Removes a role |
| `revoke-sessions EMAIL` | `just revoke EMAIL` | Deletes all the user's sessions: logged out everywhere |
| `deactivate EMAIL` | `just deactivate EMAIL` | Blocks the user: sessions stop working at once, login is refused. Sessions are suspended, not deleted |
| `activate EMAIL` | `just activate EMAIL` | Unblocks the user. Their suspended sessions work again |
| `recover EMAIL` | `just recover EMAIL` | Prints a one-hour recovery link and code for you to send the user |
| `delete-user EMAIL` | `just delete-user EMAIL` | Deletes the Kratos identity, then this service's data. `just` asks first; the binary doesn't |
| `forget-user EMAIL\|ID` | | Deletes only this service's data. By id, it cleans up after the Kratos identity is already gone |

A few things all of them share:

- **Users are named by email, resolved through Kratos.** The CLI looks the email up in Kratos (the credentials index, then a scan of `traits.email` for social-login-only accounts) and acts on the identity id. It never matches on this service's `users.email`, which is a display copy: not unique, and only refreshed when the user makes a request. If several identities share the email, the command refuses to pick one.
- **Role changes reach the JWT on the very next request.** The hydrator reads roles on every request, so nobody needs to log out.
- **The first admin needs no admin API:** `just grant-role you@x.com admin` works on a fresh stack. Access to the container is the authorization.
- **`delete-user` deletes from Kratos first.** Once the identity is gone, no request can reach this service for that user, so nothing can re-create the row before it's deleted. If the second step fails, the error names the `forget-user <id>` command that finishes the job.
- **Kratos errors come through with Kratos' reason**, e.g. `POST /admin/identities -> 409 Conflict: This identity conflicts with another identity that already exists.`

## Configuration

Every setting is a flag that falls back to an environment variable (the flag wins). Each subcommand takes only the settings it needs, and `<subcommand> --help` lists them. Secret values are hidden from the help.

| Variable / flag | Used by | Default | |
| --- | --- | --- | --- |
| `DATABASE_URL` / `--database-url` | `serve`, `migrate`, admin commands that touch user data | (required) | `postgres://users:…@postgres:5432/users` |
| `DB_MAX_CONNECTIONS` / `--db-max-connections` | same | `10` | Pool size |
| `KRATOS_ADMIN_URL` / `--kratos-admin-url` | admin commands | `http://kratos:4434` | Never expose this API publicly |
| `HYDRATOR_PASSWORD` / `--hydrator-password` | `serve` | (required) | Basic-auth password Oathkeeper sends to `/internal/hydrate` (user `oathkeeper`) |
| `JWKS_URL` / `--jwks-url` | `serve` | `http://oathkeeper:4456/.well-known/jwks.json` | Oathkeeper's public keys, for verifying JWTs |
| `JWT_ISSUER` / `--jwt-issuer` | `serve` | `http://localhost:8080/` | Must match `issuer_url` in `oathkeeper.yml` |
| `PUBLIC_ADDR` / `--public-addr` | `serve`, `healthcheck` | `0.0.0.0:3000` | Routed through Oathkeeper |
| `INTERNAL_ADDR` / `--internal-addr` | `serve` | `0.0.0.0:3001` | Never routed through Oathkeeper |
| `RUST_LOG` | all | `info,user_service=debug,sqlx=warn` | `tracing` filter |

`revoke-sessions`, `deactivate`, `activate` and `recover` only need Kratos, so they run without a database setting.

## HTTP API

**Public listener (`:3000`)**, reached only through Oathkeeper, which has already authenticated the request and attached a JWT. Every request must carry `Authorization: Bearer <JWT>`. The service verifies it against Oathkeeper's JWKS (EdDSA, pinned) and reads only `sub`. Profile and roles come from the database, never from the token.

| Route | |
| --- | --- |
| `GET /health` | `ok`, no auth (Docker healthcheck) |
| `GET /api/users/me` | `{id, email, display_name, created_at, updated_at, roles}` |
| `PUT /api/users/me` | Replaces the editable profile: `{"display_name": "Ada"}`, or `null` to clear it. Every field is required |

**Internal listener (`:3001`)**: `POST /internal/hydrate`, Oathkeeper's hydrator mutator, behind Basic auth. It receives the whole Oathkeeper session and returns it unchanged except for `extra.profile = {display_name, roles}`. The contract is spelled out at the top of `src/hydrate.rs`.

**Errors** are always `{"error": {"code": "...", "message": "..."}}`. Branch on `code`; `message` is for humans and may change.

| Status | `code` |
| --- | --- |
| 400 | `bad_request` |
| 401 | `unauthorized` |
| 404 | `not_found` |
| 422 | `invalid_body`, `display_name_empty`, `display_name_too_long` (over 100 characters), `display_name_control_characters` |
| 503 | `timeout` (every request is capped at 1s, under Oathkeeper's 2s hydrator budget) |
| 500 | `internal` (details are logged, never sent) |

## Data

```
users        id (Kratos identity id), email (display copy), display_name, created_at, updated_at (trigger-maintained)
user_roles   user_id → users.id (on delete cascade), role ∈ {admin, user}
```

Migrations are reversible sqlx pairs in `migrations/`, compiled into the binary:

```bash
just migration add_avatar_url    # new migrations/0003_add_avatar_url.{up,down}.sql
just migrate                     # apply pending ones to the dev database
just migrate-revert              # run the latest .down.sql (asks first)
```

To add a user field, follow [Customizing](../README.md#customizing) in the root README: migration, `User`, `db.rs`, then opt it into `MeResponse` and/or `Profile` (the JWT).

## Development

```bash
just test           # every test; each DB test gets its own throwaway database (#[sqlx::test])
cargo clippy --all-targets    # pedantic lints are on (Cargo.toml)
cargo fmt
just sqlx-prepare   # after changing any query: refresh .sqlx/, which the Docker build needs
```

Tests need the stack's Postgres (`just up`), but not Kratos or Oathkeeper. JWTs are signed with a fixed test key (`src/testing.rs`), and the Kratos admin API is mocked with a small axum server.

Queries use sqlx's compile-time-checked macros, so a wrong column or type is a compile error. Locally they check against `DATABASE_URL` in `.env`. The Docker build sets `SQLX_OFFLINE=true` and reads the committed `.sqlx/` instead, so a new or changed query fails the image build until you run `just sqlx-prepare` and commit the result.

The image is a static musl binary in `FROM scratch`, running as an unprivileged user: no shell, no package manager.

## Code layout

```
src/main.rs           parses the CLI, picks a runtime (multi-threaded only for `serve`)
src/cli.rs            subcommand definitions and dispatch; `migrate`, `healthcheck`
src/admin.rs          the user-admin commands
src/config.rs         settings as clap argument groups (flag or env var)
src/server.rs         `serve`: two listeners, request timeout, graceful shutdown
src/api.rs            public routes: /health, /api/users/me
src/hydrate.rs        internal route: /internal/hydrate
src/auth.rs           JWT verification (JWKS fetch, cache, key rotation)
src/kratos.rs         Kratos types (session, identity) and the admin API client
src/db.rs             all SQL
src/error.rs          AppError: the one place that maps errors to status + code
src/models/           Email, DisplayName, Role, User: validated types, invariants live here
src/testing.rs        test key, token minting, router helpers
migrations/           *.up.sql / *.down.sql
.sqlx/                offline query data for the Docker build
```
