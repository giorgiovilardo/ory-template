set dotenv-load

# List available recipes
default:
    @just --list

# Generate .env secrets and the JWT signing key; adds keys new in .env.example to an existing .env
init:
    #!/usr/bin/env sh
    set -eu
    rendered=$(awk '{ while (match($0, /__RANDOM_HEX_[0-9]+__/)) { \
      cmd = "openssl rand -hex " substr($0, RSTART + 13, RLENGTH - 15); cmd | getline r; close(cmd); \
      $0 = substr($0, 1, RSTART - 1) r substr($0, RSTART + RLENGTH) } print }' .env.example)
    if [ ! -f .env ]; then
      printf '%s\n' "$rendered" > .env
      echo "Created .env with random secrets."
    else
      printf '%s\n' "$rendered" | grep -E '^[A-Z_]+=' | while IFS= read -r line; do
        key=${line%%=*}
        if ! grep -q "^$key=" .env; then
          printf '%s\n' "$line" >> .env
          echo "Added $key to .env"
        fi
      done
    fi
    if [ ! -f oathkeeper/id_token.jwks.json ]; then
      docker run --rm oryd/oathkeeper:v26.2.0 credentials generate --alg EdDSA > oathkeeper/id_token.jwks.tmp
      mv oathkeeper/id_token.jwks.tmp oathkeeper/id_token.jwks.json
      echo "Created oathkeeper/id_token.jwks.json (EdDSA key that signs the JWTs your app receives)."
    fi

# Start everything
up: init
    docker compose up -d --build --remove-orphans
    @echo ""
    @echo "  Your app      http://localhost:8080  (through Oathkeeper)"
    @echo "  Login UI      http://localhost:4455"
    @echo "  Emails        http://localhost:8025"
    @echo "  Kratos API    http://localhost:4433 (public)  http://localhost:4434 (admin)"
    @echo "  JWKS          http://localhost:4456/.well-known/jwks.json"

admin := "python3 scripts/admin.py"

# Log in as an existing user and print the JWT your app would receive
jwt email password:
    @{{admin}} jwt {{email}} {{quote(password)}}

# List all users
[group('users')]
users:
    @{{admin}} users

# Show one user: traits, metadata, verified addresses, active sessions
[group('users')]
user email:
    @{{admin}} user {{email}}

# Create a verified user, e.g. `just add-user me@x.com 'S3cret-pass!'`
[group('users')]
add-user email password:
    @{{admin}} add-user {{email}} {{quote(password)}}

user_service := "docker compose exec -T user-service /user-service"

# Give a user a role (admin, user), e.g. `just grant-role me@x.com admin`
[group('users')]
grant-role email role:
    @{{user_service}} grant-role {{email}} {{role}}

# Take a role away from a user
[group('users')]
revoke-role email role:
    @{{user_service}} revoke-role {{email}} {{role}}

# Log a user out everywhere
[group('users')]
revoke email:
    @{{admin}} revoke {{email}}

# Block a user: their sessions stop working immediately and login is refused
[group('users')]
deactivate email:
    @{{admin}} deactivate {{email}}

# Unblock a deactivated user
[group('users')]
activate email:
    @{{admin}} activate {{email}}

# Generate a one-hour account recovery link + code for a user
[group('users')]
recover email:
    @{{admin}} recover {{email}}

# Permanently delete a user (the Kratos identity first, then user-service data)
[group('users')]
[confirm("Permanently delete this user? (y/N)")]
delete-user email:
    #!/usr/bin/env sh
    set -eu
    # Kratos first: once the identity is gone, no request can reach user-service for this
    # user, so nothing can re-create the row we're about to delete. (The other way round, a
    # request in between would leave an orphan.) The id is read up front because the email
    # can't be looked up afterwards. If the second step fails, rerun it by id:
    # `docker compose exec user-service /user-service forget-user <id>`.
    id=$({{admin}} id {{email}})
    {{admin}} delete-user {{email}}
    {{user_service}} forget-user "$id"

# Recreate Kratos, Oathkeeper and user-service to pick up config, schema or .env changes
restart:
    docker compose up -d --build --force-recreate kratos oathkeeper user-service

users_db := "postgres://users:$USERS_DB_PASSWORD@localhost:5432/users"

# Run user-service tests (needs the stack's Postgres: `just up` first)
test:
    cd user-service && DATABASE_URL="{{users_db}}" cargo test

# Create a new reversible user-service migration (up + down files)
[group('db')]
migration name:
    cd user-service && sqlx migrate add -r --sequential {{name}}

# Apply pending user-service migrations to the dev database
[group('db')]
migrate:
    cd user-service && sqlx migrate run -D "{{users_db}}"

# Revert the latest user-service migration on the dev database (runs its .down.sql)
[group('db')]
[confirm("Revert the latest migration? Its down.sql may drop data. (y/N)")]
migrate-revert:
    cd user-service && sqlx migrate revert -D "{{users_db}}"

# Refresh user-service/.sqlx after changing a query (needed for the Docker build)
[group('db')]
sqlx-prepare:
    cd user-service && DATABASE_URL="{{users_db}}" cargo sqlx prepare

# Stop everything (data is kept)
down:
    docker compose down

# Follow logs (default: kratos, oathkeeper, user-service)
logs *services="kratos oathkeeper user-service":
    docker compose logs -f {{services}}

# Show container status
ps:
    docker compose ps

# Stop everything and DELETE all users/data
[confirm("This deletes all users and data. Continue? (y/N)")]
reset:
    docker compose down -v
