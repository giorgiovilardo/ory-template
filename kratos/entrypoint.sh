#!/bin/sh
# Builds the social-login provider list from env vars, then starts Kratos.
# A provider is enabled only when both its CLIENT_ID and CLIENT_SECRET are set.
#
# To add another provider (discord, microsoft, apple, gitlab, ...):
#   1. add an `add_provider` line below and a mapper in ./oidc/
#   2. pass its env vars to the kratos service in docker-compose.yml
# Full list: https://www.ory.sh/docs/kratos/social-signin/overview
set -eu

providers=""

# add_provider <id> <provider-type> <client_id> <client_secret> <scope-json-array>
add_provider() {
  [ -n "$3" ] && [ -n "$4" ] || return 0
  entry=$(printf '{"id":"%s","provider":"%s","client_id":"%s","client_secret":"%s","mapper_url":"file:///etc/config/kratos/oidc/%s.jsonnet","scope":%s}' \
    "$1" "$2" "$3" "$4" "$1" "$5")
  providers="${providers:+$providers,}$entry"
  echo "entrypoint: social login enabled for $1"
}

add_provider google google "${GOOGLE_CLIENT_ID:-}" "${GOOGLE_CLIENT_SECRET:-}" '["openid","email","profile"]'
add_provider github github "${GITHUB_CLIENT_ID:-}" "${GITHUB_CLIENT_SECRET:-}" '["user:email"]'

if [ -n "$providers" ]; then
  export SELFSERVICE_METHODS_OIDC_ENABLED=true
  export SELFSERVICE_METHODS_OIDC_CONFIG_PROVIDERS="[$providers]"
fi

exec kratos "$@"
