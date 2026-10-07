// Maps GitHub claims to identity traits (email only; profile data lives in user-service).
// Only trust the email if GitHub marks it verified (prevents account takeover via unverified emails).
local claims = { email_verified: false } + std.extVar('claims');
local verified = 'email' in claims && claims.email_verified;

{
  identity: {
    traits: std.prune({
      [if verified then 'email' else null]: claims.email,
    }),
    verified_addresses: std.prune([
      if verified then { via: 'email', value: claims.email },
    ]),
  },
}
