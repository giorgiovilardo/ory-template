// Maps Google claims to identity traits (email only; profile data lives in user-service).
// Only trust the email if Google says it is verified (prevents account takeover via unverified emails).
local claims = std.extVar('claims');
local verified = 'email' in claims && claims.email_verified;

{
  identity: {
    traits: std.prune({
      [if verified then 'email' else null]: claims.email,
    }),
    // Skip the email verification step - Google already verified it.
    verified_addresses: std.prune([
      if verified then { via: 'email', value: claims.email },
    ]),
  },
}
