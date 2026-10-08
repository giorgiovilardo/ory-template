// Body of the user-service web hook (kratos.yml): which identity was saved, and its
// login email. user-service creates its row or refreshes its email copy.
function(ctx) {
  identity_id: ctx.identity.id,
  email: ctx.identity.traits.email,
}
