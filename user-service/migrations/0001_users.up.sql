-- One row per Kratos identity, created by the hydrator on the user's first request.
create table users (
    id           uuid primary key,              -- Kratos identity id = JWT `sub`
    email        text not null,                 -- copy of the Kratos login email, refreshed by the hydrator
    display_name text,
    created_at   timestamptz not null default now(),
    updated_at   timestamptz not null default now()
);

-- Not unique: Kratos owns uniqueness, and this copy can briefly lag behind an email change.
create index users_email_idx on users (email);
