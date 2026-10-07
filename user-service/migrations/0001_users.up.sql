-- One row per Kratos identity, created by the hydrator on the user's first request.
create table users (
    id           uuid primary key,              -- Kratos identity id = JWT `sub`
    -- Copy of the Kratos login email, refreshed by the hydrator. Display only: it can
    -- lag behind an email change, so it's neither unique nor indexed. Look users up
    -- by email through Kratos, then by id here.
    email        text not null,
    display_name text,
    created_at   timestamptz not null default now(),
    updated_at   timestamptz not null default now()
);

-- Bumps `users.updated_at` on every update, so no statement (or manual fix) can forget to.
create function set_updated_at() returns trigger language plpgsql as $$
begin
    new.updated_at = now();
    return new;
end
$$;

create trigger users_set_updated_at before update on users
    for each row execute function set_updated_at();
