create table user_roles (
    user_id    uuid not null references users (id) on delete cascade,
    -- Mirrors `models::Role`. Adding a role = new variant + a migration updating this check.
    role       text not null check (role in ('admin', 'user')),
    granted_at timestamptz not null default now(),
    granted_by uuid references users (id) on delete set null, -- null = system / CLI
    primary key (user_id, role)
);

-- Deleting a user sets `granted_by` to null on the roles they granted; without this,
-- every user delete scans the whole table.
create index user_roles_granted_by_idx on user_roles (granted_by);
