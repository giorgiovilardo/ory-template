-- Creates user-service's own role + database in the shared Postgres. Idempotent:
-- runs on every `docker compose up` (users-db-init service), safe on existing volumes.
-- Run with: psql -v pw="$USERS_DB_PASSWORD" -f create-users-db.sql

-- Postgres has no CREATE ROLE/DATABASE IF NOT EXISTS; \gexec runs the selected
-- statement only when the WHERE matches.
SELECT 'CREATE ROLE users LOGIN'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'users') \gexec

-- Always (re)set the password so it follows .env.
-- CREATEDB is only for `#[sqlx::test]`, which creates a throwaway database per test.
-- Drop it in production.
ALTER ROLE users WITH LOGIN CREATEDB PASSWORD :'pw';

SELECT 'CREATE DATABASE users OWNER users'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'users') \gexec
