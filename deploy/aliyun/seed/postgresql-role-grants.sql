\set ON_ERROR_STOP on
SET password_encryption = 'scram-sha-256';

REVOKE CONNECT ON DATABASE :"database_name" FROM PUBLIC;
ALTER SYSTEM SET listen_addresses = '127.0.0.1,::1';

SELECT format(
    'CREATE ROLE ffp_seed_tenant LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'tenant_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ffp_seed_tenant') \gexec
SELECT format(
    'CREATE ROLE ffp_seed_activation LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'activation_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ffp_seed_activation') \gexec
SELECT format(
    'CREATE ROLE ffp_seed_platform LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'platform_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ffp_seed_platform') \gexec
SELECT format(
    'CREATE ROLE ffp_seed_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS PASSWORD %L',
    :'backup_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ffp_seed_backup') \gexec

ALTER ROLE ffp_seed_tenant PASSWORD :'tenant_password';
ALTER ROLE ffp_seed_activation PASSWORD :'activation_password';
ALTER ROLE ffp_seed_platform PASSWORD :'platform_password';
ALTER ROLE ffp_seed_backup PASSWORD :'backup_password';

GRANT ffp_tenant_app TO ffp_seed_tenant;
GRANT ffp_activation_app TO ffp_seed_activation;
GRANT ffp_platform_app TO ffp_seed_platform;
GRANT CONNECT ON DATABASE :"database_name"
    TO ffp_seed_tenant, ffp_seed_activation, ffp_seed_platform, ffp_seed_backup;
GRANT USAGE ON SCHEMA iam, device, subject, screening, ops, sales TO ffp_seed_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA iam, device, subject, screening, ops, sales TO ffp_seed_backup;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sales TO ffp_seed_backup;

GRANT USAGE ON SCHEMA sales TO ffp_platform_app, ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA sales TO ffp_platform_app, ffp_activation_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sales TO ffp_platform_app;

-- The seed License activation role materializes compatibility rows consumed by
-- the existing ingestion schema. It still has no subject, screening, report,
-- or cross-tenant privilege, and remains NOBYPASSRLS.
GRANT SELECT, INSERT, UPDATE ON device.devices TO ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON device.terminals TO ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON device.terminal_device_bindings TO ffp_activation_app;
GRANT SELECT ON iam.tenants TO ffp_activation_app;
GRANT INSERT ON iam.account_login_directory, device.license_entitlements TO ffp_activation_app;

ALTER ROLE ffp_seed_tenant SET statement_timeout = '60s';
ALTER ROLE ffp_seed_activation SET statement_timeout = '30s';
ALTER ROLE ffp_seed_platform SET statement_timeout = '60s';
ALTER ROLE ffp_seed_tenant SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE ffp_seed_activation SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE ffp_seed_platform SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE ffp_seed_backup SET statement_timeout = '15min';
ALTER ROLE ffp_seed_backup SET idle_in_transaction_session_timeout = '30s';
