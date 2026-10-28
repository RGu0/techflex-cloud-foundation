BEGIN;

CREATE SCHEMA IF NOT EXISTS sales;
CREATE SEQUENCE IF NOT EXISTS sales.device_asset_serial_sequence MINVALUE 1 MAXVALUE 999999;

CREATE TABLE sales.inventory_batches (
    inventory_batch_id uuid PRIMARY KEY,
    model text NOT NULL CHECK (model = 'DO-P4864'),
    license_period_months integer NOT NULL CHECK (license_period_months = 12),
    quantity integer NOT NULL CHECK (quantity BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL
);

CREATE TABLE sales.device_inventory (
    device_inventory_id uuid PRIMARY KEY,
    inventory_batch_id uuid NOT NULL REFERENCES sales.inventory_batches(inventory_batch_id),
    asset_serial text NOT NULL UNIQUE CHECK (asset_serial ~ '^FFP-DP4864-[0-9]{6}$'),
    status text NOT NULL CHECK (status IN ('IN_STOCK', 'ACTIVATED')),
    activated_at timestamptz,
    tenant_id uuid REFERENCES iam.tenants(tenant_id),
    hardware_id uuid,
    UNIQUE (tenant_id, hardware_id),
    CHECK ((status = 'IN_STOCK') = (activated_at IS NULL)),
    CHECK ((status = 'IN_STOCK') = (tenant_id IS NULL))
);

CREATE TABLE sales.license_inventory (
    license_inventory_id uuid PRIMARY KEY,
    inventory_batch_id uuid NOT NULL REFERENCES sales.inventory_batches(inventory_batch_id),
    activation_code_hmac bytea NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN ('UNUSED', 'ACTIVATED')),
    activated_at timestamptz,
    tenant_id uuid REFERENCES iam.tenants(tenant_id),
    license_id uuid,
    UNIQUE (tenant_id, license_id),
    CHECK ((status = 'UNUSED') = (activated_at IS NULL)),
    CHECK ((status = 'UNUSED') = (tenant_id IS NULL))
);

CREATE TABLE sales.inventory_activations (
    inventory_activation_id uuid PRIMARY KEY,
    device_inventory_id uuid NOT NULL UNIQUE REFERENCES sales.device_inventory(device_inventory_id),
    license_inventory_id uuid NOT NULL UNIQUE REFERENCES sales.license_inventory(license_inventory_id),
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    account_id uuid NOT NULL,
    hardware_id uuid NOT NULL,
    license_id uuid NOT NULL,
    activated_at timestamptz NOT NULL
);

ALTER TABLE device.hardware_assets
    DROP CONSTRAINT IF EXISTS hardware_assets_stable_identity_check;
ALTER TABLE device.hardware_assets
    ADD CONSTRAINT hardware_assets_stable_identity_check CHECK (
        stable_identity ~ '^(usb-serial-[0-9a-f]{20}|FFP-DP4864-[0-9]{6})$'
    );
ALTER TABLE device.hardware_identity_directory
    DROP CONSTRAINT IF EXISTS hardware_identity_directory_stable_identity_check;
ALTER TABLE device.hardware_identity_directory
    ADD CONSTRAINT hardware_identity_directory_stable_identity_check CHECK (
        stable_identity ~ '^(usb-serial-[0-9a-f]{20}|FFP-DP4864-[0-9]{6})$'
    );

COMMIT;
