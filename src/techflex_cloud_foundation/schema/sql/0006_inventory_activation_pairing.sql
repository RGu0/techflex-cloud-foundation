BEGIN;

-- Device assets and License codes are deliberately independent sales
-- inventories.  At first activation the submitted asset serial and the
-- submitted one-time code are locked, then recorded together in
-- inventory_activations.  Never infer or pre-bind a device-to-code pair.
ALTER TABLE sales.inventory_batches
    ADD COLUMN activation_binding_mode text NOT NULL DEFAULT 'AT_FIRST_ACTIVATION'
    CHECK (activation_binding_mode = 'AT_FIRST_ACTIVATION');

GRANT USAGE ON SCHEMA sales TO ffp_activation_app;
GRANT SELECT, UPDATE ON sales.device_inventory, sales.license_inventory TO ffp_activation_app;
GRANT INSERT ON sales.inventory_activations TO ffp_activation_app;
GRANT INSERT ON iam.tenants TO ffp_activation_app;
GRANT INSERT ON iam.account_login_directory, device.license_entitlements TO ffp_activation_app;
GRANT INSERT ON device.hardware_assets, device.license_assignments,
    device.hardware_bindings TO ffp_activation_app;
GRANT INSERT ON device.hardware_identity_directory TO ffp_activation_app;

COMMIT;
