BEGIN;

-- Account activation atomically projects the activated hardware installation
-- into the data plane.  The pre-authentication role needs only these rows;
-- it remains unable to read screening payloads or identity material.
GRANT SELECT, INSERT, UPDATE ON device.devices, device.terminals, device.terminal_device_bindings TO ffp_activation_app;
GRANT SELECT ON iam.tenants TO ffp_activation_app;

COMMIT;
