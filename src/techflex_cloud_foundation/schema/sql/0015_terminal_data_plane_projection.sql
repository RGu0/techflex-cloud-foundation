BEGIN;

-- RAY-728 D3: activated terminals and institutional insole pairs reach the
-- data plane through projection rows, so the existing foreign keys of
-- screening.sessions (terminal_id, device_id) and subject.consents
-- (terminal_id) hold without being widened. From now on terminal activation,
-- revocation, insole registration and retirement write these rows in the same
-- transaction; this migration backfills rows written before that. Rows that
-- are not projections (hardware or legacy terminals, other tenants) are left
-- untouched. 0008 already grants ffp_activation_app the needed
-- device.terminals and device.devices privileges. Re-running is safe: every
-- statement converges.

INSERT INTO device.terminals
    (terminal_id, tenant_id, site_id, installation_id, client_public_key, status,
     created_at, updated_at)
SELECT t.client_installation_id, t.tenant_id, NULL, t.client_installation_id,
       'terminal-access-v1', t.status, t.activated_at, t.updated_at
FROM iam.access_terminals t
ON CONFLICT (terminal_id) DO UPDATE
SET status = EXCLUDED.status,
    updated_at = GREATEST(device.terminals.updated_at, EXCLUDED.updated_at)
-- Never take over a hardware or legacy row, or another tenant's row.
WHERE device.terminals.client_public_key = 'terminal-access-v1'
  AND device.terminals.tenant_id = EXCLUDED.tenant_id;

-- serial_hmac matches cloud.insole_inventory.postgres.insole_device_serial_hmac:
-- device.devices is UNIQUE NULLS NOT DISTINCT on (tenant_id, serial_hmac).
INSERT INTO device.devices
    (device_id, tenant_id, model, serial_hmac, capabilities, status,
     created_at, updated_at)
SELECT p.insole_id, p.tenant_id, 'insole-pair',
       sha256(convert_to('insole-pair:', 'UTF8') || uuid_send(p.insole_id)),
       '{}'::jsonb,
       CASE WHEN p.state = 'retired' THEN 'RETIRED' ELSE 'ACTIVE' END,
       p.registered_at, p.updated_at
FROM device.insole_pairs p
ON CONFLICT (device_id) DO UPDATE
SET status = EXCLUDED.status,
    updated_at = GREATEST(device.devices.updated_at, EXCLUDED.updated_at)
WHERE device.devices.model = 'insole-pair'
  AND device.devices.tenant_id = EXCLUDED.tenant_id;

COMMIT;
