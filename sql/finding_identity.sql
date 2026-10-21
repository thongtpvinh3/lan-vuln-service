BEGIN;

ALTER TABLE vuln_finding ADD COLUMN IF NOT EXISTS finding_id UUID;
ALTER TABLE vuln_misconfig_finding ADD COLUMN IF NOT EXISTS finding_id UUID;

-- Giữ ID đã có, bổ sung ID cho dữ liệu cũ.
UPDATE vuln_finding SET finding_id = gen_random_uuid() WHERE finding_id IS NULL;
UPDATE vuln_misconfig_finding SET finding_id = gen_random_uuid() WHERE finding_id IS NULL;

ALTER TABLE vuln_finding ALTER COLUMN finding_id SET NOT NULL;
ALTER TABLE vuln_misconfig_finding ALTER COLUMN finding_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_finding_uuid ON vuln_finding (finding_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_misconfig_finding_uuid ON vuln_misconfig_finding (finding_id);

COMMIT;
