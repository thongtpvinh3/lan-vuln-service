-- Đổi loại đánh giá của mapping SSH hiện tại.
UPDATE vuln_misconfig_rule_mapping m
SET evaluation_type = 'SERVICE_ENABLED', updated_at = NOW()
FROM vuln_misconfig_rule r
JOIN vuln_misconfig_source s ON s.id = r.source_id
WHERE m.source_id = r.source_id
  AND m.source_file = r.source_file
  AND m.content_sha256 = r.content_sha256
  AND s.source_key = 'COMPLIANCE_AS_CODE'
  AND r.external_rule_id = 'service_sshd_enabled'
  AND r.source_revision = s.last_revision
  AND r.deprecated = FALSE
  AND m.condition = '{"operator": "SERVICE_ENABLED", "service": "sshd", "expected": true}'::jsonb
RETURNING m.id, m.evaluation_type, m.condition;
