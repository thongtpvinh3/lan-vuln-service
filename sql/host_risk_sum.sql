-- Apply before deploying host risk scoring based on the sum of finding scores.
-- Existing scores are retained; rerun assessments to recalculate them.
BEGIN;

ALTER TABLE vuln_risk_result
    DROP CONSTRAINT IF EXISTS vuln_risk_result_risk_score_check;
ALTER TABLE vuln_risk_result
    ALTER COLUMN risk_score TYPE NUMERIC;
ALTER TABLE vuln_risk_result
    ADD CONSTRAINT vuln_risk_result_risk_score_check CHECK (risk_score >= 0);

COMMIT;
