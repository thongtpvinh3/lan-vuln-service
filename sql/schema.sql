SELECT current_database(), current_user;

CREATE TABLE IF NOT EXISTS vuln_nvd_cache (
    cache_key TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vuln_finding (
    finding_id UUID NOT NULL UNIQUE,
    stage_run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,

    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,

    product TEXT NOT NULL,
    version TEXT NOT NULL,
    cpe TEXT NOT NULL,
    cve_id TEXT NOT NULL,

    cvss_score NUMERIC(4,1),
    severity TEXT,
    status TEXT NOT NULL,

    evidence JSONB NOT NULL,

    created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_vuln_finding PRIMARY KEY (
        stage_run_id,
        host,
        port,
        protocol,
        cve_id
    ),

    CONSTRAINT chk_vuln_port
        CHECK (port BETWEEN 1 AND 65535),

    CONSTRAINT chk_vuln_cvss
        CHECK (
            cvss_score IS NULL
            OR cvss_score BETWEEN 0 AND 10
        ),

    CONSTRAINT chk_vuln_status
        CHECK (
            status IN (
                'POTENTIAL',
                'LIKELY_AFFECTED',
                'NEEDS_REVIEW',
                'NOT_AFFECTED'
            )
        )
);


-- ==========================================
-- INDEXES
-- ==========================================

CREATE INDEX IF NOT EXISTS idx_vuln_finding_scan
    ON vuln_finding(scan_id);

CREATE INDEX IF NOT EXISTS idx_vuln_finding_cve
    ON vuln_finding(cve_id);

CREATE INDEX IF NOT EXISTS idx_vuln_finding_host
    ON vuln_finding(host);


-- ==========================================
-- Tạo bản lưu CPE Công khai
-- ==========================================
CREATE TABLE IF NOT EXISTS vuln_cpe_dictionary (
    cpe_name_id UUID PRIMARY KEY,
    cpe_name TEXT NOT NULL UNIQUE,

    part CHAR(1) NOT NULL
        CHECK (part IN ('a', 'o', 'h')),

    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT,

    display_name TEXT,

    deprecated BOOLEAN NOT NULL DEFAULT FALSE,

    titles JSONB NOT NULL DEFAULT '[]'::jsonb,
    refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    deprecated_by JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw_data JSONB NOT NULL DEFAULT '{}'::jsonb,

    nvd_created_at TIMESTAMPTZ,
    nvd_modified_at TIMESTAMPTZ,

    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_cpe_format
        CHECK (cpe_name LIKE 'cpe:2.3:%')
);

CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product
    ON vuln_cpe_dictionary (part, vendor, product);

CREATE INDEX IF NOT EXISTS idx_cpe_version
    ON vuln_cpe_dictionary (part, vendor, product, version);

CREATE INDEX IF NOT EXISTS idx_cpe_modified
    ON vuln_cpe_dictionary (nvd_modified_at);

CREATE INDEX IF NOT EXISTS idx_cpe_active
    ON vuln_cpe_dictionary (vendor, product)
    WHERE deprecated = FALSE;

CREATE TABLE IF NOT EXISTS vuln_misconfig_source (
    id BIGSERIAL PRIMARY KEY,
    source_key VARCHAR(100) NOT NULL UNIQUE,
    source_name VARCHAR(255) NOT NULL,
    source_url TEXT NOT NULL,
    source_type VARCHAR(30) NOT NULL
        CHECK (source_type IN (
            'GITHUB',
            'SCAP',
            'API',
            'FILE'
        )),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    license_name TEXT,
    license_url TEXT,
    last_revision TEXT,
    last_synced_at TIMESTAMPTZ,
    last_sync_status VARCHAR(20)
        CHECK (last_sync_status IN (
            'SUCCESS',
            'FAILED',
            'PARTIAL'
        )),
    last_sync_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vuln_misconfig_rule (
    -- 1. Primary key
    id BIGSERIAL PRIMARY KEY,

    -- 2. Source and revision
    source_id BIGINT NOT NULL
        REFERENCES vuln_misconfig_source(id),

    external_rule_id TEXT NOT NULL,
    source_revision VARCHAR(64) NOT NULL,
    source_file TEXT NOT NULL,
    source_reference_url TEXT,

    -- 3. Security rule metadata
    title TEXT NOT NULL,
    description TEXT,
    rationale TEXT,
    severity VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN',

    category TEXT,
    target_type TEXT,
    target_product TEXT,
    platform_expression TEXT,

    identifiers JSONB NOT NULL DEFAULT '{}'::jsonb,
    references_data JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- 4. Remediation
    remediation TEXT,
    remediation_available BOOLEAN NOT NULL DEFAULT FALSE,

    -- 5. Original source data
    raw_format VARCHAR(20) NOT NULL DEFAULT 'YAML',
    raw_content TEXT NOT NULL,
    raw_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    content_sha256 CHAR(64) NOT NULL,

    -- 6. Metadata parsing state
    parse_status VARCHAR(20)
        NOT NULL DEFAULT 'NOT_PROCESSED',

    contains_template BOOLEAN NOT NULL DEFAULT FALSE,
    parse_error TEXT,

    -- 7. Rule normalization
    normalized_rule JSONB,
    required_evidence JSONB
        NOT NULL DEFAULT '[]'::jsonb,

    execution_status VARCHAR(20)
        NOT NULL DEFAULT 'NOT_PROCESSED',

    validation_error TEXT,

    -- 8. Activation and lifecycle
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    deprecated BOOLEAN NOT NULL DEFAULT FALSE,

    -- 9. Audit timestamps
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT uq_misconfig_rule_revision
        UNIQUE (source_id, source_file, source_revision),

    CONSTRAINT chk_misconfig_rule_severity
        CHECK (severity IN (
            'NONE', 'LOW', 'MEDIUM',
            'HIGH', 'CRITICAL', 'UNKNOWN'
        )),

    CONSTRAINT chk_misconfig_parse_status
        CHECK (parse_status IN (
            'NOT_PROCESSED',
            'PARSED',
            'PROVISIONAL',
            'RAW_ONLY'
        )),

    CONSTRAINT chk_misconfig_execution_status
        CHECK (execution_status IN (
            'NOT_PROCESSED',
            'SUPPORTED',
            'UNSUPPORTED',
            'NEEDS_REVIEW',
            'INVALID'
        )),

    CONSTRAINT chk_misconfig_raw_data
        CHECK (jsonb_typeof(raw_data) = 'object'),

    CONSTRAINT chk_misconfig_identifiers
        CHECK (jsonb_typeof(identifiers) = 'object'),

    CONSTRAINT chk_misconfig_references
        CHECK (jsonb_typeof(references_data) = 'array'),

    CONSTRAINT chk_misconfig_required_evidence
        CHECK (jsonb_typeof(required_evidence) = 'array'),

    CONSTRAINT chk_misconfig_normalized_rule
        CHECK (
            normalized_rule IS NULL
            OR jsonb_typeof(normalized_rule) = 'object'
        ),

    CONSTRAINT chk_misconfig_enabled
        CHECK (
            enabled = FALSE
            OR (
                parse_status IN ('PARSED', 'PROVISIONAL')
                AND execution_status = 'SUPPORTED'
                AND normalized_rule IS NOT NULL
                AND deprecated = FALSE
            )
        ),

    CONSTRAINT chk_misconfig_sha256
        CHECK (
            content_sha256 ~ '^[0-9a-f]{64}$'
        )
);
CREATE INDEX IF NOT EXISTS idx_misconfig_rule_source
ON vuln_misconfig_rule (source_id);

CREATE INDEX IF NOT EXISTS idx_misconfig_rule_external
ON vuln_misconfig_rule (source_id, external_rule_id);

CREATE INDEX IF NOT EXISTS idx_misconfig_rule_revision
ON vuln_misconfig_rule (source_revision);

CREATE INDEX IF NOT EXISTS idx_misconfig_rule_parse
ON vuln_misconfig_rule (parse_status);

CREATE INDEX IF NOT EXISTS idx_misconfig_rule_execution
ON vuln_misconfig_rule (execution_status)
WHERE deprecated = FALSE;

CREATE INDEX IF NOT EXISTS idx_misconfig_rule_target
ON vuln_misconfig_rule (target_type, target_product);

CREATE INDEX IF NOT EXISTS idx_misconfig_rule_identifiers
ON vuln_misconfig_rule USING GIN (identifiers);

CREATE INDEX IF NOT EXISTS idx_misconfig_rule_normalized
ON vuln_misconfig_rule USING GIN (normalized_rule);

CREATE UNIQUE INDEX IF NOT EXISTS
    uq_misconfig_rule_enabled_revision
ON vuln_misconfig_rule (source_id, source_file)
WHERE enabled = TRUE;


-- =====================================================
-- VULN_MISCONFIG_RULE_MAPPING
-- =====================================================

CREATE TABLE IF NOT EXISTS vuln_misconfig_rule_mapping (
    id BIGSERIAL PRIMARY KEY,

    -- Xác định rule trong ComplianceAsCode
    source_id BIGINT NOT NULL REFERENCES vuln_misconfig_source(id),

    source_file TEXT NOT NULL,

    -- Xác minh nội dung rule được mapping
    content_sha256 CHAR(64) NOT NULL,

    -- Quản lý các phiên bản mapping
    mapping_version VARCHAR(20) NOT NULL DEFAULT '1.0',

    -- Loại phép kiểm tra
    evaluation_type VARCHAR(50) NOT NULL,

    -- Loại thiết bị cần đánh giá
    target JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Điều kiện áp dụng rule
    applicability JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Điều kiện kiểm tra
    condition JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Dữ liệu Discovery cần có
    required_evidence JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- Verification and lifecycle
    verification_status VARCHAR(20) NOT NULL DEFAULT 'DRAFT',

    -- Cho phép Normalizer sử dụng mapping ko
    enabled BOOLEAN NOT NULL DEFAULT FALSE,

    -- Trạng thái xét duyệt mapping
    review_note TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_misconfig_mapping_version
        UNIQUE (
            source_id,
            source_file,
            content_sha256,
            mapping_version
        ),

    CONSTRAINT chk_mapping_status
        CHECK (
            verification_status IN (
                'DRAFT',
                'REVIEWED',
                'REJECTED'
            )
        ),

    CONSTRAINT chk_mapping_enabled
        CHECK (
            enabled = FALSE
            OR verification_status = 'REVIEWED'
        ),

    CONSTRAINT chk_mapping_hash
        CHECK (
            content_sha256 ~ '^[0-9a-f]{64}$'
        ),

    CONSTRAINT chk_mapping_target
        CHECK (jsonb_typeof(target) = 'object'),

    CONSTRAINT chk_mapping_applicability
        CHECK (jsonb_typeof(applicability) = 'object'),

    CONSTRAINT chk_mapping_condition
        CHECK (jsonb_typeof(condition) = 'object'),

    CONSTRAINT chk_mapping_evidence
        CHECK (jsonb_typeof(required_evidence) = 'array')
);

CREATE UNIQUE INDEX IF NOT EXISTS
    uq_misconfig_mapping_active
ON vuln_misconfig_rule_mapping (
    source_id,
    source_file
)
WHERE enabled = TRUE;


CREATE TABLE IF NOT EXISTS vuln_misconfig_rule_normalized (
    id BIGSERIAL PRIMARY KEY,

    -- Reference to source rule and mapping
    rule_id BIGINT NOT NULL,
    mapping_id BIGINT NOT NULL,

    -- Source version
    source_revision TEXT,
    content_sha256 TEXT,

    -- Normalized rule metadata
    external_rule_id TEXT,
    title TEXT,
    severity VARCHAR(20),

    -- Normalized evaluation data
    evaluation_type VARCHAR(50),
    target JSONB,
    applicability JSONB,
    condition JSONB,
    required_evidence JSONB,
    result_mapping JSONB,

    -- Full normalized specification
    normalized_rule JSONB,

    -- Rule lifecycle
    execution_status VARCHAR(20) DEFAULT 'NOT_PROCESSED',
    enabled BOOLEAN DEFAULT FALSE,

    -- Additional information
    validation_error TEXT,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vuln_misconfig_finding (
    id BIGSERIAL PRIMARY KEY,
    finding_id UUID NOT NULL UNIQUE,
    scan_id TEXT NOT NULL,
    stage_run_id TEXT NOT NULL,
    device_ip VARCHAR(45) NOT NULL,
    normalized_rule_id BIGINT NOT NULL,
    external_rule_id TEXT,
    title TEXT,
    severity VARCHAR(20),
    evaluation_status VARCHAR(20) NOT NULL,
    reason TEXT,
    evidence JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_misconfig_finding_scan
ON vuln_misconfig_finding (scan_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_misconfig_finding_identity
ON vuln_misconfig_finding (stage_run_id, device_ip, normalized_rule_id);

CREATE INDEX IF NOT EXISTS idx_misconfig_finding_device
ON vuln_misconfig_finding (device_ip);

CREATE TABLE IF NOT EXISTS vuln_risk_result (
    scan_id TEXT NOT NULL,
    stage_run_id TEXT NOT NULL,
    host TEXT NOT NULL,
    risk_score NUMERIC NOT NULL CHECK (risk_score >= 0),
    risk_level VARCHAR(20) NOT NULL,
    finding_count INTEGER NOT NULL,
    scored_count INTEGER NOT NULL,
    recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,
    review_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (stage_run_id, host),
    CHECK (review_status IN ('PENDING', 'APPROVED', 'REJECTED', 'REPORTED'))
);
