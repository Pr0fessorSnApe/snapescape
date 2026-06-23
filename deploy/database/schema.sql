-- SNAPESCAPE PostgreSQL Schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(128) UNIQUE NOT NULL,
    email VARCHAR(256) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    role VARCHAR(32) DEFAULT 'analyst',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ
);

CREATE TABLE workspaces (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(256) NOT NULL,
    owner_id UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID REFERENCES workspaces(id),
    target VARCHAR(512) NOT NULL,
    status VARCHAR(32) DEFAULT 'pending',
    phase VARCHAR(64) DEFAULT 'subdomain_discovery',
    progress FLOAT DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    asset_type VARCHAR(64) NOT NULL,
    value TEXT NOT NULL,
    parent TEXT,
    metadata JSONB DEFAULT '{}',
    discovered_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_assets_scan ON assets(scan_id);
CREATE INDEX idx_assets_type ON assets(asset_type);

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    title VARCHAR(512) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    confidence FLOAT DEFAULT 0,
    vuln_type VARCHAR(128),
    url TEXT,
    evidence JSONB DEFAULT '{}',
    cwe VARCHAR(16),
    owasp VARCHAR(16),
    validated BOOLEAN DEFAULT FALSE,
    validation_stages JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);

CREATE TABLE evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    evidence_type VARCHAR(64),
    content JSONB,
    screenshot_path TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    format VARCHAR(16) NOT NULL,
    file_path TEXT NOT NULL,
    generated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(128) NOT NULL,
    details JSONB DEFAULT '{}',
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE workers (
    id VARCHAR(64) PRIMARY KEY,
    status VARCHAR(32) DEFAULT 'idle',
    last_heartbeat TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'
);
