-- 区域版本与变更日志的持久化结构。
-- 一个区域对应多行版本；每次发布在一个事务里写入新版本+变更日志+NOTIFY。

CREATE TABLE IF NOT EXISTS zones (
    name        TEXT PRIMARY KEY CHECK (name = lower(name) AND name LIKE '%.'),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS zone_versions (
    zone        TEXT NOT NULL REFERENCES zones(name),
    version     BIGINT NOT NULL,
    serial      BIGINT NOT NULL CHECK (serial >= 0 AND serial <= 4294967295),
    records     JSONB NOT NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (zone, version),
    UNIQUE (zone, serial)
);

-- 变更日志：本次发布相对上一版本的每条差异。
CREATE TABLE IF NOT EXISTS zone_changelog (
    id          BIGSERIAL PRIMARY KEY,
    zone        TEXT NOT NULL REFERENCES zones(name),
    version     BIGINT NOT NULL,
    serial      BIGINT NOT NULL,
    change      TEXT NOT NULL CHECK (change IN ('add','del')),
    rtype       TEXT NOT NULL,
    rrtext      TEXT NOT NULL,
    logged_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_changelog_zone_ver ON zone_changelog(zone, version);
