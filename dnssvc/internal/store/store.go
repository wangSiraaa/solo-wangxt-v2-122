// Package store 用 PostgreSQL 持久化区域版本与变更日志。
//
// 发布严格走单个事务：锁定区域行 -> 校验序列号递增 -> 写版本快照 ->
// 写变更日志 -> NOTIFY。提交后服务端才会重载，因此查询永远看不到
// 半个版本。
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"dnssvc/internal/zmodel"
)

// Store 是 PostgreSQL 版本库。
type Store struct {
	pool *pgxpool.Pool
}

// New 建立连接池。
func New(ctx context.Context, conn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("连接 PostgreSQL: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("Ping PostgreSQL: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close 关闭连接池。
func (s *Store) Close() { s.pool.Close() }

// VersionInfo 是一个已发布版本。
type VersionInfo struct {
	Version int64
	Serial  uint32
	Records []*zmodel.Record
}

// Change 是变更日志中的一条。
type Change struct {
	Change string // add / del
	RType  string
	RRText string
}

// Published 是 Publish 的返回值。
type Published struct {
	Version   int64
	Serial    uint32
	Changes   []Change
	FirstTime bool // 是否是该区域首次发布
}

// Publish 在单个事务内原子发布新版本。
// serial 必须严格大于当前序列号；recs 必须已经通过 zmodel 校验。
func (s *Store) Publish(ctx context.Context, zone string, recs []*zmodel.Record, serial uint32, author string) (*Published, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("开启事务: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO zones(name) VALUES($1) ON CONFLICT (name) DO NOTHING`, zone); err != nil {
		return nil, err
	}
	// 锁住区域行，串行化并发发布。
	var curVersion *int64
	var curSerial *int64
	row := tx.QueryRow(ctx,
		`SELECT (SELECT max(version) FROM zone_versions WHERE zone=$1),
		        (SELECT serial FROM zone_versions WHERE zone=$1 ORDER BY version DESC LIMIT 1)
		   FROM zones WHERE name=$1 FOR UPDATE`, zone)
	if err := row.Scan(&curVersion, &curSerial); err != nil {
		return nil, fmt.Errorf("锁定区域行: %w", err)
	}

	var oldRecords []*zmodel.Record
	first := curVersion == nil
	if !first {
		if uint64(serial) <= uint64(*curSerial) {
			return nil, fmt.Errorf("序列号必须严格递增：当前 %d，提交 %d", *curSerial, serial)
		}
		var raw []byte
		if err := tx.QueryRow(ctx,
			`SELECT records FROM zone_versions WHERE zone=$1 AND version=$2`,
			zone, *curVersion).Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &oldRecords); err != nil {
			return nil, err
		}
	}

	newVersion := int64(1)
	if curVersion != nil {
		newVersion = *curVersion + 1
	}

	raw, err := json.Marshal(recs)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO zone_versions(zone, version, serial, records, published_by)
		VALUES ($1,$2,$3,$4,$5)`, zone, newVersion, serial, raw, author); err != nil {
		return nil, fmt.Errorf("写入版本: %w", err)
	}

	changes := Diff(oldRecords, recs)
	for _, c := range changes {
		if _, err := tx.Exec(ctx, `
			INSERT INTO zone_changelog(zone, version, serial, change, rtype, rrtext)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			zone, newVersion, serial, c.Change, c.RType, c.RRText); err != nil {
			return nil, fmt.Errorf("写入变更日志: %w", err)
		}
	}

	// 在提交同一事务里发 NOTIFY；只有提交成功监听者才会收到。
	if _, err := tx.Exec(ctx, "SELECT pg_notify('zone_changed', $1)", zone); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("提交发布事务: %w", err)
	}
	return &Published{Version: newVersion, Serial: serial, Changes: changes, FirstTime: first}, nil
}

// Current 返回最新版本；区域尚无版本时返回 (nil,nil)。
func (s *Store) Current(ctx context.Context, zone string) (*VersionInfo, error) {
	var raw []byte
	var v VersionInfo
	err := s.pool.QueryRow(ctx, `
		SELECT version, serial, records FROM zone_versions
		 WHERE zone=$1 ORDER BY version DESC LIMIT 1`, zone).Scan(&v.Version, &v.Serial, &raw)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &v.Records); err != nil {
		return nil, err
	}
	return &v, nil
}

// VersionBySerial 按序列号取版本（IXFR 用）；不存在返回 (nil,nil)。
func (s *Store) VersionBySerial(ctx context.Context, zone string, serial uint32) (*VersionInfo, error) {
	var raw []byte
	var v VersionInfo
	err := s.pool.QueryRow(ctx, `
		SELECT version, serial, records FROM zone_versions
		 WHERE zone=$1 AND serial=$2`, zone, serial).Scan(&v.Version, &v.Serial, &raw)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &v.Records); err != nil {
		return nil, err
	}
	return &v, nil
}

// VersionsBetween 返回版本号 >=from 的全部版本，按版本号升序（IXFR 用）。
func (s *Store) VersionsBetween(ctx context.Context, zone string, from int64) ([]VersionInfo, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT version, serial, records FROM zone_versions
		 WHERE zone=$1 AND version >= $2 ORDER BY version ASC`, zone, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VersionInfo
	for rows.Next() {
		var raw []byte
		var v VersionInfo
		if err := rows.Scan(&v.Version, &v.Serial, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &v.Records); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// HistoryEntry 是历史列表项。
type HistoryEntry struct {
	Version     int64
	Serial      uint32
	PublishedAt string
	By          string
	Changes     int
}

// History 返回区域的发布历史（新版本在前）。
func (s *Store) History(ctx context.Context, zone string) ([]HistoryEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT v.version, v.serial, to_char(v.published_at,'YYYY-MM-DD HH24:MI:SS'),
		       COALESCE(v.published_by,''),
		       (SELECT count(*) FROM zone_changelog c WHERE c.zone=v.zone AND c.version=v.version)
		  FROM zone_versions v WHERE v.zone=$1 ORDER BY v.version DESC`, zone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryEntry
	for rows.Next() {
		var h HistoryEntry
		var serial int64
		if err := rows.Scan(&h.Version, &serial, &h.PublishedAt, &h.By, &h.Changes); err != nil {
			return nil, err
		}
		h.Serial = uint32(serial)
		out = append(out, h)
	}
	return out, rows.Err()
}

// ChangesOf 取某次发布的变更日志。
func (s *Store) ChangesOf(ctx context.Context, zone string, version int64) ([]Change, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT change, rtype, rrtext FROM zone_changelog
		 WHERE zone=$1 AND version=$2 ORDER BY id`, zone, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Change
	for rows.Next() {
		var c Change
		if err := rows.Scan(&c.Change, &c.RType, &c.RRText); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Diff 以完整 RR 文本为键计算两个版本的差异（SOA 不进 IXFR diff）。
func Diff(old, new []*zmodel.Record) []Change {
	oldM := map[string]*zmodel.Record{}
	newM := map[string]*zmodel.Record{}
	for _, r := range old {
		if r.Type != zmodelTypeSOA {
			oldM[r.Text] = r
		}
	}
	for _, r := range new {
		if r.Type != zmodelTypeSOA {
			newM[r.Text] = r
		}
	}
	var out []Change
	for k, r := range oldM {
		if _, ok := newM[k]; !ok {
			out = append(out, Change{Change: "del", RType: typeName(r.Type), RRText: r.Text})
		}
	}
	for k, r := range newM {
		if _, ok := oldM[k]; !ok {
			out = append(out, Change{Change: "add", RType: typeName(r.Type), RRText: r.Text})
		}
	}
	// 排序保证日志顺序稳定：del 在前，随后按文本。
	sortChanges(out)
	return out
}

func sortChanges(c []Change) {
	// 简单插入排序，量很小。
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && changeLess(c[j], c[j-1]); j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
}

func changeLess(a, b Change) bool {
	if a.Change != b.Change {
		return a.Change == "del" // del 排在 add 前
	}
	return strings.Compare(a.RRText, b.RRText) < 0
}
