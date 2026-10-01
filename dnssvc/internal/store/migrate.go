package store

import (
	"context"
	"fmt"
	"os"
)

// Migrate 执行指定 SQL 文件（schema 初始化）。
func (s *Store) Migrate(ctx context.Context, path string) error {
	sqlBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取 schema %s: %w", path, err)
	}
	if _, err := s.pool.Exec(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("执行 schema: %w", err)
	}
	return nil
}
