package zserve

import (
	"sync/atomic"

	"dnssvc/internal/zmodel"
)

// holder 用原子指针持有“当前版本”。
// 发布 = 构造完整的新 Snapshot 后一次 Store；任何请求拿到的
// 要么是旧快照，要么是新快照，绝不可能是半个版本。
type holder struct {
	cur atomic.Pointer[zmodel.Snapshot]
}

func (h *holder) load() *zmodel.Snapshot { return h.cur.Load() }

func (h *holder) store(s *zmodel.Snapshot) { h.cur.Store(s) }
