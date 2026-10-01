//go:build !faultinject

package zserve

import "dnssvc/internal/zmodel"

// 正常构建：传送始终使用入口处取得的同一快照，不重读；不注入故障。
var faultEnabled = false

func (s *Server) axfrSnapshot(snap *zmodel.Snapshot) *zmodel.Snapshot { return snap }

func chunkLimit(dflt int) int { return dflt }
