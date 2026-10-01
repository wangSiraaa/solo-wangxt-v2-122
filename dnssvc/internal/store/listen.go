package store

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Listener 监听 zone_changed 通知。通知只可能由“已提交的发布事务”
// 产生（PostgreSQL NOTIFY 在事务提交后才投递），因此不会有回滚的假通知。
type Listener struct {
	pool   *pgxpool.Pool
	zone   string
	notify chan string
}

// NewListener 创建针对特定区域的监听器。
func (s *Store) NewListener(zone string) *Listener {
	return &Listener{pool: s.pool, zone: zone, notify: make(chan string, 16)}
}

// Events 返回事件通道（载荷为区域名）。
func (l *Listener) Events() <-chan string { return l.notify }

// Run 阻塞运行，直到 ctx 取消。连接断开会自动重连重新 LISTEN。
func (l *Listener) Run(ctx context.Context) {
	backoff := time.Second
	for {
		if err := l.runOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("store: 监听连接断开: %v，%s 后重连", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (l *Listener) runOnce(ctx context.Context) error {
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN zone_changed"); err != nil {
		return err
	}

	for {
		// WaitForNotification 在通知到达或连接断开时返回。
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			if errors.Is(err, pgx.ErrTxClosed) || ctx.Err() != nil {
				return ctx.Err()
			}
			var pgconnTimeout *pgconn.PgError
			_ = pgconnTimeout
			return err
		}
		if n.Payload == l.zone {
			select {
			case l.notify <- n.Payload:
			default: // 通道满：合并事件，接收方会直接加载最新版本
				select {
				case l.notify <- n.Payload:
				default:
				}
			}
		}
	}
}
