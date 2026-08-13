package memstore

import (
	"context"

	"github.com/google/uuid"
)

type mcpOAuthRefreshLock struct {
	permit chan struct{}
	refs   int
}

// WithMCPOAuthRefreshLock serializes refresh work for one connection without holding the data lock.
func (m *Mem) WithMCPOAuthRefreshLock(ctx context.Context, connectionID uuid.UUID, fn func() error) error {
	m.mu.Lock()
	if err := m.fail(); err != nil {
		m.mu.Unlock()
		return err
	}
	entry := m.mcpOAuthLocks[connectionID]
	if entry == nil {
		entry = &mcpOAuthRefreshLock{permit: make(chan struct{}, 1)}
		entry.permit <- struct{}{}
		m.mcpOAuthLocks[connectionID] = entry
	}
	entry.refs++
	m.mu.Unlock()

	select {
	case <-entry.permit:
	case <-ctx.Done():
		m.releaseMCPOAuthRefreshLock(connectionID, entry, false)
		return ctx.Err()
	}
	defer m.releaseMCPOAuthRefreshLock(connectionID, entry, true)
	return fn()
}

func (m *Mem) releaseMCPOAuthRefreshLock(connectionID uuid.UUID, entry *mcpOAuthRefreshLock, held bool) {
	if held {
		entry.permit <- struct{}{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry.refs--
	if entry.refs == 0 {
		delete(m.mcpOAuthLocks, connectionID)
	}
}
