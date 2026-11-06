package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

// TestOAuthStateSweepOnce verifies a single sweep removes only expired states.
func TestOAuthStateSweepOnce(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	u := uuid.New()
	_ = ms.InsertOAuthState(ctx, &store.OAuthState{State: "old", Provider: "p", OwnerUserID: u, ExpiresAt: time.Now().Add(-time.Minute)})
	_ = ms.InsertOAuthState(ctx, &store.OAuthState{State: "new", Provider: "p", OwnerUserID: u, ExpiresAt: time.Now().Add(time.Minute)})

	s := NewOAuthStateSweeper(ms, nil, 0)
	s.sweepOnce(ctx)

	if g, _ := ms.GetOAuthStateByState(ctx, "old"); g != nil {
		t.Fatal("expired state should be reaped")
	}
	if g, _ := ms.GetOAuthStateByState(ctx, "new"); g == nil {
		t.Fatal("live state should remain")
	}
}

// TestOAuthStateSweepOnceError covers the DeleteExpiredOAuthStates error branch (swallowed, no panic).
func TestOAuthStateSweepOnceError(t *testing.T) {
	ms := memstore.New()
	ms.FailNext = errors.New("delete failed")
	s := NewOAuthStateSweeper(ms, nil, time.Minute)
	s.sweepOnce(context.Background()) // must not panic; error is logged and swallowed
	if ms.FailNext != nil {
		t.Fatal("sweep should have consumed the failing call")
	}
}

// TestOAuthStateSweeperRunCancel drives the Run loop: a tiny initial delay and interval let one sweep
// reap the expired row, then ctx cancellation returns from the loop.
func TestOAuthStateSweeperRunCancel(t *testing.T) {
	orig := initialOAuthStateSweepDelay
	t.Cleanup(func() { initialOAuthStateSweepDelay = orig })
	initialOAuthStateSweepDelay = time.Millisecond

	ctx := context.Background()
	ms := memstore.New()
	_ = ms.InsertOAuthState(ctx, &store.OAuthState{State: "old", Provider: "p", OwnerUserID: uuid.New(), ExpiresAt: time.Now().Add(-time.Minute)})

	s := NewOAuthStateSweeper(ms, nil, time.Millisecond)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { s.Run(runCtx); close(done) }()

	deadline := time.After(2 * time.Second)
	for {
		if g, _ := ms.GetOAuthStateByState(ctx, "old"); g == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("sweep did not run")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestOAuthStateSweeperRunCancelBeforeFirstSweep covers the ctx.Done branch during the initial delay.
func TestOAuthStateSweeperRunCancelBeforeFirstSweep(t *testing.T) {
	orig := initialOAuthStateSweepDelay
	t.Cleanup(func() { initialOAuthStateSweepDelay = orig })
	initialOAuthStateSweepDelay = time.Hour // long enough that cancel wins the race

	s := NewOAuthStateSweeper(memstore.New(), nil, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return when cancelled during initial delay")
	}
}
