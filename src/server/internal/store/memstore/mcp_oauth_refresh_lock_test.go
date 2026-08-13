package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMCPOAuthRefreshLockSerializesAndCancels(t *testing.T) {
	m := New()
	connectionID := uuid.New()
	entered, release := make(chan struct{}), make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- m.WithMCPOAuthRefreshLock(context.Background(), connectionID, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	ctx, cancel := context.WithCancel(context.Background())
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- m.WithMCPOAuthRefreshLock(ctx, connectionID, func() error {
			t.Error("same-connection callback entered while lock was held")
			return nil
		})
	}()
	cancel()
	if err := <-secondDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter: %v", err)
	}
	thirdEntered := make(chan struct{})
	thirdDone := make(chan error, 1)
	go func() {
		thirdDone <- m.WithMCPOAuthRefreshLock(context.Background(), connectionID, func() error {
			close(thirdEntered)
			return nil
		})
	}()
	select {
	case <-thirdEntered:
		t.Fatal("same-connection waiter entered before release")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-thirdDone; err != nil {
		t.Fatal(err)
	}
	if len(m.mcpOAuthLocks) != 0 {
		t.Fatalf("lock entry leaked: %+v", m.mcpOAuthLocks)
	}
}

func TestMCPOAuthRefreshLockAllowsDifferentConnections(t *testing.T) {
	m := New()
	firstEntered, release := make(chan struct{}), make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- m.WithMCPOAuthRefreshLock(context.Background(), uuid.New(), func() error {
			close(firstEntered)
			<-release
			return nil
		})
	}()
	<-firstEntered
	secondEntered := make(chan struct{})
	if err := m.WithMCPOAuthRefreshLock(context.Background(), uuid.New(), func() error {
		close(secondEntered)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("different connection was blocked")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestMCPOAuthRefreshLockErrors(t *testing.T) {
	m := New()
	boom := errors.New("boom")
	m.FailNext = boom
	if err := m.WithMCPOAuthRefreshLock(context.Background(), uuid.New(), func() error { return nil }); !errors.Is(err, boom) {
		t.Fatalf("injected error: %v", err)
	}
	if err := m.WithMCPOAuthRefreshLock(context.Background(), uuid.New(), func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("callback error: %v", err)
	}
}
