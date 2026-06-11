package service

import (
	"sync"

	"github.com/google/uuid"
)

// keyedMutex hands out a mutex per key so callers can serialise work on a single id without
// serialising across unrelated ids. Entries are reference-counted and dropped when idle, so the
// map does not grow without bound.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[uuid.UUID]*refCountedMutex
}

type refCountedMutex struct {
	mu   sync.Mutex
	refs int
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{locks: make(map[uuid.UUID]*refCountedMutex)}
}

// lock acquires the mutex for key and returns the corresponding unlock function.
func (k *keyedMutex) lock(key uuid.UUID) func() {
	k.mu.Lock()
	m := k.locks[key]
	if m == nil {
		m = &refCountedMutex{}
		k.locks[key] = m
	}
	m.refs++
	k.mu.Unlock()

	m.mu.Lock()
	return func() {
		m.mu.Unlock()
		k.mu.Lock()
		m.refs--
		if m.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
