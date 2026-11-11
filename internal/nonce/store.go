package nonce

import (
	"errors"
	"sync"
	"time"
)

var errFull = errors.New("nonce store is full")

// Store remembers one-time authorization codes. Clearance cookies are not
// stored here; they are verified statelessly and rechecked against GeoIP.
type Store struct {
	mu    sync.Mutex
	items map[string]time.Time
	max   int
}

func New(max int) *Store {
	if max <= 0 {
		max = 100000
	}
	return &Store{items: make(map[string]time.Time), max: max}
}

func (s *Store) Put(jti string, exp, now time.Time) error {
	if jti == "" || !exp.After(now) {
		return errors.New("invalid nonce")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.items) >= s.max {
		s.sweepLocked(now)
	}
	if len(s.items) >= s.max {
		return errFull
	}
	if _, exists := s.items[jti]; exists {
		return errors.New("nonce collision")
	}
	s.items[jti] = exp
	return nil
}

// Consume returns true only the first time a live nonce is presented.
func (s *Store) Consume(jti string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.items[jti]
	if !ok || !now.Before(exp) {
		delete(s.items, jti)
		return false
	}
	delete(s.items, jti)
	return true
}

func (s *Store) Sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
}

func (s *Store) sweepLocked(now time.Time) {
	for jti, exp := range s.items {
		if !now.Before(exp) {
			delete(s.items, jti)
		}
	}
}
