// Package limit throttles failed logins (docs/01 "密码不折磨人，防爆破靠锁定"): every entry
// of keelAuth (web page, LDAP binds, OIDC login) counts failures per source address and per
// account name; after Limit failures in a row the next tries wait Wait, doubling each round
// up to Max. The first wait is announced; while it lasts nothing is checked.
package limit

import (
	"sync"
	"time"
)

const (
	Limit = 5
	Wait  = 5 * time.Minute
	Max   = time.Hour
)

// Limiter keeps the failures.
type Limiter struct {
	mu  sync.Mutex
	m   map[string]*fails
	Now func() time.Time // tests
}

type fails struct {
	n     int
	until time.Time
	wait  time.Duration
}

func (l *Limiter) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// Blocked: how long any of the keys still has to wait (0: none of them).
func (l *Limiter) Blocked(keys ...string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, k := range keys {
		if k == "" {
			continue
		}
		if f := l.m[k]; f != nil && now.Before(f.until) {
			return f.until.Sub(now)
		}
	}
	return 0
}

// Failed counts one failure for each key.
func (l *Limiter) Failed(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]*fails{}
	}
	now := l.now()
	for _, k := range keys {
		if k == "" {
			continue
		}
		f := l.m[k]
		if f == nil {
			f = &fails{}
			l.m[k] = f
		}
		f.n++
		if f.n >= Limit {
			if f.wait == 0 {
				f.wait = Wait
			} else if f.wait < Max {
				f.wait *= 2
			}
			f.until = now.Add(f.wait)
			f.n = 0
		}
	}
	for k, f := range l.m { // forget the old ones
		if f.n == 0 && now.After(f.until.Add(Max)) {
			delete(l.m, k)
		}
	}
}

// OK forgets the keys (a success).
func (l *Limiter) OK(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.m, k)
	}
}
