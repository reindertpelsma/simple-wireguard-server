package main

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	authRateLimitFailureWindow = 15 * time.Minute
	authRateLimitBaseDelay     = 1 * time.Second
	authRateLimitMaxDelay      = 1 * time.Minute
	authRateLimitFreeFailures  = 5
)

type authAttemptEntry struct {
	Failures    int
	LastFailure time.Time
	BlockUntil  time.Time
}

type authAttemptLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]authAttemptEntry
}

var authLimiter = &authAttemptLimiter{
	now:     time.Now,
	entries: make(map[string]authAttemptEntry),
}

func (l *authAttemptLimiter) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = make(map[string]authAttemptEntry)
	l.now = time.Now
}

func (l *authAttemptLimiter) blocked(keys ...string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	var retry time.Duration
	blocked := false
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		entry, ok := l.entries[key]
		if !ok {
			continue
		}
		if now.Sub(entry.LastFailure) > authRateLimitFailureWindow && !entry.BlockUntil.After(now) {
			delete(l.entries, key)
			continue
		}
		if entry.BlockUntil.After(now) {
			blocked = true
			if wait := entry.BlockUntil.Sub(now); wait > retry {
				retry = wait
			}
		}
	}
	return retry, blocked
}

func (l *authAttemptLimiter) recordFailure(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		entry := l.entries[key]
		if now.Sub(entry.LastFailure) > authRateLimitFailureWindow {
			entry = authAttemptEntry{}
		}
		entry.Failures++
		entry.LastFailure = now
		if entry.Failures >= authRateLimitFreeFailures {
			delay := authRateLimitBaseDelay
			for i := authRateLimitFreeFailures; i < entry.Failures && delay < authRateLimitMaxDelay; i++ {
				delay *= 2
				if delay > authRateLimitMaxDelay {
					delay = authRateLimitMaxDelay
				}
			}
			entry.BlockUntil = now.Add(delay)
		}
		l.entries[key] = entry
	}
}

func (l *authAttemptLimiter) clear(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key != "" {
			delete(l.entries, key)
		}
	}
}

func authRateLimitIPKey(r *http.Request) string {
	return "ip:" + strings.TrimSpace(clientIPForRequest(r))
}

func authRateLimitUserKey(username string) string {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return ""
	}
	return "user:" + username
}

func authRateLimitTOTPKey(userID uint) string {
	return "totp:" + strconv.FormatUint(uint64(userID), 10)
}

func requireAuthRateLimit(w http.ResponseWriter, keys ...string) bool {
	retry, blocked := authLimiter.blocked(keys...)
	if !blocked {
		return true
	}
	if retry < time.Second {
		retry = time.Second
	}
	w.Header().Set("Retry-After", strconv.FormatInt(int64((retry+time.Second-1)/time.Second), 10))
	http.Error(w, "Too many authentication attempts", http.StatusTooManyRequests)
	return false
}
