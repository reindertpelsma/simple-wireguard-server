package main

import (
	"sync"
	"time"
)

type PeerTrafficPoint struct {
	Timestamp     time.Time `json:"timestamp"`
	ReceiveBytes  uint64    `json:"receive_bytes"`
	TransmitBytes uint64    `json:"transmit_bytes"`
	TotalBytes    uint64    `json:"total_bytes"`
	ReceiveDelta  uint64    `json:"receive_delta"`
	TransmitDelta uint64    `json:"transmit_delta"`
	TotalDelta    uint64    `json:"total_delta"`
}

type trafficSnapshot struct {
	ReceiveBytes  uint64
	TransmitBytes uint64
	Timestamp     time.Time
}

type trafficTracker struct {
	mu      sync.RWMutex
	maxAge  time.Duration
	history map[string][]PeerTrafficPoint
	last    map[string]trafficSnapshot
}

func newTrafficTracker(maxAge time.Duration) *trafficTracker {
	return &trafficTracker{
		maxAge:  maxAge,
		history: make(map[string][]PeerTrafficPoint),
		last:    make(map[string]trafficSnapshot),
	}
}

func (t *trafficTracker) Record(peers []Peer, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := now.Add(-t.maxAge)
	seen := make(map[string]struct{}, len(peers))

	for _, peer := range peers {
		if peer.PublicKey == "" {
			continue
		}

		seen[peer.PublicKey] = struct{}{}
		previous, hasPrevious := t.last[peer.PublicKey]

		receiveDelta := peer.ReceiveBytes
		transmitDelta := peer.TransmitBytes
		if hasPrevious {
			if peer.ReceiveBytes >= previous.ReceiveBytes {
				receiveDelta = peer.ReceiveBytes - previous.ReceiveBytes
			}
			if peer.TransmitBytes >= previous.TransmitBytes {
				transmitDelta = peer.TransmitBytes - previous.TransmitBytes
			}
		}

		point := PeerTrafficPoint{
			Timestamp:     now,
			ReceiveBytes:  peer.ReceiveBytes,
			TransmitBytes: peer.TransmitBytes,
			TotalBytes:    peer.ReceiveBytes + peer.TransmitBytes,
			ReceiveDelta:  receiveDelta,
			TransmitDelta: transmitDelta,
			TotalDelta:    receiveDelta + transmitDelta,
		}

		history := append(t.history[peer.PublicKey], point)
		t.history[peer.PublicKey] = trimTrafficHistory(history, cutoff)
		t.last[peer.PublicKey] = trafficSnapshot{
			ReceiveBytes:  peer.ReceiveBytes,
			TransmitBytes: peer.TransmitBytes,
			Timestamp:     now,
		}
	}

	for publicKey, history := range t.history {
		if _, ok := seen[publicKey]; !ok {
			trimmed := trimTrafficHistory(history, cutoff)
			if len(trimmed) == 0 {
				delete(t.history, publicKey)
				delete(t.last, publicKey)
				continue
			}
			t.history[publicKey] = trimmed
		}
	}
}

func (t *trafficTracker) History(publicKey string) []PeerTrafficPoint {
	t.mu.RLock()
	defer t.mu.RUnlock()

	history := t.history[publicKey]
	out := make([]PeerTrafficPoint, len(history))
	copy(out, history)
	return out
}

func trimTrafficHistory(history []PeerTrafficPoint, cutoff time.Time) []PeerTrafficPoint {
	keepFrom := 0
	for keepFrom < len(history) && history[keepFrom].Timestamp.Before(cutoff) {
		keepFrom++
	}
	if keepFrom == 0 {
		return history
	}
	if keepFrom >= len(history) {
		return nil
	}
	trimmed := make([]PeerTrafficPoint, len(history)-keepFrom)
	copy(trimmed, history[keepFrom:])
	return trimmed
}
