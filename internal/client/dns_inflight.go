// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"sync"
	"time"
)

type dnsInflightManager struct {
	timeout       time.Duration
	cleanupWindow time.Duration
	nextCleanupAt time.Time
	mu            sync.Mutex
	items         map[string]time.Time
}

func newDNSInflightManager(timeout time.Duration) *dnsInflightManager {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cleanupWindow := timeout / 4
	if cleanupWindow < time.Second {
		cleanupWindow = time.Second
	}
	return &dnsInflightManager{
		timeout:       timeout,
		cleanupWindow: cleanupWindow,
		items:         make(map[string]time.Time),
	}
}

func (m *dnsInflightManager) Begin(cacheKey []byte, now time.Time) bool {
	if m == nil || len(cacheKey) == 0 {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := string(cacheKey)
	if m.nextCleanupAt.IsZero() || !now.Before(m.nextCleanupAt) {
		for existingKey, createdAt := range m.items {
			if now.Sub(createdAt) >= m.timeout {
				delete(m.items, existingKey)
			}
		}
		m.nextCleanupAt = now.Add(m.cleanupWindow)
	}

	if createdAt, ok := m.items[key]; ok && now.Sub(createdAt) < m.timeout {
		return false
	}

	m.items[key] = now
	return true
}

func (m *dnsInflightManager) Complete(cacheKey []byte) {
	if m == nil || len(cacheKey) == 0 {
		return
	}

	m.mu.Lock()
	delete(m.items, string(cacheKey))
	m.mu.Unlock()
}
