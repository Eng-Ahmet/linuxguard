package events

import (
	"sync"
)

type EventListener func(event SecurityEvent)

type Manager struct {
	mu        sync.RWMutex
	listeners []EventListener
}

func NewManager() *Manager {
	return &Manager{
		listeners: make([]EventListener, 0),
	}
}

func (m *Manager) Subscribe(listener EventListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, listener)
}

func (m *Manager) Publish(event SecurityEvent) {
	m.mu.RLock()
	listenersCopy := make([]EventListener, len(m.listeners))
	copy(listenersCopy, m.listeners)
	m.mu.RUnlock()

	for _, listener := range listenersCopy {
		go listener(event)
	}
}
