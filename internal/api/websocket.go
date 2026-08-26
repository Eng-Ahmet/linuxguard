package api

import (
	"encoding/json"
	"net/http"
	"sync"

	"linuxguard/internal/events"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Local dashboard access
	},
}

type Hub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan events.SecurityEvent
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	mu         sync.Mutex
}

func NewHub(eventManager *events.Manager) *Hub {
	h := &Hub{
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan events.SecurityEvent, 100),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
	}

	if eventManager != nil {
		eventManager.Subscribe(func(event events.SecurityEvent) {
			h.broadcast <- event
		})
	}

	return h
}

func (h *Hub) Run() {
	for {
		select {
		case conn := <-h.register:
			h.mu.Lock()
			h.clients[conn] = true
			h.mu.Unlock()

		case conn := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[conn]; ok {
				delete(h.clients, conn)
				conn.Close()
			}
			h.mu.Unlock()

		case event := <-h.broadcast:
			h.mu.Lock()
			data, err := json.Marshal(event)
			if err == nil {
				for conn := range h.clients {
					if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
						conn.Close()
						delete(h.clients, conn)
					}
				}
			}
			h.mu.Unlock()
		}
	}
}

func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	h.register <- conn
}
