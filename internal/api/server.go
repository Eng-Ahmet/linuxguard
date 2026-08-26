package api

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"time"
)

//go:embed web/*
var embeddedWebFS embed.FS

type Server struct {
	server *http.Server
	hub    *Hub
	deps   *ServerDependencies
}

func NewServer(host string, port int, deps *ServerDependencies) (*Server, error) {
	mux := http.NewServeMux()
	hub := NewHub(deps.EventManager)

	// API Endpoints
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/system", handleSystem)
	mux.HandleFunc("/api/events", handleGetEvents(deps))
	mux.HandleFunc("/api/threats", handleGetThreats(deps))
	mux.HandleFunc("/api/processes", handleGetProcesses)
	mux.HandleFunc("/api/files", handleGetFiles(deps))
	mux.HandleFunc("/api/quarantine", handleQuarantine(deps))
	mux.HandleFunc("/api/quarantine/", handleQuarantineActions(deps))
	mux.HandleFunc("/api/baseline/create", handleBaselineCreate(deps))
	mux.HandleFunc("/api/baseline/check", handleBaselineCheck(deps))

	// WebSocket Endpoint
	mux.HandleFunc("/ws/events", hub.ServeWS)

	// Static Web Dashboard (embedded)
	webSubFS, err := fs.Sub(embeddedWebFS, "web")
	if err == nil {
		fileServer := http.FileServer(http.FS(webSubFS))
		mux.Handle("/", fileServer)
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return &Server{
		server: httpServer,
		hub:    hub,
		deps:   deps,
	}, nil
}

func (s *Server) Start() error {
	go s.hub.Run()
	ln, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("failed binding server address %s: %w", s.server.Addr, err)
	}

	go func() {
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			// server closed
		}
	}()

	return nil
}

func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}
