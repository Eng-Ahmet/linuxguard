package agent

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"linuxguard/internal/api"
	"linuxguard/internal/config"
	"linuxguard/internal/database"
	"linuxguard/internal/detection"
	"linuxguard/internal/events"
	"linuxguard/internal/filesystem"
	"linuxguard/internal/processes"
	"linuxguard/internal/quarantine"
)

type Agent struct {
	cfg            *config.Config
	db             *database.DB
	eventManager   *events.Manager
	fileMonitor    *filesystem.Monitor
	processMonitor *processes.Monitor
	detectionEng   *detection.Engine
	quarantineMgr  *quarantine.Manager
	baselineEng    *filesystem.BaselineEngine
	apiServer      *api.Server
}

func NewAgent(cfg *config.Config) (*Agent, error) {
	db, err := database.Open(cfg.Database.Path)
	if err != nil {
		return nil, fmt.Errorf("failed initializing database: %w", err)
	}

	eventManager := events.NewManager()

	// Quarantine Manager
	qMgr, err := quarantine.NewManager(cfg.Quarantine.Path, db, eventManager)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed initializing quarantine: %w", err)
	}

	// Scanner & Baseline Engine
	scanner := filesystem.NewScanner(cfg.Monitoring.Paths, cfg.Monitoring.ExcludedPaths)
	baseEng := filesystem.NewBaselineEngine(scanner, db, eventManager)

	// Detection Engine
	detEng := detection.NewEngine(cfg.Detection.Enabled, db, eventManager)

	// Filesystem Monitor
	fsMon, err := filesystem.NewMonitor(cfg.Monitoring.Paths, cfg.Monitoring.ExcludedPaths, eventManager)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed initializing filesystem monitor: %w", err)
	}

	// Process Monitor
	var procMon *processes.Monitor
	if cfg.ProcessMonitor.Enabled {
		procMon = processes.NewMonitor(cfg.ProcessMonitor.IntervalSeconds, eventManager)
	}

	// Server dependencies
	serverDeps := &api.ServerDependencies{
		DB:                db,
		EventManager:      eventManager,
		QuarantineManager: qMgr,
		BaselineEngine:    baseEng,
		Scanner:           scanner,
	}

	apiServer, err := api.NewServer(cfg.Server.Host, cfg.Server.Port, serverDeps)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed initializing web server: %w", err)
	}

	return &Agent{
		cfg:            cfg,
		db:             db,
		eventManager:   eventManager,
		fileMonitor:    fsMon,
		processMonitor: procMon,
		detectionEng:   detEng,
		quarantineMgr:  qMgr,
		baselineEng:    baseEng,
		apiServer:      apiServer,
	}, nil
}

func (a *Agent) Start() error {
	if err := a.fileMonitor.Start(); err != nil {
		return fmt.Errorf("failed starting filesystem monitor: %w", err)
	}

	if a.processMonitor != nil {
		a.processMonitor.Start()
	}

	if err := a.apiServer.Start(); err != nil {
		return fmt.Errorf("failed starting API server: %w", err)
	}

	return nil
}

func (a *Agent) Stop() {
	if a.apiServer != nil {
		_ = a.apiServer.Stop()
	}

	if a.processMonitor != nil {
		a.processMonitor.Stop()
	}

	if a.fileMonitor != nil {
		a.fileMonitor.Stop()
	}

	if a.db != nil {
		_ = a.db.Close()
	}
}

func (a *Agent) RunUntilSignal() {
	if err := a.Start(); err != nil {
		fmt.Printf("Error starting agent: %v\n", err)
		return
	}

	fmt.Printf("LinuxGuard Security Agent active at http://%s:%d\n", a.cfg.Server.Host, a.cfg.Server.Port)
	fmt.Printf("Database: %s | Quarantine: %s\n", a.cfg.Database.Path, a.cfg.Quarantine.Path)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sig := <-sigChan
	fmt.Printf("Signal %v received. Shutting down LinuxGuard cleanly...\n", sig)

	a.Stop()
	fmt.Println("LinuxGuard agent terminated safely.")
}
