package processes

import (
	"fmt"
	"os/user"
	"strconv"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

type ProcessInfo struct {
	PID       int32     `json:"pid"`
	PPID      int32     `json:"ppid"`
	Name      string    `json:"name"`
	ExePath   string    `json:"exe_path"`
	Cmdline   string    `json:"cmdline"`
	User      string    `json:"user"`
	CPU       float64   `json:"cpu"`
	Memory    float32   `json:"memory"`
	StartTime time.Time `json:"start_time"`
}

// GetRunningProcesses collects a current snapshot of all active processes.
func GetRunningProcesses() ([]*ProcessInfo, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed fetching processes: %w", err)
	}

	var list []*ProcessInfo
	for _, p := range procs {
		info := GetProcessDetails(p)
		if info != nil {
			list = append(list, info)
		}
	}
	return list, nil
}

// GetProcessDetails safely extracts details for a single process.
func GetProcessDetails(p *process.Process) *ProcessInfo {
	name, _ := p.Name()
	exe, _ := p.Exe()
	cmd, _ := p.Cmdline()
	ppid, _ := p.Ppid()
	createTime, _ := p.CreateTime()

	username := "unknown"
	uids, err := p.Uids()
	if err == nil && len(uids) > 0 {
		u, err := user.LookupId(strconv.Itoa(int(uids[0])))
		if err == nil {
			username = u.Username
		} else {
			username = strconv.Itoa(int(uids[0]))
		}
	}

	cpuPercent, _ := p.CPUPercent()
	memPercent, _ := p.MemoryPercent()

	var startTime time.Time
	if createTime > 0 {
		startTime = time.Unix(createTime/1000, 0)
	} else {
		startTime = time.Now()
	}

	return &ProcessInfo{
		PID:       p.Pid,
		PPID:      ppid,
		Name:      name,
		ExePath:   exe,
		Cmdline:   cmd,
		User:      username,
		CPU:       cpuPercent,
		Memory:    memPercent,
		StartTime: startTime,
	}
}
