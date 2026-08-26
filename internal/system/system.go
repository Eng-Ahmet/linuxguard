package system

import (
	"os"
	"runtime"
	"syscall"
	"time"
)

type SystemInfo struct {
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	CPUs        int    `json:"cpus"`
	GoVersion   string `json:"go_version"`
	UptimeSec   uint64 `json:"uptime_sec"`
	MemoryUsed  uint64 `json:"memory_used"`
	MemoryTotal uint64 `json:"memory_total"`
}

var startTime = time.Now()

func GetSystemInfo() *SystemInfo {
	hostname, _ := os.Hostname()

	var sysInfo syscall.Sysinfo_t
	var uptime uint64
	var memUsed, memTotal uint64

	if err := syscall.Sysinfo(&sysInfo); err == nil {
		uptime = uint64(sysInfo.Uptime)
		unit := uint64(sysInfo.Unit)
		if unit == 0 {
			unit = 1
		}
		memTotal = uint64(sysInfo.Totalram) * unit
		memFree := uint64(sysInfo.Freeram) * unit
		memUsed = memTotal - memFree
	}

	return &SystemInfo{
		Hostname:    hostname,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		CPUs:        runtime.NumCPU(),
		GoVersion:   runtime.Version(),
		UptimeSec:   uptime,
		MemoryUsed:  memUsed,
		MemoryTotal: memTotal,
	}
}

func GetAgentUptime() time.Duration {
	return time.Since(startTime)
}
