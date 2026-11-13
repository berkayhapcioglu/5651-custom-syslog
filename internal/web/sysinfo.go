package web

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// sysInfo is the host resource view (Linux /proc; zero values elsewhere).
type sysInfo struct {
	CPUs       int
	CPUPercent float64 // whole host, last sample
	Load1      float64
	Load5      float64
	MemTotal   int64
	MemUsed    int64
	ProcRSS    int64 // this service
	Goroutines int
	HaveProc   bool
}

func (m sysInfo) MemPercent() float64 {
	if m.MemTotal == 0 {
		return 0
	}
	return 100 * float64(m.MemUsed) / float64(m.MemTotal)
}

// level classifies a percentage for the status cards.
func level(p float64) string {
	switch {
	case p >= 90:
		return "err"
	case p >= 75:
		return "warn"
	}
	return "ok"
}

type cpuSampler struct {
	mu      sync.Mutex
	percent float64
	prevAll uint64
	prevIdl uint64
}

func readCPU() (all, idle uint64, ok bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	line, _, _ := bytes.Cut(b, []byte("\n"))
	f := strings.Fields(string(line))
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, false
	}
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		all += n
		if i == 3 || i == 4 { // idle, iowait
			idle += n
		}
	}
	return all, idle, true
}

func (c *cpuSampler) sample() {
	all, idle, ok := readCPU()
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.prevAll != 0 && all > c.prevAll {
		da, di := all-c.prevAll, idle-c.prevIdl
		c.percent = 100 * float64(da-min(di, da)) / float64(da)
	}
	c.prevAll, c.prevIdl = all, idle
}

func (c *cpuSampler) run(ctx context.Context) {
	c.sample()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.sample()
		}
	}
}

func (c *cpuSampler) get() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.percent
}

func meminfo() (total, avail int64, ok bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, found := strings.Cut(sc.Text(), ":")
		if !found {
			continue
		}
		fs := strings.Fields(v)
		if len(fs) == 0 {
			continue
		}
		n, _ := strconv.ParseInt(fs[0], 10, 64)
		switch k {
		case "MemTotal":
			total = n * 1024
		case "MemAvailable":
			avail = n * 1024
		}
	}
	return total, avail, total > 0
}

func procRSS() int64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			f := strings.Fields(l)
			if len(f) >= 2 {
				n, _ := strconv.ParseInt(f[1], 10, 64)
				return n * 1024
			}
		}
	}
	return 0
}

func (s *Server) sysInfo() sysInfo {
	m := sysInfo{CPUs: runtime.NumCPU(), Goroutines: runtime.NumGoroutine(), CPUPercent: s.cpu.get()}
	if total, avail, ok := meminfo(); ok {
		m.HaveProc = true
		m.MemTotal, m.MemUsed = total, total-avail
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 2 {
			m.Load1, _ = strconv.ParseFloat(f[0], 64)
			m.Load5, _ = strconv.ParseFloat(f[1], 64)
		}
	}
	m.ProcRSS = procRSS()
	if m.ProcRSS == 0 {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		m.ProcRSS = int64(ms.Sys) // #nosec G115 -- memory size fits in int64
	}
	return m
}
