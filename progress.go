package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type ProgressBar struct {
	Total     int64
	Current   int64
	Width     int
	StartTime time.Time
	mu        sync.Mutex
	done      bool
	lastDraw  time.Time
}

func NewProgressBar(total int64) *ProgressBar {
	return &ProgressBar{
		Total:     total,
		Width:     40,
		StartTime: time.Now(),
		lastDraw:  time.Now(),
	}
}

func (p *ProgressBar) Update(n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Current += n
	p.draw()
}

func (p *ProgressBar) SetCurrent(current int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Current = current
	p.draw()
}

func (p *ProgressBar) Done() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done = true
	p.draw()
	fmt.Println()
}

func (p *ProgressBar) draw() {
	if p.done {
		return
	}

	if time.Since(p.lastDraw) < 100*time.Millisecond {
		return
	}
	p.lastDraw = time.Now()

	percent := float64(p.Current) / float64(p.Total)
	if percent > 1 {
		percent = 1
	}

	filled := int(percent * float64(p.Width))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", p.Width-filled)

	elapsed := time.Since(p.StartTime).Seconds()
	var speed float64
	var eta string
	if elapsed > 0 {
		speed = float64(p.Current) / elapsed
		if speed > 0 && p.Current < p.Total {
			remaining := float64(p.Total-p.Current) / speed
			eta = formatDuration(time.Duration(remaining) * time.Second)
		} else {
			eta = "---"
		}
	} else {
		speed = 0
		eta = "---"
	}

	currentStr := formatSize(p.Current)
	totalStr := formatSize(p.Total)
	speedStr := formatSize(int64(speed)) + "/s"

	fmt.Printf("\r\033[K[%s] %s/%s (%.1f%%) %s ETA: %s",
		bar, currentStr, totalStr, percent*100, speedStr, eta)
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		return "---"
	}
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd%dh%dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
