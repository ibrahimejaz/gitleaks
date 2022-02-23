package detect

import (
	"fmt"
	"sync"
	"time"
)

type RegexTiming struct {
	data map[string]time.Duration
	mu   sync.Mutex
}

func (r *RegexTiming) Add(regex string, duration time.Duration) {
	r.mu.Lock()
	r.data[regex] = r.data[regex] + duration
	r.mu.Unlock()
}

func (r *RegexTiming) Report() {
	for k, v := range r.data {
		fmt.Printf("| %-40s | %-20s |\n", k, v)
	}
}

func NewTimer() *RegexTiming {
	return &RegexTiming{data: make(map[string]time.Duration)}
}

var timings RegexTiming
var fileTimings RegexTiming

func init() {
	timings = *NewTimer()
	fileTimings = *NewTimer()
}
