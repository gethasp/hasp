package reposcan

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const outgoingProgressInterval = 3 * time.Second

// The ticker covers both Git enumeration and a single large object read.
// close joins the writer before the CLI renders its final result.
type outgoingProgress struct {
	scanned atomic.Int64
	mu      sync.Mutex
	output  io.Writer
	total   int
	full    bool
	stop    chan struct{}
	done    chan struct{}
}

func newOutgoingProgress(output io.Writer, full bool) *outgoingProgress {
	p := &outgoingProgress{output: output, total: -1, full: full, stop: make(chan struct{}), done: make(chan struct{})}
	if output == io.Discard {
		close(p.done)
		return p
	}
	if full {
		fmt.Fprintln(output, "warning: no available remote tips limit this push; enumerating all reachable history")
	}
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(outgoingProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-ticker.C:
				p.report()
			}
		}
	}()
	return p
}

func (p *outgoingProgress) enumerated(total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.total = total
	if p.full {
		fmt.Fprintf(p.output, "warning: full-history push scan will read %d Git objects\n", total)
	}
}

func (p *outgoingProgress) report() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.total < 0 {
		fmt.Fprintln(p.output, "hasp: enumerating outgoing Git objects...")
	} else {
		fmt.Fprintf(p.output, "hasp: scanned %d/%d outgoing Git objects\n", p.scanned.Load(), p.total)
	}
}

func (p *outgoingProgress) close() {
	close(p.stop)
	<-p.done
}
