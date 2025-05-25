package agent

import (
	"context"
	"sync"
)

// WorkItem represents a unit of work to be processed by a worker
type WorkItem interface {
	Process(ctx context.Context) error
}

// WorkerPool manages a pool of workers to process work items
type WorkerPool struct {
	workChan    chan WorkItem
	resultChan  chan error
	workerCount int
	wg          sync.WaitGroup
}

// NewWorkerPool creates a new worker pool with the specified number of workers
func NewWorkerPool(workerCount int) *WorkerPool {
	if workerCount <= 0 {
		workerCount = 1
	}

	return &WorkerPool{
		workChan:    make(chan WorkItem, workerCount*2),
		resultChan:  make(chan error, workerCount*2),
		workerCount: workerCount,
	}
}

// Start starts the worker pool
func (p *WorkerPool) Start(ctx context.Context) {
	// Start workers
	for i := 0; i < p.workerCount; i++ {
		p.wg.Add(1)
		go p.worker(ctx)
	}
}

// worker processes work items from the work channel
func (p *WorkerPool) worker(ctx context.Context) {
	defer p.wg.Done()

	for {
		select {
		case <-ctx.Done():
			// Context cancelled, stop worker
			return
		case workItem, ok := <-p.workChan:
			if !ok {
				// Channel closed, stop worker
				return
			}

			// Process work item
			err := workItem.Process(ctx)

			// Send result
			select {
			case p.resultChan <- err:
				// Result sent
			default:
				// Result channel full, log and continue
			}
		}
	}
}

// Submit adds a work item to the pool
func (p *WorkerPool) Submit(item WorkItem) {
	p.workChan <- item
}

// Results returns the channel for receiving results
func (p *WorkerPool) Results() <-chan error {
	return p.resultChan
}

// Stop stops the worker pool
func (p *WorkerPool) Stop() {
	close(p.workChan)
	p.wg.Wait()
	close(p.resultChan)
}

// ProcessDomainItem represents a domain to be processed
type ProcessDomainItem struct {
	Domain string
	RunID  int64
	Agent  *Agent
}

// Process implements the WorkItem interface for ProcessDomainItem
func (item *ProcessDomainItem) Process(ctx context.Context) error {
	return item.Agent.processDomain(ctx, item.Domain, item.RunID)
}
