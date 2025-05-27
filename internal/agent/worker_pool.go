package agent

import (
	"context"
	"fmt"
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
	ctx         context.Context // Store context to allow clean shutdown
	cancel      context.CancelFunc
	mu          sync.Mutex // For thread-safe operations
	isRunning   bool
}

// NewWorkerPool creates a new worker pool with the specified number of workers
func NewWorkerPool(workerCount int) *WorkerPool {
	if workerCount <= 0 {
		workerCount = 1
	}

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		workChan:    make(chan WorkItem, workerCount*2),
		resultChan:  make(chan error, workerCount*2),
		workerCount: workerCount,
		ctx:         ctx,
		cancel:      cancel,
		isRunning:   false,
	}
}

// Start starts the worker pool
func (p *WorkerPool) Start(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.isRunning {
		return // Already running
	}

	// Create a derived context from the provided one
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.isRunning = true

	// Start workers
	for i := 0; i < p.workerCount; i++ {
		p.wg.Add(1)
		go p.worker(p.ctx)
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
			case <-ctx.Done():
				// Context cancelled, don't send result
				return
			case p.resultChan <- err:
				// Result sent
			}
		}
	}
}

// Submit submits a work item to the pool
func (p *WorkerPool) Submit(item WorkItem) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.isRunning {
		return fmt.Errorf("worker pool is not running")
	}

	select {
	case p.workChan <- item:
		return nil
	default:
		return fmt.Errorf("worker pool is full")
	}
}

// Results returns the channel for receiving results
func (p *WorkerPool) Results() <-chan error {
	return p.resultChan
}

// Stop stops the worker pool and waits for all workers to finish
func (p *WorkerPool) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.isRunning {
		return // Already stopped
	}

	// Cancel context to stop workers
	p.cancel()

	// Close work channel
	close(p.workChan)

	// Wait for all workers to finish
	p.wg.Wait()

	// Close result channel
	close(p.resultChan)

	p.isRunning = false
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
