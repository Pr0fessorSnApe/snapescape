package pipeline

import (
	"context"
	"fmt"
	"sync"
	"time"

	"snapescape/go-worker/internal/queue"
	"snapescape/go-worker/internal/scanner"
)

type Executor struct {
	queue    *queue.RedisQueue
	workerID string
	scanner  *scanner.NativeScanner
}

func NewExecutor(q *queue.RedisQueue, workerID string) *Executor {
	return &Executor{
		queue:    q, workerID: workerID,
		scanner: scanner.NewNativeScanner(),
	}
}

func (e *Executor) Execute(ctx context.Context, task *queue.Task) queue.Result {
	result := queue.Result{
		TaskID: task.ID, ScanID: task.ScanID, Phase: task.Phase,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		WorkerID: e.workerID, Data: make(map[string]interface{}),
	}

	e.queue.Publish(ctx, queue.TelemetryChan, fmt.Sprintf(
		`{"scan_id":"%s","event":"task_start","phase":"%s","worker_id":"%s"}`,
		task.ScanID, task.Phase, e.workerID,
	))

	var err error
	switch task.Phase {
	case "http_probe", "http":
		hosts, _ := task.Payload["hosts"].([]interface{})
		var results []map[string]interface{}
		for _, h := range hosts {
			for _, scheme := range []string{"https", "http"} {
				url := fmt.Sprintf("%s://%v", scheme, h)
				if r, e := e.scanner.ProbeURL(ctx, url); e == nil {
					results = append(results, r)
					break
				}
			}
		}
		result.Data["results"] = results
		result.Success = true
	case "port_scan":
		ports := []int{80, 443, 8080, 8443, 22, 21, 3306, 5432, 6379, 27017}
		open := e.scanner.PortScan(ctx, task.Target, ports, 200)
		result.Data["open_ports"] = open
		result.Success = true
	case "dns", "subdomain_discovery":
		ips, e := e.scanner.DNSResolve(ctx, task.Target)
		err = e
		if err == nil {
			result.Data["ips"] = ips
			result.Success = true
		}
	default:
		// Full scan phases handled by Python orchestrator
		result.Success = true
		result.Data["delegated"] = "python-orchestrator"
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
	}

	e.queue.Publish(ctx, queue.TelemetryChan, fmt.Sprintf(
		`{"scan_id":"%s","event":"task_complete","success":%t,"worker_id":"%s"}`,
		task.ScanID, result.Success, e.workerID,
	))
	return result
}

type WorkerPool struct {
	executor    *Executor
	concurrency int
	wg          sync.WaitGroup
}

func NewWorkerPool(executor *Executor, concurrency int) *WorkerPool {
	return &WorkerPool{executor: executor, concurrency: concurrency}
}

func (p *WorkerPool) Start(ctx context.Context) {
	for i := 0; i < p.concurrency; i++ {
		p.wg.Add(1)
		go p.workerLoop(ctx, fmt.Sprintf("%s-%d", p.executor.workerID, i))
	}
}

func (p *WorkerPool) workerLoop(ctx context.Context, consumer string) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			task, msgID, err := p.executor.queue.Dequeue(ctx, consumer)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				time.Sleep(time.Second)
				continue
			}
			if task == nil {
				continue
			}
			result := p.executor.Execute(ctx, task)
			p.executor.queue.PublishResult(ctx, result)
			p.executor.queue.Ack(ctx, msgID)
		}
	}
}

func (p *WorkerPool) Wait() { p.wg.Wait() }
