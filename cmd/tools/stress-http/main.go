// stress-http 是 MxSec Manager HTTP API 压测工具
// 模拟 N 个并发用户持续请求 Manager API，验证读链路（MySQL/ClickHouse → Manager）
//
// 用法：
//
//	go run ./cmd/tools/stress-http \
//	  --base-url http://manager:8080 \
//	  --token <jwt> \
//	  --concurrency 100 \
//	  --duration 3m \
//	  --report-interval 15s
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	baseURL        = flag.String("base-url", "http://manager:8080", "Manager HTTP 地址")
	token          = flag.String("token", "", "JWT Token")
	concurrency    = flag.Int("concurrency", 100, "并发用户数")
	duration       = flag.Duration("duration", 3*time.Minute, "压测时长")
	reportInterval = flag.Duration("report-interval", 15*time.Second, "统计报告输出间隔")
)

// 待压测的端点（仅 GET，无副作用）
var endpoints = []string{
	"/api/v1/hosts",
	"/api/v1/dashboard/stats",
	"/api/v1/alerts",
	"/api/v1/monitor/host?range=1h",
	"/api/v1/results",
}

var (
	totalReqs   int64
	totalErrors int64
	totalBytes  int64
)

func main() {
	flag.Parse()
	if *token == "" {
		log.Fatal("必须提供 --token 参数")
	}

	log.Printf("MxSec Manager HTTP API 压测工具启动")
	log.Printf("目标: %s | 并发: %d | 时长: %v", *baseURL, *concurrency, *duration)
	log.Printf("端点: %v", endpoints)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        *concurrency * 2,
			MaxIdleConnsPerHost: *concurrency * 2,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	ctx := make(chan struct{})
	go func() {
		time.Sleep(*duration)
		close(ctx)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("收到终止信号，正在停止...")
		close(ctx)
	}()

	go reportLoop(ctx)

	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			runWorker(ctx, client, id)
		}(i)
	}

	wg.Wait()
	printFinalReport()
}

func runWorker(ctx chan struct{}, client *http.Client, id int) {
	epIdx := id % len(endpoints)
	for {
		select {
		case <-ctx:
			return
		default:
			ep := endpoints[epIdx]
			epIdx = (epIdx + 1) % len(endpoints)

			req, _ := http.NewRequest("GET", *baseURL+ep, nil)
			req.Header.Set("Authorization", "Bearer "+*token)
			req.Header.Set("Accept", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				atomic.AddInt64(&totalErrors, 1)
				continue
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			atomic.AddInt64(&totalReqs, 1)
			atomic.AddInt64(&totalBytes, n)
			if resp.StatusCode >= 400 {
				atomic.AddInt64(&totalErrors, 1)
			}
		}
	}
}

func reportLoop(ctx chan struct{}) {
	ticker := time.NewTicker(*reportInterval)
	defer ticker.Stop()

	var lastReqs, lastErrors int64
	lastTime := time.Now()

	for {
		select {
		case <-ctx:
			return
		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(lastTime).Seconds()

			reqs := atomic.LoadInt64(&totalReqs)
			errs := atomic.LoadInt64(&totalErrors)
			bytes := atomic.LoadInt64(&totalBytes)

			qps := float64(reqs-lastReqs) / elapsed
			errRate := float64(0)
			if reqs > 0 {
				errRate = float64(errs) / float64(reqs) * 100
			}

			log.Printf("[STATS] 并发: %d | QPS: %.1f req/s | 累计: %d | 错误: %d (%.2f%%) | 流量: %s",
				*concurrency, qps, reqs, errs, errRate, formatBytes(bytes))

			lastReqs, lastErrors, lastTime = reqs, errs, now
			_ = lastErrors
		}
	}
}

func printFinalReport() {
	reqs := atomic.LoadInt64(&totalReqs)
	errs := atomic.LoadInt64(&totalErrors)
	bytes := atomic.LoadInt64(&totalBytes)

	errRate := float64(0)
	if reqs > 0 {
		errRate = float64(errs) / float64(reqs) * 100
	}

	fmt.Println("\n========== HTTP API 压测报告 ==========")
	fmt.Printf("并发用户数  : %d\n", *concurrency)
	fmt.Printf("压测时长    : %v\n", *duration)
	fmt.Printf("总请求数    : %d\n", reqs)
	fmt.Printf("总错误数    : %d\n", errs)
	fmt.Printf("错误率      : %.2f%%\n", errRate)
	fmt.Printf("总流量      : %s\n", formatBytes(bytes))
	if reqs > 0 {
		fmt.Printf("平均 QPS    : %.1f req/s\n", float64(reqs)/duration.Seconds())
	}
	fmt.Println("========================================")

	if errRate > 5.0 {
		fmt.Println("[警告] 错误率超过 5%，请检查 Manager 日志")
		os.Exit(1)
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
