# 未知端口指纹识别 Implementation Plan

> **For agentic workers:** 按步骤逐项执行，改动集中在 `src/xui.py` + 新增 `config/web_keywords.json`。

**Goal:** 模式 14/16 中，masscan 结果的端口若不在任何服务 config 的 `default_ports` 内，改为跑通用 Web 指纹（抓 `<title>` 关键词）尝试归类，而不是直接跳过。

**Architecture:** 保持"端口对上表 → 按该服务 probe 验证"路径完全不变；仅新增"端口对不上 → 通用 title 指纹"兜底分支。新增独立关键词表与两个函数，不触碰单模式 `run_pipeline()`。

**Tech Stack:** Python 3 stdlib (urllib, re, json, concurrent.futures)。

## Global Constraints

- 只改 `src/xui.py`；新增 `config/web_keywords.json`；不改任何 `mode_XX_*.json`。
- 端口对上表的原有流程行为必须零变化。
- 咸蛋(4)/AIKey(9)/Proxy(13) 本次不动（`default_ports` 保持为空，仍不可达）。
- 通用 title 指纹命中后归入的 mode 需跳过 `exclude_modes`（模式16 即跳过 6/SSH）。
- 失败/缺文件不得导致崩溃，须 `ui_warn` 降级。
- 改动先落本地，`py_compile` 通过 → SFTP 上传 Debian `/root/scan/src/xui.py`。

---

### Task 1: 新增 config/web_keywords.json

**Files:**
- Create: `config/web_keywords.json`

关键词（小写）→ mode_id：

```json
{
  "x-ui": 1,
  "nezha": 2,
  "哪吒": 2,
  "h-ui": 3,
  "s-ui": 5,
  "sub store": 7,
  "openwrt": 8,
  "istoreos": 8,
  "luci": 8,
  "alist": 10,
  "misub": 11
}
```

- [ ] 写入文件，确认 JSON 合法。

---

### Task 2: load_web_keywords() + fingerprint_web_title()

**Files:**
- Modify: `src/xui.py`（在 `fingerprint_scan` 之后、`_fingerprint_check_one` 之前插入；加载函数就近放在 `load_mode_config` 附近）

- [ ] **Step 1: load_web_keywords()** — 读 `config/web_keywords.json`，返回 `{keyword_lower: mode_id}`；文件缺失/解析失败 → `ui_warn` 并返回 `{}`。

- [ ] **Step 2: fingerprint_web_title(ip, port, keywords)** — 返回命中的 `mode_id` 或 `None`：
  - 端口 `443`/`8443` 用 `https://`，否则 `http://`
  - `GET /`，TLS 跳过校验（复用 `fingerprint_probe` 同款 ctx），timeout 3s
  - 抓 `<title ...>(.*?)</title>`（`re.IGNORECASE|re.DOTALL`），strip().lower()
  - 对 `keywords` 逐项 `if kw in title: return mode_id`
  - 任何异常 → `return None`

- [ ] **Step 3: 并发包装 `_web_title_check_one(item, keywords)`** → `(ip, port, mode_id_or_None)`，沿用 `_fingerprint_check_one` 风格。

---

### Task 3: run_pipeline_all 未知端口路由

**Files:**
- Modify: `src/xui.py` 指纹循环（当前 line 1430-1450）

- [ ] **Step 1:** 循环前加载 `web_keywords = load_web_keywords()`。

- [ ] **Step 2:** 每个端口组记录 `matched_this_port = False`；已知服务 `filtered` 非空时置 True（原逻辑不变）。

- [ ] **Step 3:** 若 `not matched_this_port and web_keywords`：对该端口组所有 IP 用 ThreadPool 并发跑 `_web_title_check_one`；命中的 `(ip, port)` 按 `mode_id` 归入 `matched_modes`（跳过 `exclude_modes`）；打印 `ui_info`。

- [ ] **Step 4:** 保持 `if not matched_modes` 早退逻辑不变。

---

### Task 4: 验证

- [ ] 本地 `python -m py_compile src/xui.py` → PY OK
- [ ] 审计（见下）
- [ ] SFTP 上传 Debian + `python3 -m py_compile`
- [ ] mode 16 smoke（141.11.90.0/24 或 156.226.169.0/24），确认未知端口被通用指纹处理且不崩
- [ ] mode 14 smoke，确认 SSH/SubStore 匹配数量与改动前一致

## Self-Review 要点（实现前自查）
1. `fingerprint_scan` 对 `http://ip:port/login` 拼 URL 的写法 → `fingerprint_web_title` 也需同样注意 URL 拼接（不要重复 scheme）。
2. `port_groups` 的 key 是 int（来自 masscan int 解析 / parse_ip_file int），`exclude_ports` 也是 int set —— 类型一致。
3. `matched_modes` 值须为 `(ip,port)` 元组列表，与 `_run_mode_bruteforce` 消费格式一致。
4. 未知端口命中 mode 15 自身？keywords 里不含 15，安全。
5. 大端口组：并发上限复用现有约定（如 12）。
6. 不得把同一 `(ip,port)` 重复加入（已知服务已命中则跳过兜底）。
