# 指纹阶段优化 (B+C+E) Implementation Plan

**Goal:** 指纹识别阶段（run_pipeline_all）解决"大量 IP:PORT 时卡死观感"：跨端口组统一并发 + 进度显示 + 同 IP 短路。

**Architecture:** 把当前"端口组间串行、组内并发"改为一个全局任务池：先为每个端口组确定候选 mode（端口匹配），再对所有 (ip,port,mode) 任务统一并发执行；进度用 ui_progress 行刷新；同 IP 一旦命中某服务即跳过其后续端口的探测。

**Tech Stack:** Python 3, concurrent.futures.ThreadPoolExecutor, 现有 ui_* helpers。

## Global Constraints
- 只改 `src/xui.py` 的 `run_pipeline_all` 指纹块；`filter_by_fingerprint`/`filter_unknown_ports_by_title` 保持可用（不删除）。
- A/D 不变：timeout 仍 3s；已知端口 probe 未命中后仍跑通用 title 兜底。
- 端口组→mode 的匹配规则（`port in default_ports`）不变。
- 结果结构 `matched_modes: {mode_id: [(ip,port),...]}` 不变，供 `_run_mode_bruteforce` 消费。
- 失败/异常不得崩溃。

---

### Task 1: 新增进度 helper `ui_progress(done, total, prefix)`
- 有 TTY 且颜色开启：`\r` 覆盖刷新 `prefix 1234/5000 (24%)`
- 非 TTY：每完成 200 条打印一行
- 线程安全（已有 `_UI_LOCK`）

### Task 2: 重写 run_pipeline_all 指纹块为全局并发
1. 构建候选任务计划：
   - for port, ips in port_groups（跳过 exclude_ports）:
     - 找出该 port 对应的 mode 列表 `port_modes`（`port in default_ports` 且不在 exclude_modes）
     - 记录 `plan.append((port, ips, port_modes))`
2. 全局池 `ThreadPoolExecutor(max_workers=32)`，对每个 (port, ip) 提交一个"验证单元"：
   - 依次尝试该 port 的 port_modes 的 probe；命中即返回 (mode_id, ip, port)
   - 若 port_modes 为空或全未命中 → 走通用 title 指纹兜底
3. as_completed 收集，更新进度，写入 `matched_modes`（去重 `(ip,port)`）
4. E 短路：维护 `claimed_ips` set，若某 ip 已命中任一服务，则其后续端口任务直接返回 None（在提交前无法预知，改为收集时忽略 + 提交时检查已 claim 的 ip 跳过）
   - 简化实现：先按 ip 分组，同 ip 的多个 (port) 串行在一个任务内，命中即 break

### Task 3: E 短路（同 IP）
- 把任务单位从 per-(ip,port) 改为 per-ip：一个 ip 的多端口在一个 worker 内按端口顺序探测，一旦某端口命中某服务，记录并 break。

### Task 4: 验证
- py_compile
- 审计
- 推送 VPS + smoke

## Self-Review
- 进度 helper 必须在 `_UI_LOCK` 内写 stdout。
- max_workers=32 可能过多；取 min(32, total_tasks)。
- 通用兜底只在 known 全失败时跑（D 不变=仍跑）。
- 结果去重：同一 (ip,port) 不得重复加入 matched_modes。
- per-ip 短路后，一个 ip 只归一个服务；这与现状"一个 ip 多端口属不同服务"会冲突（如一台机既有 SSH 又有 Alist）——需保留：短路只在"同一 ip 已命中某服务"时跳过*其它端口的探测*，会导致漏掉同机其它服务。**风险点：需与用户确认短路粒度**。
