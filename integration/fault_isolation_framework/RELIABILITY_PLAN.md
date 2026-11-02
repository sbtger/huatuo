# 内存快照可靠性补测计划

本计划补充 [稳定性计划](STABILITY_PLAN.md) 的四项 P0 缺口。它验证业务故障隔离、采集任务隔离和同进程运行稳定性；不测性能回归，不执行 72 小时。

## 范围与判定

| 项目 | 执行方式 | 必须满足 |
| --- | --- | --- |
| 同一 Agent 持续采集 | 普通 Agent，20 轮，至少 1800 秒；每轮 Go/Java/Python 分别正常采集，轮间业务探针继续工作 | 全程 PID/启动时间不变；每轮三个运行时都有新事件；正常快照非空；RSS/FD 不突破既有预算，预热后线程增长不超过 16，inotify 监听数量净增长不超过 0；观察和业务流水完整 |
| 目标间故障隔离 | Go 目标注入 EFAULT、延迟、阻塞，分别请求健康 Java/Python 目标采集；三个主业务持续接受探针 | 健康目标使用同一 Agent 成功采集；故障作用于正确目标；延迟/阻塞必须有故障注入读路径的活跃时间窗口覆盖健康请求和完成，不能只检查配置存在 |
| 采集中目标退出 | 新建临时 Go 容器，测试 overlay 在读取前暂停；观察命中后删除该容器，再释放暂停执行真实 syscall | 原始读取返回 ESRCH；退出目标不得产生成功快照；同一 Agent 随后采集仍存活主业务成功；临时容器清理；不重启任何主业务 |
| 完整冷却窗口 | 正常事件后回落再制造边沿，每 250ms 检查事件数，至少连续观察 3 秒并覆盖剩余窗口；过期后再制造边沿 | 冷却内无新增事件，采样不能有超过 1 秒的间隙；冷却后有新正常事件，避免把采集失效误判为抑制成功 |
| 已有可选故障矩阵 | Go/Java/Python 各跑 panic、cancel、delay、block、kill_after_read、permission 及后续恢复；此前 EFAULT/短读已有短测 | 精确命中证据、失败分类、业务状态和恢复符合原框架约束；不把没有实际执行的模式写成通过 |

EFAULT 是瞬时失败，在其节点冷却结束后请求其他目标；该项验证故障作用范围及后续健康目标采集，不声称瞬时 syscall 横跨整个健康采集。延迟与阻塞才要求真正的时间重叠。故障进入/退出标记使用同一虚拟机的 CLOCK_MONOTONIC，与 Python monotonic_ns 对齐。隔离专项的 delay 为有界 30 秒；原故障矩阵的 delay 保持 4 秒。

冷却边界取自原始事件时间：memburst 从触发/入队时刻开始计时，不能从异步快照完成后重新计时；阈值模块使用保存时刻的保守边界。保留 200ms 边界余量；若压力准备耗尽可观察窗口，则测试失败，不能声称已验证抑制。

## 业务隔离与采集隔离分别报告

主业务的 HTTP、内容、事务状态、独立读取、后台 tick、PID/启动时间和 memory.failcnt 断言沿用原门限。业务正常与健康目标采集成功是两个独立结论。离线审计分别输出整体 `status` 和已观测业务的 `business_audit_status`（PASS/FAIL/UNVERIFIED）。即使特性失败导致计划提前中止，仍独立校验请求流水哈希、计数、阶段样本、阶段间错误和业务断言；请求证据缺失或损坏为 UNVERIFIED，不能用空错误列表当成业务通过。整体缺少周期或阶段仍为 FAIL，业务结果不能代替覆盖门禁。`adapter_audit_completed` 表示特性审计是否真正完成，未完成时不把空日志错误列表解释为已验收日志。

阻塞在测试 overlay 的读取边界制造，不等于已经验证内核中不可中断 syscall 的主动取消。真实权限故障仍由 seccomp 拒绝 process_vm_readv；退出竞争在暂停释放后执行真实读取，不直接伪造 ESRCH。

若某个共享 worker 被阻塞，导致健康目标无法在采集期限内完成，专项必须 FAIL，即使全部业务探针正常。它说明采集任务隔离这一更强标准尚未满足，不能改写成业务隔离失败，也不能通过重启 Agent 后的成功掩盖原失败。本次只增加测试，不修改生产调度或中断机制。

## 可复现命令

前置条件和构建方式见 [原计划](STABILITY_PLAN.md)。在专用 root/cgroup v1 虚拟机执行，两个模块不能同时占用同一测试环境。

```sh
# 两个模块分别执行，每个至少 30 分钟；不要复用已有输出目录。
python3 integration/fault_isolation_framework/stability.py \
  --module memory_threshold_snapshot --checks steady --cycles 1 \
  --steady-rounds 20 --steady-seconds 1800 \
  --build /tmp/reliability-build --bpf-dir "$PWD/bpf" \
  --output /tmp/reliability-threshold-steady

python3 integration/fault_isolation_framework/stability.py \
  --module memburst --checks steady --cycles 1 \
  --steady-rounds 20 --steady-seconds 1800 \
  --build /tmp/reliability-build --bpf-dir "$PWD/bpf" \
  --output /tmp/reliability-memburst-steady
```

四个短专项分别使用 `--checks target-exit`、`--checks isolation-efault`、`--checks isolation-delay`、`--checks isolation-block`，并设置 `--cycles 1`。分别运行两个模块、使用不同输出目录，使一个失败不遮住其他场景。每个专项仍包含原有正常周期与加强后的冷却验证。

```sh
# 两个模块分别执行，使用不同输出目录。
python3 integration/fault_isolation_framework/stability.py \
  --module memory_threshold_snapshot --inject-faults --cycles 6 \
  --faults panic,cancel,delay,block,kill_after_read,permission \
  --build /tmp/reliability-build --bpf-dir "$PWD/bpf" \
  --output /tmp/reliability-threshold-matrix
```

按需指定 `--languages` 可以做较小诊断子集，但不能将子集通过写为三运行时通过。本轮计划使用默认 Go/Java/Python。

## 证据与监督

除原输出外，`steady-rounds.jsonl` 保存逐轮 Agent 身份和三种运行时的事件索引；汇总必须与此文件一致。Agent 进程元数据证明 steady 用普通二进制，事件仍逐个审计，不能把同一事件重复当成新结果。独立资源观察器在轮间等待时继续采样；直接统计 fdinfo 内的 inotify 监听条目，不能用 FD 数量替代监听数量。默认线程增长预算为 16、监听净增长预算为 0，均为初始测试预算；缺少所要求的原始字段必须失败。

故障日志包含精确阶段/目标标记，delay/block 另有 READ_ACTIVE/READ_END 单调时钟时间。健康请求时间必须落在活跃读取窗口内，缺少开始标记、读取已结束、Agent 换代或缺健康事件均失败。target-exit 保存真实 READ_RESULT，并独立检查退出目标的原始事件没有成功结果。

父监督保留阶段和总时限；steady 的等待预算根据明确的时长和轮次扩展，其余阶段默认 180 秒。业务观察器不能退出或停止记账。所有资源按所有权清单清理，不全局杀进程、不修改 PID 上限、不改变主业务资源限制。失败目录和执行源码快照保留。

## 暂不扩展的项目

本批不增加同时启用两个模块、多容器同时触发、连续故障风暴、配置全边界、cgroup v2/其他运行时兼容、生产告警止损、性能或 72 小时验收。后续按实际发布支持范围选择；遇到本批发现的具体风险再增加回归用例。

普通单目标采集前回落全部测试压力源，防止上一目标持续高压干扰本次控制边沿；新 Agent 启动前也必须回落压力，避免自动启动采集先消耗冷却。延迟/阻塞专项等待节点冷却后发起健康请求，但故障读取仍处于活跃窗口。正常/恢复采集失败时，在清理前保存真实 cgroup usage/limit/stat、控制值、进程状态及 Agent fdinfo，不能把写入 500MiB 控制值当成实际压力已达标。

本轮扩展故障按每个模式单独使用 `--inject-faults --cycles 1 --faults MODE` 执行三个运行时，避免某个失败遮住剩余模式。失败目录始终保留。

压力控制文件通过同目录临时文件和原子替换发布，避免服务读到截断后的空值。原始 producer100 的阈值 steady 失败已确认出现此读取竞争；修复后的 producer105 与旧执行快照分别保留，旧失败不覆盖。具体执行结论、业务审计和已知问题见 [补测报告](RELIABILITY_VALIDATION.md) 与 [定位记录](RELIABILITY_DIAGNOSIS.md)。
