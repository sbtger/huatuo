# 内存快照稳定性短周期验证记录

This is a historical pre-worker record. Its builds and measurements do not
validate the later dedicated-helper implementation. See
[worker validation](WORKER_VALIDATION.md) for the new scope and open issues.

日期：2026-11-02。对应 [测试计划](STABILITY_PLAN.md)。本次只验证短周期故障隔离与反复采集，不作 72 小时、性能或生产可用率结论。

## 代码与构建

上游 `main` 为 `8a627bdc032ba12d0e83d59a49083b071baa8c9f`，原框架两条提交已 rebase；新增工作在 `feat/memory-snapshot-stability-tests`。执行时为提交前源码，原始 `environment.json` 保存逐文件 SHA-256；不能把较早试跑归为最终源码的执行结果。

BPF 在目标虚拟机使用 clang 18 和对应头文件从当前源码编译，移回构建机执行 ABI、mock、capnp 等标准生成步骤，再构建普通 Agent、故障 overlay Agent、Go 业务与 seccomp 启动器。构建机旧 clang/libbpf 无法直接编译当前 BPF，因此没有复用旧版本对象。生成文件未手工修改，也未提交生成产物。

环境：专用 Linux amd64 虚拟机，内核 `5.10.0-cache-ext-vm-nokmem-8780cdccc1e2`、16 GiB 内存、cgroup v1、Docker API 1.52、Go 1.24.3、HotSpot 17.0.19、CPython 3.12.3。本地 pod API 夹具提供发现信息，不是真实 Kubernetes 控制面。

## 本轮覆盖

每个模块执行两个周期，三个主业务整个任务持续存活，分别执行无 Agent 压力对照及正常采集预热。每周期包括：

- Go/Java/Python 正常采集、目标及快照内容校验、冷却抑制。
- Go 临时容器创建、发现、采集、删除；阈值模块额外变更并恢复内存 limit。
- 第一周期分别注入三个运行时的 EFAULT，第二周期注入短读；每次随后正常采集证明恢复。
- 实际 `/dev/full` ENOSPC 及换回正常存储后的恢复。
- 第一周期 SIGTERM，第二周期 SIGKILL，替换 Agent 后采集原业务。
- Agent 私有限制下的真实 EMFILE、私有 cgroup OOM，分别保存内核/错误证据并恢复。
- 每两秒观察 Agent RSS、FD、线程；同一 Agent 完成全部运行时预热后记录基线，替换前记录终点。

memburst 另带八个真实小堆 Go 邻居进程，增加 RSS 排名规模。使用真实匿名内存变化，未替换 `/proc/meminfo`。正常路径使用普通 Agent，只有显式读取故障及其同进程恢复使用 overlay Agent。

所有阶段同时断言主业务 HTTP 响应及内容、事务序号与累计状态、独立状态读取、后台 tick、PID/启动时间、非僵尸状态和业务 cgroup failcnt。最终独立审计原始请求、事件索引、故障命中、周期计数、资源窗口及 SHA-256，不能仅依据控制器退出码判通过。

## 结果

最终结果见同目录 `STABILITY_RESULTS.json`；该文件为原始证据的精简索引，完整请求、日志、快照、配置、指标和资源流水保留在执行机，不提交到 Git。

| 模块 | 周期/阶段 | 时长（含监督收尾） | 业务 work 请求 | 结果 |
| --- | --- | --- | --- | --- |
| memory_threshold_snapshot | 2 / 48 | 353.079 秒 | 10,416 | PASS |
| memburst | 2 / 46 | 461.823 秒 | 13,677 | PASS |

阈值模块记录 33 次成功正常/恢复采集、2 次临时 cgroup 替换、2 次 limit 变更、20 次 Agent 替换；成功事务共 5,148 次。业务错误、意外 Agent 日志、审计错误和监督清理错误均为零。两个有实际持续观察时长的预热窗口 RSS 分别增长 9.188 MiB、7.574 MiB，FD 增长均为零；另有任务尾部短窗口，不据此推断长期增长。

memburst 记录 31 次成功正常/恢复采集、2 次临时 cgroup 替换、20 次 Agent 替换；成功事务共 6,759 次。业务错误、意外 Agent 日志、审计错误和监督清理错误均为零。主要预热窗口 RSS 增长分别为 16.188 MiB、36.613 MiB，FD 增长均为零。

两个最终目录均通过 `stability.py --audit` 和原 `audit.py` 的独立重审；任务结束后按所有权清单检查无遗留资源。完整原始证据及执行源码归档分别为执行机 `/root/stability-threshold-final2-evidence-20261102.tar.gz`、`/root/stability-memburst-final4-evidence-20261102.tar.gz`，构建主机 `/data1/zp/` 保留副本。归档与精简 JSON 的哈希可用于追查本轮证据；复跑仍需按计划重新构建和执行。

## 试跑中发现的问题

1. 业务夹具最初将后台 tick 与压力分配放在同一执行路径，无法独立观察进度；已改为独立 tick，并在压力分配之间主动让出调度。HTTP、进度及调度滞后门限没有放宽。
2. 容器创建/删除期间存在预期发现窗口日志。仅对本轮临时 CID、准确生命周期窗口和确定原因做白名单，其他 warn/error 仍失败。
3. 较早 memburst 试跑全部 43 阶段通过、业务零错误，但 RSS 增长 76.082 MiB 超过 64 MiB，整轮保留为 FAIL。该基线只经过 Go 预热，终点已包含 Java/Python，不能直接据此判定泄漏。改为同一 Agent 完成三个运行时预热后建基线，门限保持不变。之后也将正常路径切换到普通 Agent，避免 overlay 的开销影响发布版本资源观察。
4. 宿主匿名占比门限过低会在目标进入 RSS 前列前触发。现按启动基线与真实压力预算计算下限，并先确认非 Go 目标 RSS，再驱动匿名突增。

这些修正针对测试夹具、触发和审计，不修改生产采集实现。失败目录保留，不覆盖或删除失败证据。

## 检查与限制

框架自检 77 项通过；`make check` 通过。相关 Go 回归范围为 `internal/memsnapshot/...`、`core/autotracing/...`、`internal/cgroups/memorywatch/...` 及 Go 业务夹具，均通过；未声称运行全仓 Go 测试。

本轮未执行 provider panic、context 取消、deadline、阻塞 syscall、读取后强杀、权限拒绝这些可选扩展故障；其实现与断言需要另行实际执行后才可记为通过。实际 PID 复用没有观察到。未验证 72 小时、性能、其他内核/cgroup v2/运行时版本、同一时刻多容器竞争、生产规模资源争抢、外部告警及线上止损链路。RSS 短窗口通过只说明没有突破本轮预算，不证明长期无泄漏。
