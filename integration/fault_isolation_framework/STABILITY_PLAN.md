# memburst 与 memory_threshold_snapshot 稳定性测试计划

本计划在现有故障隔离框架上验证真实 Agent 的反复触发、目标生命周期、资源退化和故障恢复。短周期与 72 小时使用同一代码路径；本轮只执行虚拟机短测，不据此声明已完成长稳或性能验收。

## 代码与环境

- 工作分支：`feat/memory-snapshot-stability-tests`；原故障隔离分支保留。
- 上游基线：`8a627bdc0`；原两条框架提交已 rebase 为 `4421f0527`、`6f137a535`。
- 实测环境：140 的专用 Linux amd64 虚拟机，cgroup v1、Docker、root，Go/HotSpot/CPython 三个业务。
- 当前仅维护 cgroup v1 执行环境；不支持的环境会失败，不能作为通过项。
- 普通 Agent、故障 Agent、Go 业务、seccomp 启动器均有构建哈希，启动前校验。稳态、预热、生命周期及重启使用普通 Agent；只有显式注入读取/provider 故障和其同进程恢复使用故障 Agent。每个常规 Agent 的进程记录保存实际二进制及哈希，避免用测试 overlay 的资源开销代表发布版本。环境记录保存运行时、内核、命令、BPF/源码/二进制哈希。
- `agent-fault` 通过测试专用 overlay 构建，不修改发布源码。BPF 使用与当前源码匹配的虚拟机编译产物；具体构建过程见本轮验证记录。

## 测试目标与分层

| 测试层 | 目标 | 证据 |
| --- | --- | --- |
| 业务隔离 | 采集失败、Agent 退出及资源故障不导致主业务响应或状态错误 | 每请求 JSONL、独立状态读取、PID 与启动时间、后台 tick |
| 反复功能 | 每次声明的触发确实产生正确目标的事件，冷却和恢复正确 | 原始快照索引、目标 PID、语言、RSS、状态及原因 |
| 生命周期 | 临时容器创建/采集/删除、limit 变化后监听仍可用 | 新 CID/cgroup、原始采集事件、删除结果、逐轮计数 |
| 资源稳定 | 观察资源峰值及同一 Agent 身份下预热后的增长 | 每 2 秒资源 JSONL、预热基线、替换前终点 |
| 执行可靠 | 阶段挂起、丢观察窗口或计划不完整不能 PASS | 独立监督进程、进度检查点、阶段/总时限、审计 |

## 稳定性周期的具体内容

正式周期前，Go、Java、Python 分别执行 Agent-off 压力对照，再分别完成一次正常采集预热。三个主业务保持存活，整个任务中不因场景切换重置状态。临时生命周期业务与主业务分开，不能用其预期退出豁免主业务身份断言。

每个周期包含：

1. 三个运行时分别完成正常采集，其他两个业务持续接受探针检查。
2. 冷却检查：正常采集后回落压力并在冷却窗口内再次制造边沿，要求无额外事件。
3. 临时 Go 容器创建、发现、真实采集、移除，以及 cgroup 消失检查；按 `churn-per-cycle` 重复。
4. 阈值模块修改测试主 Go 容器的 memory limit 后重新触发并采集，恢复原 limit；每周期重复相同次数。此检查验证 limit 改变后的可用性，不声称穷尽阈值与 limit 的所有边界组合。
5. 到达故障周期时，在三个运行时上注入选定故障，各自执行随后恢复；故障按故障周期轮转，所选故障数量超过可执行故障周期会被拒绝。
6. 到达故障周期时，事件写入实际 ENOSPC，然后使用正常存储和新 Agent 验证恢复。
7. 到达重启周期时，奇数周期验证 SIGTERM 正常退出，偶数周期验证 SIGKILL；新 Agent 继续采集原主业务，再次检查恢复。
8. 启用 `resource-faults` 时，分别对测试 Agent 执行真实 RLIMIT_NOFILE=16 的 EMFILE 和独立测试 cgroup 的 OOM，各自重新启动 Agent 并采集；主业务 cgroup 不受这两项资源限制。
9. 回落压力，持续观察至该周期分配的最小时长，保存资源检查点与周期计数。72 小时为最低实际观察时长，场景开销可能使总执行更长。

### 两个模块的差异

| 项目 | memburst | memory_threshold_snapshot |
| --- | --- | --- |
| 触发源 | 真实主机匿名内存变化；Go 业务作为匿名压力驱动 | 真实容器内存阈值通知 |
| 受控参数 | 采样间隔 1 秒、窗口 2 个样本、增幅 1%、匿名占比下限按启动时基线加至少 256 MiB 动态设定、冷却默认 8 秒 | 阈值 60%、超时 3 秒、冷却默认 8 秒、最多 7 条对象条目 |
| 压力 | 主业务 500 MiB 映射；非 Go 目标先达到足够 RSS，再用 Go 匿名压力驱动宿主机触发 | 主业务 500 MiB 映射，容器上限 768 MiB |
| 事件校验 | RSS 排序、前最多三个目标对应关系、目标语言、正常非空快照及 RSS | 容器及目标 PID、语言、正常非空快照及 RSS |
| 规模补充 | `extra-processes` 启动额外真实小堆 Go 进程以增加排名规模 | 同样可启动邻居进程，但不据此宣称多容器同时触发已验证 |

短窗口和较低触发参数用于制造足够可重复事件；不能将结果直接推广为生产默认配置的开销结论。主机匿名触发需要安静的专用虚拟机。用真实内存输入，不替换 `/proc/meminfo`。

### 采集故障矩阵

| 故障 | 命中证据 | 恢复 |
| --- | --- | --- |
| EFAULT | 目标读取边界注入标记 + 持久化 bad address 原因 | 同一个 Agent |
| 短读 | 真实读取后减少返回长度，标记与短读原因一致 | 同一个 Agent |
| Provider panic | 指定目标/阶段标记、恢复日志及失败快照 | 同一个 Agent |
| Context 取消 | 标记与 canceled 失败快照 | 同一个 Agent |
| 延迟超过 deadline | 延迟读取返回后，失败快照为 deadline exceeded | 同一个 Agent；未证明强制中断 syscall |
| 持续阻塞 | 标记、无落盘事件、Agent 指标 HTTP 响应，随后确认 SIGKILL | 替换 Agent |
| 读取完成后杀死 | 完成真实读取的独立标记、无事件，确认 SIGKILL | 替换 Agent |
| 权限拒绝 | seccomp 使真实 process_vm_readv 返回 EPERM，标记及失败原因匹配 | 替换 Agent，seccomp 不可撤销 |
| 存储失败 | 仅测试事件文件指向 `/dev/full`，日志为真实 ENOSPC | 新 Agent 和正常存储 |
| Agent FD 耗尽 | 仅该 Agent 的 RLIMIT_NOFILE，原始日志含 EMFILE | 新 Agent，正常 FD 限制 |
| Agent OOM | 仅测试 Agent 的 cgroup；内核 oom_kill 计数增加且 Agent 以 SIGKILL 退出 | 新 Agent，正常内存限制 |

Go 正常结果必须 complete；Java/Python 可以接受包含正常条目的 documented partial。CPython 仅对 `CPython interpreter GC generations are invalid` 允许最多三次真实采集尝试；保留每次失败与结果，不用重试抹去首次失败。正常 partial 不能作为故障命中证据。

## 通用断言与失败条件

- 主业务进程身份保持不变，不能退出、重启或成为僵尸。
- 每个 `/work` 返回 HTTP 200 与预定 SHA-256 文本；每次序号 n 的更新增加 `13*n`，确认与独立读取均正确。
- 后台 tick 和事务持续推进；保留原有 HTTP 1 秒、进度间隔 2 秒和调度滞后 500 ms 门限，不因故障放宽。这些是测试夹具的挂起门限，不是性能 SLO。
- 固定到达率；计划与完成数量对账；停止并排空在途请求后审计全部流水，阶段间错误同样失败。
- 主业务 memory.failcnt 不增加。预期 OOM 只允许发生在测试 Agent 的独立 cgroup。
- 每个预期故障有准确的目标、动作和阶段标记；恢复必须实际触发并得到正常结果。
- 原始文件 SHA-256、阶段数、请求计数、事件索引与汇总一致；同一事件不能被多个阶段重复充作新采集。
- 未达到最小时长、缺少周期、重复周期、缺资源采样、观察器失败、采样间隔大于 10 秒、清理失败均 FAIL。
- 已建立预热基线的 Agent 必须有增长终点。短命故障启动进程不计入长时间泄漏结论；没有增长窗口的身份不能提供增长验证证据。

### 资源观察与预算

每 2 秒采集 Agent 的 PID/启动时间、RSS、FD、线程数和所处阶段，检查业务观察线程仍存活。同一个 Agent 完成全部选定运行时的正常采集后才建立可比较的预热基线，在替换前建立终点；对同一身份比较，不跨 Agent 重启计算增长。只执行单一故障及恢复的短命 Agent 仍检查绝对资源预算，不提供多运行时增长结论；整轮必须存在已充分预热的增长观察窗口。

默认资源门限为 RSS 512 MiB、FD 512，预热后 RSS 增长 64 MiB、FD 增长 16，可通过参数调整。它们是初始测试保护预算，应结合业务和正常基线校准；不是业界标准或已批准的生产性能上限。

业务请求流保存在磁盘，只保留当前阶段内存记录；最终审计流式处理请求，避免 72 小时全量记录常驻内存。周期检查点只保存 INCOMPLETE 汇总，最终停止/清理后生成完整哈希清单并审计。原始日志保留在输出目录，应提前准备足够磁盘空间。

## 独立监督与清理

父监督进程与场景控制器分离。默认阶段时限短测 180 秒、长稳 900 秒；长稳周期的计划等待单独扩展预算。资源观察文件超过 10 秒没有更新时，监督者独立判失败。总时限可显式指定，超时保存 supervisor FAIL，终止控制器，并依据所有权日志清理本次创建的 Agent 进程组、容器、镜像及测试 cgroup。停止采集后进入有界 finalizing 阶段，允许资源观察器正常关闭；最终哈希和审计仍受阶段/总时限约束。

进程通过 PID 和启动时间验证所有权；PID 被复用时不发信号，并报告无法清理。只清理本次创建且内容未变化的 kubelet 配置。不覆盖既有输出目录，不全局 pkill、不删除其他测试容器、不修改主机 PID 上限或全局 OOM/ptrace 设置。

## 执行命令

从已完成标准生成步骤的 checkout 构建：

```sh
python3 integration/fault_isolation_framework/build.py --repo . --output /tmp/stability-build
python3 -m unittest discover -s integration/fault_isolation_framework -p 'test_*.py'
```

在专用 root 虚拟机中顺序执行两个短测，输出目录必须不存在：

```sh
python3 integration/fault_isolation_framework/stability.py \
  --module memory_threshold_snapshot --profile short \
  --build /tmp/stability-build --bpf-dir "$PWD/bpf" \
  --inject-faults --resource-faults --output /tmp/threshold-short

python3 integration/fault_isolation_framework/stability.py \
  --module memburst --profile short --extra-processes 8 \
  --build /tmp/stability-build --bpf-dir "$PWD/bpf" \
  --inject-faults --resource-faults --output /tmp/memburst-short
```

短测默认 2 周期、每周期 1 轮临时容器替换；阈值模块每周期 1 轮 limit 变化。每周期轮转 EFAULT/短读，包含 SIGTERM/SIGKILL 替换、ENOSPC 和所选资源故障。只验证这些实际执行的场景；不会自动把其他故障标为通过。

后续经资源预算和环境确认后才启动长稳；本轮不执行以下命令：

```sh
python3 integration/fault_isolation_framework/stability.py \
  --module memory_threshold_snapshot --profile soak \
  --build /tmp/stability-build --bpf-dir "$PWD/bpf" \
  --inject-faults --resource-faults --output /tmp/threshold-soak

python3 integration/fault_isolation_framework/stability.py \
  --module memburst --profile soak --extra-processes 100 \
  --build /tmp/stability-build --bpf-dir "$PWD/bpf" \
  --inject-faults --resource-faults --output /tmp/memburst-soak
```

soak 门禁：至少 72 小时、100 周期、每周期默认 10 次临时容器替换；阈值模块再执行同数 limit 变化。默认每 10 周期执行一次故障组，轮转全部八种读取/provider 故障。每个运行时至少 100 次周期正常采集，此外还有生命周期和恢复采集。`extra-processes` 范围为 0–128，应按目标生产进程规模另设阶梯。

重复审计，不重新启动业务：

```sh
python3 integration/fault_isolation_framework/stability.py --audit --output /tmp/threshold-short
python3 integration/fault_isolation_framework/audit.py /tmp/threshold-short/evidence
```

## 输出与验收

| 文件 | 内容 |
| --- | --- |
| `supervisor.json`、`controller.log` | 独立监督结果、退出码、超时/清理错误和控制器日志 |
| `progress.json`、`ownership.jsonl` | 当前阶段、开始时间及本次拥有的资源 |
| `evidence/summary.json`、`audit.json` | 阶段及业务断言、独立完整性审计 |
| `evidence/campaign.json`、`cycles.jsonl` | 最小时长、实际时长、轮次、触发与生命周期计数、范围限制 |
| `evidence/resources.jsonl` | 连续资源记录与预热/终点 |
| 请求 JSONL、Agent 日志/配置/指标、快照事件 | 业务、故障和恢复的原始证据 |
| `environment.json`、`manifest.json`、`registrations.jsonl` | 执行环境、版本、哈希与证据注册清单 |
| `resource-fault-*.json` | Agent EMFILE、内核 OOM 计数和退出原因 |

成功要求 supervisor、summary、audit、campaign 均为 PASS。short 中 `long_soak_verified` 必须为 false，性能评估保持 false。测试不是自动 CI 门禁；需要专用 VM 的任务必须显式启动。

## 当前验证边界与后续项

- 实际 PID 复用单独计数。容器替换不等于 PID 复用；`require-pid-reuse` 在未实际观察到复用时失败，不改全局 PID 设置强行凑数。
- 本轮不跑 72 小时、不计算性能回归百分比。短周期零错误不能推广为生产可用率或长期无泄漏。
- 生命周期辅助目标目前使用 Go；Java/Python 为持续存活的主业务及故障目标。未将主业务的预期重启纳入状态连续性豁免。
- 多目标交替采集已实现；多容器同一时刻触发的竞争专项、运行时不支持专项、阈值所有边界组合需要独立补充验证。
- 外部告警平台和线上止损 API 未接入。现有 Agent 退出/替换与资源清理不等于告警路由和生产黑名单流程已验收。
- cgroup v2、其他内核/JDK/CPython 版本及真实 Kubernetes 控制面未验证；当前 pod API 是本地夹具。
