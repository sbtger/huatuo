# Memsnapshot worker 故障隔离验证

日期：2026-11-02—2026-11-03。生产边界见 [worker 设计与部署](../../docs/memsnapshot-worker.md)，
通用业务断言见 [可靠性计划](RELIABILITY_PLAN.md)。本记录仅评价故障隔离；
性能、真实内核 D-state 和 72 小时长稳不在通过结论内。

## 验证目标

验证 Go/Java/Python 内存采集失败时，业务仍能正确响应、提交并保留状态；
Agent 保持可用，并能在同一进程中继续采集健康目标。允许失败快照和显式
busy/unavailable，不允许把失败包装成成功或无限创建替代 worker。

生产代码将运行时识别、provider、符号解析和进程内存读取移入一次性 helper。
两个固定 cgroup 槽各限制 256 MiB，总限制 512 MiB；请求、响应、stderr 和 FD
分别有上限。截止时间覆盖启动、传输、执行、解析及进程完成；槽位直到 Wait
和 IO 清理完成才释放。超时后父进程不再同步补读 procfs。

## 环境与执行层次

| 层次 | 环境 | 评价范围 |
| --- | --- | --- |
| 真实 Agent/业务 | Linux 5.10、cgroup v1、16 vCPU/16 GiB、Docker | 两种触发器、Go 1.24.3、HotSpot 17.0.19、CPython 3.12.3 |
| 原生进程/cgroup | Linux 5.10、cgroup v1 | IPC、回收、限额、重启残留、所有权 |
| 原生进程/cgroup + race | Linux 7.2-rc2、cgroup v2、4 vCPU/6 GiB | 相同进程边界和真实 memory controller；不代表完整 Agent v2 E2E |
| 构建/控制测试 | Go 1.24.3、Python 3.9 | 相关 Go 包、框架证据审计、标准 helper release 参数 |

本地 pod API 夹具提供发现数据，不是真实 Kubernetes 控制面。业务保持正常
GC 和分配；Python 仅对已知且准确匹配的 GC 元数据竞态允许最多三次采集，
保留每次失败，不能借重试掩盖其他错误。

## 原生故障矩阵

- 无返回、提前退出、超长/损坏 JSON、错误版本/身份、尾随数据：拒绝响应并回收。
- 两个槽同时忙：第三次请求显式失败；一个槽超时后另一个槽仍可完成采集。
- helper 实际分配 400 MiB：由 256 MiB cgroup 限额触发内核 OOM，目标进程
  保持存活，下一次采集正常；用内核计数与进程退出证明，不能只看 memory.failcnt。
- 同一 cgroup inode 上第二个 manager 被锁拒绝；重启处理残留的已知 helper。
- 外来进程、伪造 argv、未知根子组及槽内嵌套子组：拒绝约束或发送信号。
- 实际 helper 在 exec 后的 RLIMIT_NOFILE 软/硬上限均为 128。
- 父进程 stderr 写入阻塞：Close 可以超时，但不能提前释放共享 lease。
- 真实 Go 快照使用普通 helper；真实 provider panic 使用单独标识的 fault helper，
  保持合法 JSON、failed 原因、运行时和内存元数据。
- 目标退出后恢复真实 process_vm_readv：必须观察 ESRCH。
  整个容器退出会先取消 collector，该路径另断言取消、回收和同 Agent 恢复。

stderr 洪水用例写入 2 MiB，仅向父日志转发 64 KiB，继续排空剩余内容并完成
合法响应；不能通过停止读取 stderr 来实现字节上限。

这些测试包含模拟不返回的用户态 reader；没有制造真实不可中断内核任务。
真实 D-state 下 SIGKILL 不保证立即退出，设计保证继续占用原槽而不无限扩容。

## 真实 Agent 矩阵和业务断言

EFAULT、长延迟和模拟阻塞检查故障目标失败后，同一 Agent 继续完成其他健康
运行时采集。六模式矩阵分别对三个运行时注入 panic、context cancel、delay、
block、读取完成后停住、seccomp EPERM，并检查恢复。seccomp 不可逆，权限
拒绝后的恢复需要替换 Agent；其他 worker 故障不能靠重启 Agent 才恢复。

所有阶段持续断言 HTTP 响应内容、事务序号/累计状态、独立状态读取、后台 tick、
业务 PID/启动时间、非僵尸及 cgroup OOM 计数。除场景阶段外也审计完整原始业务
请求，不能仅用采集成功、控制器退出码或 Agent 存活判断通过。

worker PID/启动时间、请求 ID、启动/回收原始日志、故障注入时间、failed 事件
文件及索引、后续正常采集必须相互匹配。替换 failed 记录、遗漏阶段、修改文件、
加入意外 warn/error/panic/fatal 都应失败。资源观察包含父 Agent 与采样到的子
worker，保留分别的值；子进程已完成 CPU 时间另由回收日志记录。采样峰值不是
严格瞬时峰值，不据此推导性能开销。

## 结果

五个最终任务均整体通过；总体仍标记 **PARTIAL**，保留一次未定位的历史
limit-change 超时，不将后续通过等同于已修复该问题。
精简索引见 [WORKER_RESULTS.json](WORKER_RESULTS.json)。

| 模块 | 故障格/阶段 | 时长（含监督收尾） | work 请求 | 整轮 |
| --- | --- | --- | --- | --- |
| memburst | 18 / 102 | 1181.408 秒 | 35,223 | PASS |
| memory_threshold_snapshot | 18 / 108 | 920.843 秒 | 27,420 | PASS |
| threshold 同 Agent 20 轮/30 分钟 | — / 16 | 1919.788 秒 | 57,369 | PASS |
| memburst 最终隔离 + 5 次生命周期 | — / 18 | 328.305 秒 | 9,675 | PASS |
| threshold 最终隔离 + 5 次生命周期/limit | — / 19 | 275.853 秒 | 8,088 | PASS |

五轮合计 263 个阶段、137,775 次 work 请求，业务错误、意外 Agent 日志、
证据错误及清理错误均为零。30 分钟阶段实际观察 1800.005 秒，20 轮均由普通
Agent 的同一 PID/启动时间 `[205016, 2864615]` 完成，三个运行时每轮都有正常
采集；不是通过轮流重启 Agent 拼接观察窗口。

另核对最终三个 threshold 任务的 12 次 limit 变更事件，memory_max 均为 734,003,200
字节（700 MiB）。该后验字段核对与此前的超时失败分别保留。

memburst 的 11,386 条资源记录中有 12 次子进程采样不可用，threshold 的
8,835 条中有 4 次；其余三个任务合计 5 次。均保留原因，父 Agent 样本不丢失，
资源错误记录为零。
这些是采样数据，不将不可用的子进程内存当成已证明为零。

构建发生在提交前，原始 build.json 保留基线提交号。用归档基线与构建前补丁
重建源码，11,371 个受 Git 管理的非测试 Go 文件与 e74db8395 逐字节一致；
执行的冻结框架 62 个 Python 文件也与该提交一致。索引记录对应证明文件哈希，
不能将二进制内嵌的旧 VCS 信息改成当前提交号。

原生 worker 测试在 v1/v2 各通过 15 个顶层测试（包含协议控制，均开启 race，
没有跳过）。OOM 原始计数在 v1 的故障槽为 oom_kill=1，v2 为 oom_kill=2；
这里只据此证明该槽发生内核 OOM kill，不将计数解释为业务进程死亡。目标身份
和后续正常采集均通过断言。标准 helper release 参数构建和真实 Go 快照 smoke
通过；本轮未构建并运行完整 RPM/Docker 发布镜像。

五个最终任务复制到构建主机后，在 Python 3.9 下通过 stability.py 和 audit.py
两个入口的重审，与保留的原始 producer verdict 一致。137 项框架控制测试通过。
producer v7 与兼容性修复后的 auditor v8 分别冻结并记录哈希。

按 16 份所有权清单检查 301 个资源，无原有测试进程/容器/镜像遗留。固定
worker 根及两个槽保留且为空，读回限额分别为 512/256/256 MiB。
不得将中间试跑归为最终构建，也不得将完整性审计失败改记为通过。

## 本轮发现并处理的问题

1. 可执行文件最初按文本审计导致 ELF 解码失败。新增 binary artifact 格式，
   仍验证非空及 SHA-256，替换二进制的负向控制必须失败。
2. 容器删除先取消 worker，原用例错误要求继续读出 ESRCH。现在分别证明容器
   退出取消和直接读已退出进程，避免把没有执行的 syscall 记为已验证。
3. 测试 overlay 的 select{} 会触发最小 helper 的 Go deadlock 检测。改为定时器
   循环模拟不返回，保留截止时间、回收和异常日志反向断言。
4. 实际 provider panic 的默认日志写入 stdout，污染协议。生产 helper 在处理
   请求前将日志输出设为 stderr；真实故障 helper 回归已完成 RED→GREEN。
5. 一次 limit-change 未触发采集而超时；业务状态通过，整轮保持 FAIL。
   增加临时 watch/admission 日志后连续三轮通过；之后普通构建又通过
   12 次 limit 字段核对。原因仍未确定，不能据此宣称该间歇性问题已修复。

6. 通用阻塞故障路径绕过正常 capture()，未在失败事件落盘后更新测试的冷却
   起点，导致恢复压力在生产冷却期内被抑制。原始 worker 回收时间与恢复
   压力窗口证明了时序错误；框架按实际落盘时刻更新起点，控制测试已
   RED→GREEN，生产冷却逻辑未改。

7. 退出中的 helper 在身份读取后丢失 mm，/proc/status 不再含 VmRSS，旧观察器
   将此误报为整条资源采样失败。现在只将缺失 RSS 的子进程样本标为不可用，
   保留 PID 和原因及完整父 Agent 样本；父 Agent 缺失数据和其他字段异常
   仍失败。新增控制测试已 RED→GREEN，资源预算没有放宽。

8. 复制数据在 Python 3.9 重审时，一处日志归因直接用 fromisoformat 解析
   Go 的纳秒时间而报错；改为复用已有兼容解析入口。回归同时断言正确
   CID/时间窗/原因才放行，另外三种情况仍拒绝，已 RED→GREEN。

保留 8 轮原始失败。stdout 污染的两轮原始业务审计亦为 FAIL：操作抛错后没有
返回 fault_hits，记录了 fault was not reached；原始 work/事务错误字典为空。
不修改其 FAIL，也不将这两轮计入通过请求数。

完整 make unit 在构建主机仍有两个已知环境失败：
core/metrics.TestIOCostObject 的 BPF NULL 夹具编译，以及 internal/bpf 初始化
权限；相关 memsnapshot/autotracing/Agent 包通过，不能称全仓测试通过。

## 结论边界与未验证项

发现、触发、RSS 排名和落盘仍在 Agent；本实现隔离的是运行时识别、provider、
符号解析和采集读取，不能将此解释为全部 Agent 代码已隔离。

shell 在自身首次 exec 后入组，再 exec Go helper；限额覆盖 Go helper 的启动
及后续执行，不保证首次 fork/exec 就已原子入组。首次 exec 之前的内核挂起、
真实 D-state、全机/祖先 cgroup 资源耗尽和 CPU/IO 争抢不在本轮通过结论内。

本轮未重跑 worker 改造后的真实 Agent OOM/FD 耗尽，也未执行 memburst 的
同 Agent 30 分钟驻留、72 小时长稳或正式性能评估。历史稳定性/性能记录对应
各自记录的旧构建，不能当作本次 worker 版本的新结果。

## 复跑

先用标准构建准备匹配的 BPF/生成依赖，再运行框架 build.py。普通 Agent、
fault Agent 和两种 helper 都必须转移，不能只复制主 Agent。

```sh
python3 integration/fault_isolation_framework/build.py --repo . --output /tmp/worker-build
python3 -m unittest discover -s integration/fault_isolation_framework -p 'test_*.py'

# 每个模块单独、顺序执行，输出目录必须新建。
python3 integration/fault_isolation_framework/stability.py \
  --module memburst --profile short --build /tmp/worker-build \
  --bpf-dir "$PWD/_output/bpf" --output /tmp/worker-memburst-matrix \
  --cycles 6 --duration-seconds 0 --inject-faults --fault-every 1 \
  --faults block,kill_after_read,permission,panic,cancel,delay

python3 integration/fault_isolation_framework/stability.py \
  --module memory_threshold_snapshot --profile short --build /tmp/worker-build \
  --bpf-dir "$PWD/_output/bpf" --output /tmp/worker-threshold-steady \
  --checks steady --steady-rounds 20 --steady-seconds 1800 \
  --cycles 1 --duration-seconds 0

python3 integration/fault_isolation_framework/stability.py \
  --audit --output /tmp/worker-memburst-matrix
python3 integration/fault_isolation_framework/audit.py /tmp/worker-memburst-matrix/evidence
```

threshold 故障矩阵使用相同六模式参数，将 module 改为 memory_threshold_snapshot。
最终定向任务选择 isolation-efault,isolation-delay,isolation-block,target-exit，
cycles=1、churn-per-cycle=5；分别对两个模块执行。

原始配置、请求、快照、日志、指标、资源样本、构建、执行源码与失败尝试保留在
构建主机 `/data1/zp/huatuo-worker-evidence-20261102/`。Git 只保存方案与精简索引，
不提交原始二进制和大批量快照；归档哈希见结果索引。
