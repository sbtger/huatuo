# OOM Runtime 内存切片测试

OOM Runtime 内存切片测试分为快速单元测试、2222 虚拟机真实进程版本矩阵，以及可选的
真实 memcg OOM 系统测试。Provider 测试读取真实 Runtime 内存，不使用模拟快照。

生产 gate 的绝对硬上限是 **50 ms**。VM Provider 用例同样传入 50 ms deadline，并要求
采集函数在该窗口内返回；容器创建、分配、OOM 选择、事件保存和退出 137 的端到端耗时
不等于 gate 时间，必须分别记录。

## 执行入口

```bash
# 只列出测试范围
bash integration/oom_runtime_snapshot_vm.sh --list

# 快速单测和三语言全版本矩阵
make oom-runtime-snapshot-vm-test

# 大量小对象与约 1 GiB 大对象
HUATUO_SNAPSHOT_TEST_PROFILE=extreme make oom-runtime-snapshot-vm-test

# 针对分层采样偏置的混合负载
HUATUO_SNAPSHOT_TEST_PROFILE=mixed make oom-runtime-snapshot-vm-test

# 在 disposable VM 中追加真实 memcg OOM 链路
HUATUO_SNAPSHOT_RUN_MEMCG_OOM=1 make oom-runtime-snapshot-vm-test

# 追加 4 个隔离 memcg 同时 OOM 的风暴与 fail-open 验证
HUATUO_SNAPSHOT_RUN_MEMCG_OOM=1 HUATUO_MEMCG_STORM_CASES=4 \
  make oom-runtime-snapshot-vm-test
```

脚本必须以 root 在 Linux 虚拟机中执行，因为三种 Provider 都通过生产路径读取另一个
进程的内存。默认 Runtime 根目录为 `/opt/huatuo-runtime-matrix`；也可以通过
`HUATUO_GO_<VERSION>`、`HUATUO_PYTHON_<VERSION>`、`HUATUO_JAVA_<VERSION>` 指向
已有安装。缺少版本时执行：

```bash
bash integration/install_oom_runtime_snapshot_runtimes.sh
```

安装脚本写入独立目录，不替换系统的 `go`、`python3` 或 `java`。

## 当前自动化测试列表

| 层级 | 语言或机制 | 当前验证内容 |
|---|---|---|
| 快速单测 | 通用 gate | 1-50 ms 配置边界、ACK cookie、deadline、BPF 释放确认、busy/cooldown、失败退避、部分结果保留和 JSON 合并 |
| 快速单测 | Go | 1.20-1.25 layout、发现、MemProfileRate 外推、两阶段 Top-K、软 deadline 和结果预留 |
| 快速单测 | Python | 3.8-3.14 layout、GC generation、dict/managed values、pymalloc 分层估算、批量流式读取和短窗口预算 |
| 快速单测 | Java | G1 Region 分层、分布前缀、确定性抽样、在线方差、置信区间、Humongous 对象和对象工作量上限 |
| VM 矩阵 | Go 1.20.14-1.25.0 | 外部读取真实 mbuckets；多 goroutine、小对象、大对象和 50 ms 截断 |
| VM 矩阵 | CPython 3.8-3.14 | 外部读取真实 pymalloc/GC；多线程、小对象、大对象和 50 ms 截断 |
| VM 矩阵 | JDK 8/11/17/21/25 | 外部读取真实 HotSpot G1；多线程、小对象、大对象、估算与 50 ms 截断 |
| VM 兼容性 | JDK 21 | 1/16 MiB Region，压缩 oop/klass 开关组合；明确拒绝 Parallel/Serial GC |
| 系统 E2E | Go/CPython/HotSpot | 真实 memcg OOM、退出 137、BPF gate/ACK、`gate_release` 和最终 JSON |
| 系统风暴 | 通用 gate | 多个隔离 memcg 同时 OOM、50 ms fail-open、first-wins、无死锁与结果不串 |

## 三种负载档位

### change

每次相关代码变更使用的快速回归：默认每进程 5 万个小对象、128 个 256 KiB 大对象，
Python 另包含三类不同大小的业务对象。重点检查版本兼容、非空诊断结果和 50 ms 返回。

### extreme

发布前的容量边界：默认 100 万个小对象、4096 个 256 KiB 大对象。允许
`PARTIAL_*`，但必须在 deadline 前返回，并保留已完成样本、覆盖率、估算标记和截断原因。
该档用于发现对象数、Region 数、arena/pool 数、工作内存和输出大小上限问题。

### mixed

专门攻击“顺序扫描或单一前缀看起来准确、实际遗漏热点”的采样漏洞：

- Java 分阶段或交错分配 Hot/Warm/Cold 类型，并混入 filler 与 Humongous 对象；
- Java 在 JDK 21 上重复三次 interleaved Region 用例，避免一次随机命中掩盖偏置；
- Python 使用相近 block size 的 Hot/Warm/Cold 类型，改变 30k/9k/3k 占比；
- 两种语言都验证少数类型没有因地址集中、Region 类型、occupancy 或 size class 被饿死。

当前 mixed 验收阈值：

- Java 预期 Top-K 类型召回率不低于 90%；主要类型 count 和 shallow bytes 误差不高于 20%；
- Python 三个预期类型均应出现；估算结果的单类型 count 误差不高于 20%，占比绝对误差
  不高于 10 个百分点；
- 如果短窗口只能输出 allocator size class，测试必须明确标记这一退化语义，不能伪装成
  Python 类型统计。

`raw_coverage` 只表示实际读取字节或 Region 比例，不单独作为准确率判据。低覆盖率场景
必须同时检查 Top-K 召回、主要类型误差、`estimated`、RSE/置信区间和各 sampling stratum
的 completed/planned 数量。

## 真实 memcg OOM E2E

真实 OOM 测试会故意杀死 cgroup 内进程，因此默认关闭，只能在 disposable VM 执行：

```bash
HUATUO_SNAPSHOT_RUN_MEMCG_OOM=1 \
  bash integration/oom_runtime_snapshot_vm.sh
```

该测试验证：

- Go、CPython、HotSpot victim 最终都被 SIGKILL，容器或进程退出语义不被采集改变；
- admitted 请求输出 `gate_release=ack`，状态为 `COMPLETE` 或 `PARTIAL_*`；
- deadline 或 ACK 未被 BPF 接受时输出 `timeout_or_ack_missed`，已有可信前缀仍保留；
- 原始 OOM JSON 始终存在，增强字段的语言、状态、entries 和 coverage 可解析。

设置 `HUATUO_MEMCG_STORM_CASES=N`（`N >= 2`）后，脚本还会在 Huatuo 存活的情况下并发
启动 N 个隔离 memcg 的 Go victim，等全部就绪后同时触发 OOM。内核单槽 gate 只放行一个
victim，验证：所有 victim 均退出 137；首个被 admitted 的请求输出 `gate_release=ack`，
状态为 `COMPLETE` 或 `PARTIAL_*`；其余并发请求因 gate 被占用或失败 cooldown 输出
`SKIPPED_BUSY` 或 `SKIPPED_COOLDOWN`，`entry_count` 为 0，不会再次扫描；每个 OOM 事件
只关联自己的 victim，跳过事件不会携带其他请求的 cookie、snapshot ID 或 entries。

Provider 版本矩阵不能替代系统 E2E：前者验证远端堆读取，后者验证从
`oom_kill_process`、perf 通知、用户态采集、ACK 到最终 OOM JSON 的完整链路。

## 每次变更与上线前验收

每次 Provider 或 gate 代码变更至少执行：

```bash
go test ./core/events ./internal/memsnap/... -count=1
bash -n integration/oom_runtime_snapshot_vm.sh
bash -n integration/test_oom_runtime_snapshot_memcg.sh
```

合入或发布前执行完整版本矩阵、`extreme`、`mixed` 和真实 memcg OOM。生产灰度前还需要
补齐并记录以下系统级结果，这些不能仅靠普通 `go test` 证明：

1. perf event 投递失败时立即 fail-open；
2. 用户态不消费、ACK 写失败、迟到 ACK 和 Huatuo 异常退出时，gate 在 50 ms deadline
   后释放；
3. tail-call 固定工作量提前耗尽时同样 fail-open，并能区分该原因；
4. 使用 `HUATUO_MEMCG_STORM_CASES` 验证多 memcg OOM 风暴无死锁、无串错；victim
   提前退出、PID 复用和 Huatuo 重启仍需独立故障注入；
5. 在目标生产内核和 cpuset 上量化 50 ms BPF 忙轮询对调度、softirq 和业务 P99/P999
   尾延迟的影响；
6. Huatuo 位于 victim memcg 外且至少有一个独立可调度 CPU；条件不足时保持功能关闭；
7. 长时间 soak 中 Java/Python 持续满足 Top-K 召回不低于 90%、主要类型误差不高于 20%。

只有 Provider 精度通过不代表整体方案已达到生产上线标准。gate fail-open、不改变 OOM
forward progress、目标内核兼容和调度影响是优先级更高的上线门槛。
