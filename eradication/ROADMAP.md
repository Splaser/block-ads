# 根除流程路线图

按顺序推进，每项完成后记录测试场景、结果和提交。当前已有共享 artifact 归属记录，但正式状态机、操作日志和持续验证尚未实现。先把前六项验证扎实，再扩展检测范围。

## 1. HitEvent / integration correctness

当前进度：`tests/` 中的可控子进程、模拟 ETW 属性、身份拒绝、双 PID 共享文件及恢复归属测试已通过。真实 Kernel Process ETW provider 测试在 Windows workflow 上通过，覆盖真实进程事件、HitEvent 和 case 的一对一追溯；本机非管理员会话仍无法启动 ETW session。加载 DLL 的进程在隔离、恢复、重启后再次命中并产生新 case；尚待原 `fuck` 日志的系统级回归和真实 PID 复用压力。

### 1.1 Event correctness：ETW / startup scan → HitEvent

- [x] 使用隔离目录与可控测试进程，分别触发启动扫描和 ETW，核对事件的 PID、父 PID、创建时间、镜像路径、文件 identity、规则、来源和时间戳。
- [x] 定义“唯一”的边界：同一次原始命中产生一条带 ID 的 HitEvent；20 秒进程 gate 与同 ID 入队去重分别测试，多个 PID 命中同一文件保留不同事件。
- [ ] 核对原有 kill/日志与 HitEvent 严格一对一，且原流程行为不变。
- [x] 覆盖排队前退出、创建时间缺失、模拟 PID 复用后的创建时间不符、镜像路径或文件 identity 变化。真实 PID 复用压力测试仍包含在上一条真实 ETW 验收中。
- [ ] 评估 ETW 事件到 `procHit` 身份快照之间的窗口：当前事件没有可比较的创建时间，原始 `fuck` 路径仍按既有行为执行。通过真实命中测试记录这个边界，再设计不改变原拦截语义的处理。

### 1.2 Remediation correctness：HitEvent → 处置

- [x] 同 ID HitEvent 在单次运行中只入队一次；已退出进程通过创建时间校验，不产生第二次文件修改。跨重启队列恢复留待第 3 项。
- [x] 多个 PID 命中同一文件时，每个命中保留独立 case，artifact 与持久化项只实际处置一次；并发排队、共享归属与恢复后进程重启重新命中均有测试。
- [x] 测试分别断言 HitEvent 数量、case 数量和实际文件隔离次数；对同 ID 重复提交及不同 PID 命中同一文件分别断言。
- [x] 持久化 artifact ownership：多个 case 引用同一隔离记录；关联 case 先释放引用，owner 在其他引用释放后才能恢复。恢复后共享记录与 owner case 一起更新。
- [x] 稳定 `artifact_id` 使用 `SHA256 + 规范化原路径 + 文件 identity`；哈希尚不可用时用路径与文件 identity 查找已隔离记录。同路径被替换、同内容但不同文件 identity 不合并。

## 2. Quarantine + restore round-trip

当前进度：真实 EXE 已完成隔离、恢复及重新启动验证；本机测试已让命中进程加载无签名 DLL，随后自动隔离并恢复 EXE/DLL，Windows workflow 验证待完成。Run/RunOnce 与 Task Scheduler 的真实往返测试在 Windows workflow 上通过，Startup `.lnk` 在隔离目录内完成真实快捷方式往返测试。

- [ ] 真实隔离 EXE/DLL，恢复原路径、哈希和可执行状态；覆盖同一 artifact 被多个 case 引用时的恢复协调。本机测试已通过，等待 Windows workflow 验证真实加载 DLL 的自动隔离。
- [x] 验证原路径已被其他文件占用时拒绝覆盖，包括相同哈希占位文件和检查后竞态；重复隔离与重复恢复通过共享归属和恢复测试验证。
- [x] 分别验证 Run/RunOnce、任务 XML、Startup `.lnk` 的备份与恢复；快捷方式保留 target、arguments、working directory 和原始二进制 metadata。
- [x] 在 [ROUND_TRIP.md](ROUND_TRIP.md) 记录各步骤 crash 后可能观察到的状态与当前不能自动恢复的窗口，作为第 3 项 journal 的输入。

## 3. Crash semantics / Action Journal

- [ ] 为每个 destructive step 定义 `落盘 intent → 执行动作 → 验证结果 → 落盘 committed state`；明确文件同步和原子写入边界。
- [ ] 持久化按序操作日志，记录操作 ID、case/artifact 引用、动作、前置条件、结果、错误和时间。示例：`quarantine_copy=success`、`hash_verify=success`、`delete_original=failed: sharing violation`、`remove_task=skipped`。
- [ ] 在复制、哈希校验、删除原件、清除持久化项、写入 committed state 之前和之后分别注入崩溃。
- [ ] 启动时从 intent、journal、case、备份与隔离副本重建进度；先验证实际外部状态，再决定继续、回滚或等待人工处理，避免重复删除。
- [ ] 被占用文件保持 `pending`；将来若加入 reboot-delete，单独记录 `PendingReboot`，重启后验证前不能记为已删除。

## 4. Task / Service 失败与恢复

- [ ] 计划任务覆盖引号、参数、`%ENV%`、`cmd /c`、`powershell -File`，以及不应匹配的参数或名称；在真实 Task Scheduler 中验证 XML round-trip。
- [ ] 注入备份失败、删除失败、删除后验证失败，验证 journal、case 与恢复行为；覆盖多个 case 关联同一任务。
- [ ] Service 继续只扫描和备份，保持 `experimental_review`，不自动 disable 或 delete。
- [ ] 如将来考虑服务处置，先完成 SCM round-trip：start type、delayed auto start、dependencies、service account、failure actions、description、SID type、required privileges、trigger start、binary path 及当前运行状态；注册表导出本身不足以证明可恢复。

## 5. Formal case + artifact state machine

- [ ] 明确并持久化 case 流程：`Detected → Contained → EvidenceCollected → Quarantined → PersistenceRemoved → PendingVerification → Verified → RestoreAvailable`。
- [ ] 分别定义 case、共享 artifact、持久化项及 remediation ownership 的状态与转移；部分失败进入 `PartialFailure`，延迟删除进入 `PendingReboot`。
- [ ] 每次转移引用对应的 Action Journal 记录，定义前置条件、落盘时机、重试与恢复规则；最终状态不能替代操作历史。
- [ ] 任一失败、未验证删除或未完成恢复都不能计为成功；为 GUI 和诊断提供可解释的状态来源。

## 6. Post-clean verification

- [ ] 在处置后立即核对原 EXE/DLL 不存在、命中进程已退出、精确关联的 Run/Task/Startup 未重建；服务继续只记录 `experimental_review`。
- [ ] 设置有界观察窗口，检查文件、进程和持久化项是否重生；记录重生时间与关联的 updater/watchdog/helper 证据。仅凭一次文件不存在不能进入 `Verified`。
- [ ] 在许可且具备可归因数据时观察 payload 下载或重新释放迹象；网络活动本身不能单独证明与命中软件有关。
- [ ] 重启后再次验证文件、进程和持久化项；若无法自动完成，case 保持 `pending_verification` 并明确需要人工复查。
- [ ] 将每次验证的范围、时间、结果和证据写入 Action Journal；全部必要检查通过后才转入 `Verified`，复现则进入 `PartialFailure` 或新一轮有归属的处置。

## 7. GUI read-only API

- [ ] 提供稳定的只读 case、artifact 和 journal API；先展示进度、证据、失败原因和恢复可用性，再设计 GUI 恢复操作。
- [ ] GUI 与主分支改动合并后接入，避免让界面直接推断 JSON 文件中的临时实现细节。

## 8. 扩展持久化类型

- [ ] 前七项稳定后再评估 WMI、Winlogon、IFEO、COM 等。每新增一种类型，都先设计准确关联、完整备份、恢复、失败测试和 journal 操作。
