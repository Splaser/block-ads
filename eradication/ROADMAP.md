# 根除流程路线图

按顺序推进；每项完成后在这里记录测试场景、结果和对应提交。当前实现仍是第一版，case JSON 中的 `status` 只有 `pending`、`review`、`completed`，不能把它当作下述完整状态机。

## 1. 真实命中进程 integration test

- [ ] 用隔离的测试目录和可控测试进程，分别走启动扫描与 ETW 命中。
- [ ] 核对原有 kill/日志与根除队列严格一对一，且原流程行为不变。
- [ ] 覆盖进程在排队前退出、PID 被复用、创建时间缺失、镜像路径或文件 identity 变化。
- [ ] 评估 ETW 事件到 `procHit` 身份快照之间的极短窗口：当前事件没有提供可比较的创建时间，且原始 `fuck` 路径按既有行为执行；需要真实命中测试验证并设计不改变原拦截语义的处理。
- [ ] 覆盖同一文件被多个 PID 命中时，每个命中有独立 case，文件与持久化项只实际处置一次。

## 2. restore round-trip test

- [ ] 真实隔离 EXE/DLL，恢复原路径、哈希和可执行状态。
- [ ] 分别验证 Run/RunOnce、任务 XML、Startup `.lnk` 的备份与恢复；快捷方式需保留 target、arguments、working directory 和原始二进制 metadata。
- [ ] 验证原路径已被其他文件占用时拒绝覆盖，以及重复执行恢复的行为。

## 3. Task / Service 失败与恢复测试

- [ ] 计划任务覆盖引号、参数、`%ENV%`、`cmd /c`、`powershell -File`，及不应匹配的参数/名称。
- [ ] 测试备份失败、删除失败、删除后校验失败以及重复关联多个 case。
- [ ] Service 当前只扫描和备份，标记 `experimental_review`，不自动删除。先设计完整 SCM 配置和状态恢复，再考虑 enable/disable 或删除。

## 4. Crash recovery

- [ ] 在复制、校验、删除原文件、删除持久化项各步骤注入崩溃。
- [ ] 启动时从 plan、case、备份和隔离副本重建进度，避免重复删除或错误恢复。
- [ ] 文件被占用时保持 `pending`；将来若加入 reboot-delete，单独记 `PendingReboot`，直到重启后验证才算完成。

## 5. Case 状态机

- [ ] 明确并持久化 `Detected → Contained → EvidenceCollected → Quarantined → PersistenceRemoved → Verified → RestoreAvailable`。
- [ ] 为每一步定义前置条件、幂等重试和落盘时机；部分失败进入 `PartialFailure`，延迟删除进入 `PendingReboot`。
- [ ] 将 artifact、persistence item 的状态与 case 状态分开，任何失败或未验证删除都不能计为成功。
- [ ] 为 GUI 提供稳定的只读 case API，再接入展示和恢复操作。

## 6. 扩展持久化类型

- [ ] 完成前五项后再评估 WMI、Winlogon、IFEO、COM 等。每新增一种类型都先设计准确关联、完整备份、恢复和失败测试。
