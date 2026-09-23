# 测试

所有 Go 测试都放在本目录。普通测试使用隔离的工作区临时目录和可控的测试子进程，不运行主程序的全局扫描，也不触碰系统计划任务或服务。

```powershell
go test ./...
go test -race ./tests
```

真实 Kernel Process ETW provider 测试需要从管理员 PowerShell 单独运行：

```powershell
$env:BLOCK_ADS_TEST_LIVE_ETW = '1'
go test ./tests -run '^TestLiveKernelProcessETW$' -count=1 -v
```

该测试使用独立的临时 ETW session 名称和测试子进程。普通权限下 `StartTraceW` 会返回 `Access is denied`，这不代表模拟 ETW 属性解析测试失败。

`codex/removal` 每次推送也会运行 `.github/workflows/removal-p1.yml`，在 Windows runner 上执行普通测试及真实 ETW 测试。只有真实 ETW 运行通过后，路线图第 1.1 项才算完成。
