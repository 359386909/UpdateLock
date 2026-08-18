# 版本说明

## 未发布

- 新增仅适用于 Windows 10 的“禁止升级到 Windows 11”与独立恢复功能。
- 自动识别当前真实 Windows 10 功能版本，按 Build、`DisplayVersion`、`ReleaseId` 交叉校验；未知 Build 拒绝写入。
- 新功能仅写入 `ProductVersion`、`TargetReleaseVersion`、`TargetReleaseVersionInfo`，不改动现有自动更新策略或服务控制。
- 新增独立备份 `%ProgramData%\UpdateLock\windows11-upgrade-backup-v1.txt`，保留原始存在性、类型和值，恢复成功后才删除备份。
- Windows 7 和 Windows 11 上新功能按钮灰显，底层调用同样零写入。

## 2.1.0

在 2.0 基础上加强 Windows 10/11 的手动更新入口封锁，不重复改动既有控制逻辑：

- 新增 `SetDisableUXWUAccess=1`，关闭 Windows Update 页面中的手动检查、下载和安装入口。
- 状态检测新增“Windows Update 手动访问”项目，只有原有自动更新策略和访问封锁全部生效才显示完全关闭。
- 新增 `%ProgramData%\UpdateLock\windows-update-access-backup-v1.txt`，独立保存并恢复访问策略原值。
- 原六项 `policy-backup-v1.txt` 格式保持不变，继续兼容 2.0 备份。
- 新增访问策略备份解析、恢复和状态组合测试。
- 程序文件版本和产品版本统一修正为 `2.1.0.0`。

注意：本版仍禁止 Windows Update 驱动更新，新硬件可能需要手动安装厂商驱动。

## 2.0.0

首个 Win7/10/11 原生统一版本：

- 从 C#/.NET 迁移为原生 C++17/Win32 单文件 EXE。
- 使用 `/MT` 静态 CRT，无需安装 .NET Framework 或 VC++ Redistributable。
- 自动识别 Windows 7、Windows 10、Windows 11，并选择对应 Controller。
- Windows 7 新增 `NoAutoUpdate`、`DisableWindowsUpdateAccess` 和 `wuauserv` 控制。
- Windows 10/11 保留六项自动更新、通知、自动重启和驱动更新策略。
- 使用 Win32 Registry API 与 SCM API，不依赖脚本或外部命令。
- 保留原始状态备份、一键恢复、回读验证、失败回滚、UAC 和单实例保护。
- 兼容旧 `policy-backup-v1.txt`，并为 Win7 使用独立原始状态备份。
- 统一图标、中文界面和作者信息“啊常用户”。

