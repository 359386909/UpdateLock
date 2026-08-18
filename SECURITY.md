# 安全与稳定性说明

## 操作边界

- Windows 7 只修改 `NoAutoUpdate`、`DisableWindowsUpdateAccess` 和 `wuauserv`。
- Windows 10/11 只修改 README 中列出的更新策略，不删除服务、系统文件或更新缓存。
- “禁止升级到 Windows 11”是独立功能，仅在 Windows 10 写入 `ProductVersion`、`TargetReleaseVersion` 和 `TargetReleaseVersionInfo`，不修改服务、TPM、Secure Boot 或兼容性检查。
- 不修改 BITS、CryptSvc、TrustedInstaller、Windows Installer、Task Scheduler、RPC、防火墙或网络配置。
- 所有策略写入后回读验证，失败时尝试恢复到本次操作前状态。

## 已知风险

- 关闭 Windows Update 会延迟系统安全补丁、Windows Update 驱动和部分产品更新。
- `ExcludeWUDriversInQualityUpdate=1` 可能影响新 USB 硬件自动获取驱动。
- EXE 需要管理员权限；请只从本仓库 Release 下载并核对 SHA-256。
- 当前版本没有受信任的 Authenticode 数字签名，作者元数据不等同于数字签名。

Windows 10 升级锁定的原始三项注册表状态单独保存在 `%ProgramData%\UpdateLock\windows11-upgrade-backup-v1.txt`，恢复完成并逐项回读一致后才删除该备份。

## 问题反馈

反馈时请提供 Windows 版本、工具版本、状态详情和错误文本。请勿公开上传密码、Token、远程连接信息或包含隐私的数据。

