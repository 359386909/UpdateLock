#define UPDATELOCK_TEST
#include "UpdateLock.cpp"

#include <iostream>

namespace {

void Require(bool condition, const wchar_t* message) {
    if (!condition) throw AppError(message);
}

void RemoveIfPresent(const std::wstring& path) {
    if (!DeleteFileW(path.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) ThrowWin32(L"删除测试文件");
}

} // namespace

int wmain() {
    try {
        wchar_t tempRoot[MAX_PATH] = {};
        if (!GetTempPathW(MAX_PATH, tempRoot)) ThrowWin32(L"获取测试临时目录");
        const std::wstring testDirectory = std::wstring(tempRoot) + L"UpdateLock-NativeTests-" +
            std::to_wstring(GetCurrentProcessId());
        if (!CreateDirectoryW(testDirectory.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
            ThrowWin32(L"创建测试临时目录");
        }
        Require(Base64Encode(L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate") ==
            "U09GVFdBUkVcUG9saWNpZXNcTWljcm9zb2Z0XFdpbmRvd3NcV2luZG93c1VwZGF0ZQ==",
            L"Base64 与 C# UTF-8 格式不一致。" );
        Require(Base64Decode("Tm9BdXRvVXBkYXRl") == L"NoAutoUpdate", L"Base64 解码不兼容。" );
        Require(Base64Decode("").empty(), L"空 Base64 处理错误。" );
        Require(ParseInt32("  +42 ") == 42 && ParseInt32("-2147483648") == INT32_MIN,
            L"旧 C# Int32 文本兼容解析错误。" );

        const UpdateStatus all = ModernUpdateController::BuildStatus(true, true, true, true, true);
        const UpdateStatus partial = ModernUpdateController::BuildStatus(true, true, true, true, false);
        const UpdateStatus coreFailed = ModernUpdateController::BuildStatus(false, true, true, true, true);
        Require(all.level == StatusLevel::Disabled && all.title == L"Windows 更新已完全关闭", L"现代完整状态语义错误。" );
        Require(partial.level == StatusLevel::PartiallyDisabled && partial.title == L"Windows 自动更新已关闭，但部分封锁策略未生效", L"现代访问封锁状态语义错误。" );
        Require(coreFailed.level == StatusLevel::Enabled && coreFailed.title == L"Windows 更新未完全关闭", L"现代核心状态语义错误。" );

        ModernUpdateController modern(L"Windows 10");
        modern.TestSetBackupPath(testDirectory + L"\\policy-backup-v1.txt");
        RemoveIfPresent(modern.TestBackupPath());
        const std::vector<std::string> modernLines = {
            Base64Encode(kWindowsUpdate) + "|" + Base64Encode(L"UpdateNotificationLevel") + "|1|2",
            Base64Encode(kAutomaticUpdates) + "|" + Base64Encode(L"AUOptions") + "|0|0",
            Base64Encode(kWindowsUpdate) + "|" + Base64Encode(L"ExcludeWUDriversInQualityUpdate") + "|1|1",
            Base64Encode(kAutomaticUpdates) + "|" + Base64Encode(L"NoAutoUpdate") + "|0|-7",
            Base64Encode(kWindowsUpdate) + "|" + Base64Encode(L"SetUpdateNotificationLevel") + "|1|1",
            Base64Encode(kAutomaticUpdates) + "|" + Base64Encode(L"NoAutoRebootWithLoggedOnUsers") + "|1|1"
        };
        WriteUtf8LinesAtomically(modern.TestBackupPath(), modernLines, true);
        const std::vector<PolicyState> parsed = modern.TestReadBackup();
        Require(parsed.size() == 6, L"现代旧备份行数解析错误。" );
        Require(std::wstring(parsed[0].policy->name) == L"ExcludeWUDriversInQualityUpdate", L"现代备份未按原白名单顺序重排。" );
        Require(std::wstring(parsed[3].policy->name) == L"NoAutoUpdate" && !parsed[3].exists && parsed[3].value == -7,
            L"现代备份存在性或 Int32 值解析错误。" );
        RemoveIfPresent(modern.TestBackupPath());

        modern.TestSetAccessBackupPath(testDirectory + L"\\windows-update-access-backup-v1.txt");
        RemoveIfPresent(modern.TestAccessBackupPath());
        WriteUtf8LinesAtomically(modern.TestAccessBackupPath(), {
            "UpdateLock-ModernAccess|1",
            Base64Encode(kWindowsUpdate) + "|" + Base64Encode(L"SetDisableUXWUAccess") + "|0|9"}, true);
        const PolicyState accessBackup = modern.TestReadAccessBackup();
        Require(std::wstring(accessBackup.policy->name) == L"SetDisableUXWUAccess" &&
            !accessBackup.exists && accessBackup.value == 9, L"Windows Update 访问策略备份解析错误。" );
        RemoveIfPresent(modern.TestAccessBackupPath());

        Windows7UpdateController win7;
        win7.TestSetBackupPath(testDirectory + L"\\windows7-original-state-v1.txt");
        RemoveIfPresent(win7.TestBackupPath());
        const std::vector<std::string> win7Lines = {
            "UpdateLock-Windows7|1",
            "DWORD|" + Base64Encode(kAutomaticUpdates) + "|" + Base64Encode(L"NoAutoUpdate") + "|0|0",
            "DWORD|" + Base64Encode(kWindowsUpdate) + "|" + Base64Encode(L"DisableWindowsUpdateAccess") + "|1|5",
            "SERVICE|wuauserv|3|1|0"
        };
        WriteUtf8LinesAtomically(win7.TestBackupPath(), win7Lines, true);
        win7.TestReadBackup();
        RemoveIfPresent(win7.TestBackupPath());

        bool rejected = false;
        WriteUtf8LinesAtomically(win7.TestBackupPath(), {
            "UpdateLock-Windows7|1",
            "DWORD|" + Base64Encode(kAutomaticUpdates) + "|" + Base64Encode(L"NoAutoUpdate") + "|0|0",
            "DWORD|" + Base64Encode(kWindowsUpdate) + "|" + Base64Encode(L"Unexpected") + "|1|5",
            "SERVICE|wuauserv|3|1|0"}, true);
        try { win7.TestReadBackup(); } catch (const AppError&) { rejected = true; }
        RemoveIfPresent(win7.TestBackupPath());
        Require(rejected, L"Win7 备份白名单未拒绝越界项目。" );

        const VersionInfo currentVersion = ReadWindowsVersion();
        Require(currentVersion.productType == VER_NT_WORKSTATION,
            L"当前测试机不是 Windows 工作站。" );
        std::unique_ptr<IUpdateController> current = CreateController(currentVersion);
        const UpdateStatus liveStatus = current->GetStatus();
        Require(!liveStatus.title.empty() && !liveStatus.details.empty(),
            L"当前系统只读状态检查失败。" );
        if (!RemoveDirectoryW(testDirectory.c_str())) ThrowWin32(L"删除测试临时目录");

        std::wcout << L"ALL_NATIVE_TESTS_PASSED" << std::endl;
        return 0;
    } catch (const AppError& error) {
        std::wcerr << L"TEST_FAILED: " << error.message << std::endl;
        return 1;
    }
}
