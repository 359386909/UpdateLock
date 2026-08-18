#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>
#include <wincrypt.h>
#include <objbase.h>
#include <wuapi.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cwctype>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "resource.h"

namespace {

const wchar_t* const kAppName = L"Win7/10/11 自动更新关闭工具";
const wchar_t* const kMutexName = L"Global\\UpdateLock.SingleInstance.7A64EA9A";
const wchar_t* const kWindowsUpdate = L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate";
const wchar_t* const kAutomaticUpdates = L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU";
const wchar_t* const kCurrentVersion = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
const REGSAM kRegistryView = KEY_WOW64_64KEY;

struct AppError : public std::exception {
    std::wstring message;
    explicit AppError(const std::wstring& value) : message(value) {}
    const char* what() const noexcept override { return "AppError"; }
};

std::wstring Win32Message(DWORD code) {
    wchar_t* text = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD count = FormatMessageW(flags, nullptr, code, 0,
        reinterpret_cast<wchar_t*>(&text), 0, nullptr);
    std::wstring result = count && text ? text : L"未知错误";
    if (text) LocalFree(text);
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) {
        result.pop_back();
    }
    return result;
}

[[noreturn]] void ThrowWin32(const wchar_t* operation, DWORD code = GetLastError()) {
    throw AppError(std::wstring(operation) + L"失败。Win32 " + std::to_wstring(code) +
                   L"：" + Win32Message(code));
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) return std::string();
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (!count) ThrowWin32(L"UTF-8 编码");
    std::string result(static_cast<size_t>(count), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), &result[0], count, nullptr, nullptr)) {
        ThrowWin32(L"UTF-8 编码");
    }
    return result;
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) return std::wstring();
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (!count) ThrowWin32(L"UTF-8 解码");
    std::wstring result(static_cast<size_t>(count), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), &result[0], count)) {
        ThrowWin32(L"UTF-8 解码");
    }
    return result;
}

std::string Base64Encode(const std::wstring& value) {
    const std::string bytes = WideToUtf8(value);
    DWORD count = 0;
    if (!CryptBinaryToStringA(reinterpret_cast<const BYTE*>(bytes.data()),
        static_cast<DWORD>(bytes.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        nullptr, &count)) ThrowWin32(L"Base64 编码");
    std::string result(count, '\0');
    if (!CryptBinaryToStringA(reinterpret_cast<const BYTE*>(bytes.data()),
        static_cast<DWORD>(bytes.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        &result[0], &count)) ThrowWin32(L"Base64 编码");
    if (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

std::string Base64EncodeBytes(const std::vector<BYTE>& bytes) {
    if (bytes.empty()) return std::string();
    DWORD count = 0;
    const BYTE* data = bytes.data();
    if (!CryptBinaryToStringA(data, static_cast<DWORD>(bytes.size()),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &count)) {
        ThrowWin32(L"Base64 编码");
    }
    if (count == 0) return std::string();
    std::string result(count, '\0');
    if (!CryptBinaryToStringA(data, static_cast<DWORD>(bytes.size()),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &count)) {
        ThrowWin32(L"Base64 编码");
    }
    if (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

std::vector<BYTE> Base64DecodeBytes(const std::string& value) {
    if (value.empty()) return {};
    DWORD count = 0;
    if (!CryptStringToBinaryA(value.c_str(), static_cast<DWORD>(value.size()),
        CRYPT_STRING_BASE64, nullptr, &count, nullptr, nullptr)) {
        throw AppError(L"备份文件包含无效 Base64。" );
    }
    std::vector<BYTE> result(count);
    if (!CryptStringToBinaryA(value.c_str(), static_cast<DWORD>(value.size()),
        CRYPT_STRING_BASE64, result.data(), &count, nullptr, nullptr)) {
        throw AppError(L"备份文件包含无效 Base64。" );
    }
    result.resize(count);
    return result;
}

std::wstring Base64Decode(const std::string& value) {
    DWORD count = 0;
    if (!CryptStringToBinaryA(value.c_str(), static_cast<DWORD>(value.size()),
        CRYPT_STRING_BASE64, nullptr, &count, nullptr, nullptr)) {
        throw AppError(L"备份文件包含无效 Base64。" );
    }
    if (count == 0) return std::wstring();
    std::string bytes(count, '\0');
    if (!CryptStringToBinaryA(value.c_str(), static_cast<DWORD>(value.size()),
        CRYPT_STRING_BASE64, reinterpret_cast<BYTE*>(&bytes[0]), &count, nullptr, nullptr)) {
        throw AppError(L"备份文件包含无效 Base64。" );
    }
    bytes.resize(count);
    return Utf8ToWide(bytes);
}

std::vector<std::string> Split(const std::string& value, char delimiter) {
    std::vector<std::string> result;
    size_t start = 0;
    for (;;) {
        const size_t end = value.find(delimiter, start);
        result.push_back(value.substr(start, end == std::string::npos ? end : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result;
}

int32_t ParseInt32(const std::string& text) {
    std::wstring value = Utf8ToWide(text);
    while (!value.empty() && iswspace(value.front())) value.erase(value.begin());
    while (!value.empty() && iswspace(value.back())) value.pop_back();
    if (value.empty()) throw AppError(L"备份文件包含无效整数。" );

    wchar_t localeNegative[16] = {};
    wchar_t localePositive[16] = {};
    GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SNEGATIVESIGN,
        localeNegative, static_cast<int>(std::size(localeNegative)));
    GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SPOSITIVESIGN,
        localePositive, static_cast<int>(std::size(localePositive)));
    if (localeNegative[0] && value.compare(0, wcslen(localeNegative), localeNegative) == 0) {
        value.replace(0, wcslen(localeNegative), L"-");
    } else if (localePositive[0] && value.compare(0, wcslen(localePositive), localePositive) == 0) {
        value.replace(0, wcslen(localePositive), L"+");
    }

    wchar_t* end = nullptr;
    errno = 0;
    const long long number = _wcstoi64(value.c_str(), &end, 10);
    if (errno == ERANGE || !end || *end != '\0' ||
        number < std::numeric_limits<int32_t>::min() || number > std::numeric_limits<int32_t>::max()) {
        throw AppError(L"备份文件包含无效整数。" );
    }
    return static_cast<int32_t>(number);
}

struct ScopedHandle {
    HANDLE value = nullptr;
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE handle) : value(handle) {}
    ~ScopedHandle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
};

struct ScopedRegKey {
    HKEY value = nullptr;
    ~ScopedRegKey() { if (value) RegCloseKey(value); }
    ScopedRegKey() = default;
    ScopedRegKey(const ScopedRegKey&) = delete;
    ScopedRegKey& operator=(const ScopedRegKey&) = delete;
};

struct ScopedServiceHandle {
    SC_HANDLE value = nullptr;
    ~ScopedServiceHandle() { if (value) CloseServiceHandle(value); }
    ScopedServiceHandle() = default;
    explicit ScopedServiceHandle(SC_HANDLE handle) : value(handle) {}
    ScopedServiceHandle(const ScopedServiceHandle&) = delete;
    ScopedServiceHandle& operator=(const ScopedServiceHandle&) = delete;
};

struct PolicyValue {
    const wchar_t* path;
    const wchar_t* name;
};

struct RawRegistryState {
    const PolicyValue* policy;
    bool exists;
    DWORD type;
    std::vector<BYTE> data;
};

struct PolicyState {
    const PolicyValue* policy;
    bool exists;
    int32_t value;
};

bool SamePolicy(const PolicyValue& a, const std::wstring& path, const std::wstring& name) {
    return path == a.path && name == a.name;
}

RawRegistryState ReadRawRegistryState(const PolicyValue& policy) {
    ScopedRegKey key;
    const LSTATUS opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, policy.path, 0,
        KEY_QUERY_VALUE | kRegistryView, &key.value);
    if (opened == ERROR_FILE_NOT_FOUND || opened == ERROR_PATH_NOT_FOUND) {
        return RawRegistryState{&policy, false, 0, {}};
    }
    if (opened != ERROR_SUCCESS) ThrowWin32(L"读取注册表值", opened);

    DWORD type = 0;
    DWORD size = 0;
    LSTATUS queried = RegQueryValueExW(key.value, policy.name, nullptr, &type, nullptr, &size);
    if (queried == ERROR_FILE_NOT_FOUND) return RawRegistryState{&policy, false, 0, {}};
    if (queried != ERROR_SUCCESS) ThrowWin32(L"读取注册表值大小", queried);
    if (size > 1024 * 1024) throw AppError(L"注册表值过大，拒绝读取。" );

    std::vector<BYTE> data(size);
    queried = RegQueryValueExW(key.value, policy.name, nullptr, &type,
        data.empty() ? nullptr : data.data(), &size);
    if (queried != ERROR_SUCCESS) ThrowWin32(L"读取注册表值", queried);
    data.resize(size);
    return RawRegistryState{&policy, true, type, std::move(data)};
}

void SetRawRegistryState(const RawRegistryState& state) {
    if (!state.exists || state.type == 0 || state.data.size() > MAXDWORD) {
        throw AppError(L"要写入的注册表原始状态无效。" );
    }
    ScopedRegKey key;
    DWORD disposition = 0;
    const LSTATUS created = RegCreateKeyExW(HKEY_LOCAL_MACHINE, state.policy->path, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_QUERY_VALUE | kRegistryView, nullptr,
        &key.value, &disposition);
    if (created != ERROR_SUCCESS) ThrowWin32(L"写入注册表值", created);
    const LSTATUS written = RegSetValueExW(key.value, state.policy->name, 0, state.type,
        state.data.data(), static_cast<DWORD>(state.data.size()));
    if (written != ERROR_SUCCESS) ThrowWin32(L"写入注册表值", written);
}

void DeleteRawRegistryValue(const PolicyValue& policy) {
    ScopedRegKey key;
    const LSTATUS opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, policy.path, 0,
        KEY_SET_VALUE | KEY_QUERY_VALUE | kRegistryView, &key.value);
    if (opened == ERROR_FILE_NOT_FOUND || opened == ERROR_PATH_NOT_FOUND) return;
    if (opened != ERROR_SUCCESS) ThrowWin32(L"打开注册表值", opened);
    const LSTATUS deleted = RegDeleteValueW(key.value, policy.name);
    if (deleted != ERROR_SUCCESS && deleted != ERROR_FILE_NOT_FOUND) {
        ThrowWin32(L"删除注册表值", deleted);
    }
}

void RestoreRawRegistryState(const RawRegistryState& state) {
    if (state.exists) SetRawRegistryState(state);
    else DeleteRawRegistryValue(*state.policy);
}

void VerifyRawRegistryState(const RawRegistryState& expected) {
    const RawRegistryState actual = ReadRawRegistryState(*expected.policy);
    if (actual.exists != expected.exists ||
        (actual.exists && (actual.type != expected.type || actual.data != expected.data))) {
        throw AppError(std::wstring(expected.policy->name) + L" 回读不一致。" );
    }
}

std::wstring RawRegistryString(const RawRegistryState& state) {
    if (!state.exists || state.type != REG_SZ || state.data.size() % sizeof(wchar_t) != 0) {
        return std::wstring();
    }
    std::wstring value(state.data.size() / sizeof(wchar_t), L'\0');
    if (!state.data.empty()) std::memcpy(&value[0], state.data.data(), state.data.size());
    while (!value.empty() && value.back() == L'\0') value.pop_back();
    return value;
}

RawRegistryState MakeRegistryStringState(const PolicyValue& policy, const std::wstring& value) {
    RawRegistryState state{&policy, true, REG_SZ,
        std::vector<BYTE>((value.size() + 1) * sizeof(wchar_t))};
    std::memcpy(state.data.data(), value.c_str(), state.data.size());
    return state;
}

RawRegistryState MakeRegistryDwordState(const PolicyValue& policy, DWORD value) {
    RawRegistryState state{&policy, true, REG_DWORD, std::vector<BYTE>(sizeof(DWORD))};
    std::memcpy(state.data.data(), &value, sizeof(value));
    return state;
}

bool IsRegistryDword(const RawRegistryState& state, DWORD expected) {
    if (!state.exists || state.type != REG_DWORD || state.data.size() != sizeof(DWORD)) return false;
    DWORD value = 0;
    std::memcpy(&value, state.data.data(), sizeof(value));
    return value == expected;
}

PolicyState ReadDwordState(const PolicyValue& policy) {
    ScopedRegKey key;
    const LSTATUS opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, policy.path, 0,
        KEY_QUERY_VALUE | kRegistryView, &key.value);
    if (opened == ERROR_FILE_NOT_FOUND || opened == ERROR_PATH_NOT_FOUND) {
        return PolicyState{&policy, false, 0};
    }
    if (opened != ERROR_SUCCESS) ThrowWin32(L"读取注册表策略", opened);
    DWORD type = 0;
    DWORD value = 0;
    DWORD size = sizeof(value);
    const LSTATUS queried = RegQueryValueExW(key.value, policy.name, nullptr, &type,
        reinterpret_cast<BYTE*>(&value), &size);
    if (queried == ERROR_FILE_NOT_FOUND) return PolicyState{&policy, false, 0};
    if (queried != ERROR_SUCCESS) ThrowWin32(L"读取注册表策略", queried);
    if (type != REG_DWORD || size != sizeof(DWORD)) {
        throw AppError(std::wstring(L"注册表值不是 REG_DWORD：") + policy.path + L"\\" + policy.name);
    }
    return PolicyState{&policy, true, static_cast<int32_t>(value)};
}

void SetDword(const PolicyValue& policy, int32_t value) {
    ScopedRegKey key;
    DWORD disposition = 0;
    const LSTATUS created = RegCreateKeyExW(HKEY_LOCAL_MACHINE, policy.path, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_QUERY_VALUE | kRegistryView, nullptr,
        &key.value, &disposition);
    if (created != ERROR_SUCCESS) ThrowWin32(L"写入注册表策略", created);
    const DWORD raw = static_cast<DWORD>(value);
    const LSTATUS written = RegSetValueExW(key.value, policy.name, 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&raw), sizeof(raw));
    if (written != ERROR_SUCCESS) ThrowWin32(L"写入注册表策略", written);
}

void DeleteDword(const PolicyValue& policy) {
    ScopedRegKey key;
    const LSTATUS opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, policy.path, 0,
        KEY_SET_VALUE | KEY_QUERY_VALUE | kRegistryView, &key.value);
    if (opened == ERROR_FILE_NOT_FOUND || opened == ERROR_PATH_NOT_FOUND) return;
    if (opened != ERROR_SUCCESS) ThrowWin32(L"打开注册表策略", opened);
    const LSTATUS deleted = RegDeleteValueW(key.value, policy.name);
    if (deleted != ERROR_SUCCESS && deleted != ERROR_FILE_NOT_FOUND) {
        ThrowWin32(L"删除注册表策略", deleted);
    }
}

void RestorePolicy(const PolicyState& state) {
    if (state.exists) SetDword(*state.policy, state.value);
    else DeleteDword(*state.policy);
}

void VerifyPolicy(const PolicyState& expected) {
    const PolicyState actual = ReadDwordState(*expected.policy);
    if (actual.exists != expected.exists || (actual.exists && actual.value != expected.value)) {
        throw AppError(std::wstring(expected.policy->name) + L" 恢复后回读不一致。" );
    }
}

std::wstring BackupDirectory() {
    wchar_t path[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE,
        nullptr, SHGFP_TYPE_CURRENT, path))) {
        throw AppError(L"无法定位 ProgramData。" );
    }
    return std::wstring(path) + L"\\UpdateLock";
}

void PrepareBackupDirectory() {
    const std::wstring directory = BackupDirectory();
    if (!CreateDirectoryW(directory.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        ThrowWin32(L"创建备份目录");
    }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr)) {
        ThrowWin32(L"创建备份目录权限");
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present) {
        LocalFree(descriptor);
        throw AppError(L"无法读取备份目录权限。" );
    }
    const DWORD result = SetNamedSecurityInfoW(const_cast<LPWSTR>(directory.c_str()),
        SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, dacl, nullptr);
    LocalFree(descriptor);
    if (result != ERROR_SUCCESS) ThrowWin32(L"设置备份目录权限", result);
}

std::vector<std::string> ReadUtf8Lines(const std::wstring& path) {
    ScopedHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) ThrowWin32(L"打开备份文件");
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file.value, &size)) ThrowWin32(L"读取备份文件大小");
    if (size.QuadPart < 0 || size.QuadPart > 1024 * 1024) throw AppError(L"备份文件大小无效。" );
    std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    if (!bytes.empty() && (!ReadFile(file.value, &bytes[0], static_cast<DWORD>(bytes.size()), &read, nullptr) || read != bytes.size())) {
        ThrowWin32(L"读取备份文件");
    }
    if (bytes.size() >= 3 && static_cast<unsigned char>(bytes[0]) == 0xEF &&
        static_cast<unsigned char>(bytes[1]) == 0xBB && static_cast<unsigned char>(bytes[2]) == 0xBF) {
        bytes.erase(0, 3);
    }
    (void)Utf8ToWide(bytes);
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < bytes.size()) {
        size_t end = bytes.find('\n', start);
        std::string line = bytes.substr(start, end == std::string::npos ? end : end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
        if (end == std::string::npos) { start = bytes.size(); break; }
        start = end + 1;
    }
    if (start == bytes.size() && !bytes.empty() && bytes.back() == '\n') {
        // File.WriteAllLines ends with CRLF; no synthetic empty line is part of the format.
    }
    return lines;
}

std::wstring UniqueTempPath(const std::wstring& finalPath) {
    return finalPath + L".tmp-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
           std::to_wstring(GetTickCount());
}

void WriteUtf8LinesAtomically(const std::wstring& path, const std::vector<std::string>& lines, bool durable) {
    const std::wstring temp = UniqueTempPath(path);
    ScopedHandle file(CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | (durable ? FILE_FLAG_WRITE_THROUGH : 0), nullptr));
    if (file.value == INVALID_HANDLE_VALUE) ThrowWin32(L"创建临时备份文件");
    std::string bytes;
    for (const std::string& line : lines) bytes += line + "\r\n";
    DWORD written = 0;
    if (!bytes.empty() && (!WriteFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()),
        &written, nullptr) || written != bytes.size())) {
        const DWORD error = GetLastError();
        CloseHandle(file.value);
        file.value = nullptr;
        DeleteFileW(temp.c_str());
        ThrowWin32(L"写入临时备份文件", error);
    }
    if (durable && !FlushFileBuffers(file.value)) {
        const DWORD error = GetLastError();
        CloseHandle(file.value);
        file.value = nullptr;
        DeleteFileW(temp.c_str());
        ThrowWin32(L"刷新临时备份文件", error);
    }
    CloseHandle(file.value);
    file.value = nullptr;
    if (!MoveFileW(temp.c_str(), path.c_str())) {
        const DWORD error = GetLastError();
        DeleteFileW(temp.c_str());
        ThrowWin32(L"提交备份文件", error);
    }
}

bool FileExists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

enum class StatusLevel { Enabled, PartiallyDisabled, Disabled };
enum class OperationOutcome { Success, PartialSuccess, Failed };

struct UpdateStatus {
    StatusLevel level;
    std::wstring title;
    std::vector<std::wstring> details;
};

struct OperationResult {
    OperationOutcome outcome;
    std::wstring message;
};

struct VersionInfo {
    DWORD major;
    DWORD minor;
    DWORD build;
    BYTE productType;
};

VersionInfo ReadWindowsVersion() {
    typedef LONG (WINAPI* RtlGetVersionFn)(PRTL_OSVERSIONINFOEXW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) ThrowWin32(L"加载系统版本组件");
    const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(ntdll, "RtlGetVersion"));
    if (!rtlGetVersion) throw AppError(L"当前系统不提供可靠版本检测接口。" );
    RTL_OSVERSIONINFOEXW info = {};
    info.dwOSVersionInfoSize = sizeof(info);
    const LONG status = rtlGetVersion(&info);
    if (status != 0) throw AppError(L"无法可靠识别当前 Windows 版本。" );
    return VersionInfo{info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber,
                       info.wProductType};
}

enum class Windows10VersionSource { DisplayVersion, ReleaseId, BuildMapping };

struct Windows10VersionInfo {
    bool isWindows10 = false;
    bool known = false;
    DWORD build = 0;
    DWORD revision = 0;
    std::wstring functionalVersion;
    Windows10VersionSource source = Windows10VersionSource::BuildMapping;
    std::wstring error;
};

struct Windows10BuildMapping {
    DWORD build;
    const wchar_t* functionalVersion;
};

const std::array<Windows10BuildMapping, 14> kWindows10BuildMappings = {{
    {10240, L"1507"}, {10586, L"1511"}, {14393, L"1607"}, {15063, L"1703"},
    {16299, L"1709"}, {17134, L"1803"}, {17763, L"1809"}, {18362, L"1903"},
    {18363, L"1909"}, {19041, L"2004"}, {19042, L"20H2"}, {19043, L"21H1"},
    {19044, L"21H2"}, {19045, L"22H2"}
}};

const Windows10BuildMapping* FindWindows10BuildMapping(DWORD build) {
    for (const Windows10BuildMapping& mapping : kWindows10BuildMappings) {
        if (mapping.build == build) return &mapping;
    }
    return nullptr;
}

bool IsDigits(const std::wstring& value) {
    if (value.empty()) return false;
    return std::all_of(value.begin(), value.end(), [](wchar_t c) { return c >= L'0' && c <= L'9'; });
}

bool IsDisplayVersionFormat(const std::wstring& value) {
    return value.size() == 4 && value[2] == L'H' &&
        value[0] >= L'0' && value[0] <= L'9' && value[1] >= L'0' && value[1] <= L'9' &&
        (value[3] == L'1' || value[3] == L'2');
}

bool IsReleaseIdFormat(const std::wstring& value) {
    return value.size() == 4 && IsDigits(value);
}

std::wstring ReadOptionalRegistryString(const wchar_t* name) {
    const PolicyValue policy{kCurrentVersion, name};
    return RawRegistryString(ReadRawRegistryState(policy));
}

DWORD ReadOptionalRegistryDword(const wchar_t* name) {
    const PolicyValue policy{kCurrentVersion, name};
    const RawRegistryState state = ReadRawRegistryState(policy);
    if (!state.exists || state.type != REG_DWORD || state.data.size() != sizeof(DWORD)) return 0;
    DWORD value = 0;
    std::memcpy(&value, state.data.data(), sizeof(value));
    return value;
}

class Windows10VersionDetector {
public:
    static Windows10VersionInfo Resolve(const VersionInfo& version,
        const std::wstring& displayVersion, const std::wstring& releaseId, DWORD revision) {
        Windows10VersionInfo result;
        result.isWindows10 = version.major == 10 && version.minor == 0 && version.build < 22000;
        result.build = version.build;
        result.revision = revision;
        if (!result.isWindows10) return result;

        const Windows10BuildMapping* mapping = FindWindows10BuildMapping(version.build);
        if (!mapping) {
            result.error = L"已确认当前系统为 Windows 10，但当前 Build 无法映射到已知功能版本。\r\nBuild：" +
                std::to_wstring(version.build) + L"\r\n为避免写入错误目标版本，本次未修改系统。";
            return result;
        }

        if (IsDisplayVersionFormat(displayVersion) && displayVersion == mapping->functionalVersion) {
            result.known = true;
            result.functionalVersion = displayVersion;
            result.source = Windows10VersionSource::DisplayVersion;
        } else if (!IsDisplayVersionFormat(displayVersion) && IsReleaseIdFormat(releaseId) &&
                   releaseId == mapping->functionalVersion) {
            result.known = true;
            result.functionalVersion = releaseId;
            result.source = Windows10VersionSource::ReleaseId;
        } else {
            result.known = true;
            result.functionalVersion = mapping->functionalVersion;
            result.source = Windows10VersionSource::BuildMapping;
        }
        return result;
    }

    static Windows10VersionInfo Detect(const VersionInfo& version) {
        return Resolve(version, ReadOptionalRegistryString(L"DisplayVersion"),
            ReadOptionalRegistryString(L"ReleaseId"), ReadOptionalRegistryDword(L"UBR"));
    }

    static const wchar_t* SourceName(Windows10VersionSource source) {
        switch (source) {
        case Windows10VersionSource::DisplayVersion: return L"DisplayVersion";
        case Windows10VersionSource::ReleaseId: return L"ReleaseId";
        case Windows10VersionSource::BuildMapping: return L"Build 识别";
        }
        return L"Build 识别";
    }
};

class IUpdateController {
public:
    virtual ~IUpdateController() = default;
    virtual std::wstring DisplayName() const = 0;
    virtual std::wstring Description() const = 0;
    virtual std::wstring Warning() const = 0;
    virtual std::wstring Confirmation() const = 0;
    virtual std::wstring DisableButtonText() const = 0;
    virtual bool CanRestore() const = 0;
    virtual UpdateStatus GetStatus() const = 0;
    virtual OperationResult Disable() = 0;
    virtual OperationResult Restore() = 0;
};

class ModernUpdateController : public IUpdateController {
public:
    explicit ModernUpdateController(const wchar_t* displayName)
        : displayName_(displayName), backupPath_(BackupDirectory() + L"\\policy-backup-v1.txt"),
          accessBackupPath_(BackupDirectory() + L"\\windows-update-access-backup-v1.txt") {}

    std::wstring DisplayName() const override { return displayName_; }
    std::wstring Description() const override {
        return L"关闭 Windows 自动更新、更新通知、更新自动重启和 Windows Update 驱动更新，并禁止通过 Windows Update 手动下载或安装更新。";
    }
    std::wstring Warning() const override {
        return L"注意：关闭后 Windows 不会按正常自动更新流程获取系统安全补丁和 Windows Update 驱动更新。\r\n"
               L"Windows Update 页面将不再提供手动检查、下载或安装更新的入口。\r\n"
               L"“恢复”只恢复本软件第一次运行前保存的本机更新策略状态。";
    }
    std::wstring Confirmation() const override {
        return L"这会关闭 Windows 自动更新、更新通知、更新自动重启和 Windows Update 驱动更新。\r\n"
               L"同时禁用 Windows Update 的手动检查、下载和安装入口。";
    }
    std::wstring DisableButtonText() const override { return L"彻底关闭 Windows 更新"; }
    bool CanRestore() const override { return FileExists(backupPath_); }
#ifdef UPDATELOCK_TEST
    std::vector<PolicyState> TestReadBackup() const { return ReadBackup(); }
    const std::wstring& TestBackupPath() const { return backupPath_; }
    void TestSetBackupPath(const std::wstring& path) { backupPath_ = path; }
    PolicyState TestReadAccessBackup() const { return ReadAccessBackup(); }
    const std::wstring& TestAccessBackupPath() const { return accessBackupPath_; }
    void TestSetAccessBackupPath(const std::wstring& path) { accessBackupPath_ = path; }
#endif

    UpdateStatus GetStatus() const override {
        const bool autoBlocked = IsValue(kPolicies[3], 1);
        const bool noRestart = IsValue(kPolicies[4], 1);
        const bool notificationsBlocked = IsValue(kPolicies[1], 1) && IsValue(kPolicies[2], 2);
        const bool driverBlocked = IsValue(kPolicies[0], 1);
        const bool accessBlocked = IsValue(kDisableWindowsUpdateAccess, 1);
        return BuildStatus(autoBlocked, notificationsBlocked, noRestart, driverBlocked, accessBlocked);
    }

    static UpdateStatus BuildStatus(bool autoBlocked, bool notificationsBlocked,
                                    bool noRestart, bool driverBlocked, bool accessBlocked) {
        StatusLevel level;
        std::wstring title;
        std::wstring summary;
        if (!autoBlocked) {
            level = StatusLevel::Enabled;
            title = L"Windows 更新未完全关闭";
            summary = L"核心自动更新策略未生效。";
        } else if (notificationsBlocked && noRestart && driverBlocked && accessBlocked) {
            level = StatusLevel::Disabled;
            title = L"Windows 更新已完全关闭";
            summary = L"Windows Update 手动检查、下载和安装：已禁用";
        } else {
            level = StatusLevel::PartiallyDisabled;
            title = L"Windows 自动更新已关闭，但部分封锁策略未生效";
            summary = L"部分附加或访问封锁策略未生效。";
        }
        return UpdateStatus{level, title, {
            std::wstring(L"自动更新：") + (autoBlocked ? L"已关闭" : L"未关闭") +
                L"    更新通知：" + (notificationsBlocked ? L"已关闭" : L"未关闭"),
            std::wstring(L"更新自动重启：") + (noRestart ? L"已限制" : L"未限制") +
                L"    Windows Update 驱动更新：" + (driverBlocked ? L"已关闭" : L"未关闭"),
            std::wstring(L"Windows Update 手动访问：") + (accessBlocked ? L"已禁用" : L"未禁用"),
            summary}};
    }

    OperationResult Disable() override {
        std::vector<PolicyState> before;
        PolicyState accessBefore{};
        try { before = Capture(); }
        catch (const AppError& error) {
            return {OperationOutcome::Failed, L"读取当前策略失败，系统未修改：\r\n" + error.message};
        }
        try { accessBefore = ReadDwordState(kDisableWindowsUpdateAccess); }
        catch (const AppError& error) {
            return {OperationOutcome::Failed, L"读取 Windows Update 访问策略失败，系统未修改：\r\n" + error.message};
        }
        try {
            SaveOriginalIfNeeded(before);
            SaveAccessOriginalIfNeeded(accessBefore);
            SetDword(kPolicies[3], 1);
            SetDword(kPolicies[4], 1);
            DeleteDword(kPolicies[5]);
            SetDword(kPolicies[0], 1);
            SetDword(kPolicies[1], 1);
            SetDword(kPolicies[2], 2);
            SetDword(kDisableWindowsUpdateAccess, 1);
            if (GetStatus().level != StatusLevel::Disabled) {
                throw AppError(L"自动更新、附加策略或 Windows Update 访问封锁写入后回读未全部达到目标状态。" );
            }
            return {OperationOutcome::Success,
                L"Windows 更新已完全关闭。\r\n\r\n"
                L"Windows Update 的手动检查、下载和安装入口已禁用。"};
        } catch (const AppError& error) {
            return DisableFailure(before, accessBefore, error.message);
        } catch (...) {
            return DisableFailure(before, accessBefore, L"发生未预期的原生运行时错误。");
        }
    }

    OperationResult Restore() override {
        std::vector<PolicyState> before;
        PolicyState accessBefore{};
        try { before = Capture(); }
        catch (const AppError& error) {
            return {OperationOutcome::Failed, L"读取当前策略失败，系统未修改：\r\n" + error.message};
        }
        try { accessBefore = ReadDwordState(kDisableWindowsUpdateAccess); }
        catch (const AppError& error) {
            return {OperationOutcome::Failed, L"读取 Windows Update 访问策略失败，系统未修改：\r\n" + error.message};
        }
        try {
            const std::vector<PolicyState> original = ReadBackup();
            RestoreStates(original);
            VerifyStates(original);
            if (FileExists(accessBackupPath_)) {
                const PolicyState originalAccess = ReadAccessBackup();
                RestorePolicy(originalAccess);
                VerifyPolicy(originalAccess);
            }
            if (!DeleteFileW(backupPath_.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) {
                return {OperationOutcome::PartialSuccess,
                    L"原始策略已经恢复并验证，但无法删除备份文件：\r\n" +
                    Win32Message(GetLastError())};
            }
            if (!DeleteFileW(accessBackupPath_.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) {
                return {OperationOutcome::PartialSuccess,
                    L"原始策略已经恢复并验证，但无法删除 Windows Update 访问策略备份：\r\n" +
                    Win32Message(GetLastError())};
            }
            return {OperationOutcome::Success, L"已恢复为本软件首次运行前的策略状态。"};
        } catch (const AppError& error) {
            return RestoreFailure(before, accessBefore, error.message);
        } catch (...) {
            return RestoreFailure(before, accessBefore, L"发生未预期的原生运行时错误。");
        }
    }

private:
    static const std::array<PolicyValue, 6> kPolicies;
    static const PolicyValue kDisableWindowsUpdateAccess;
    std::wstring displayName_;
    std::wstring backupPath_;
    std::wstring accessBackupPath_;

    static bool IsValue(const PolicyValue& policy, int32_t expected) {
        const PolicyState state = ReadDwordState(policy);
        return state.exists && state.value == expected;
    }

    static const PolicyValue* FindPolicy(const std::wstring& path, const std::wstring& name) {
        for (const PolicyValue& policy : kPolicies) {
            if (SamePolicy(policy, path, name)) return &policy;
        }
        return nullptr;
    }

    static std::vector<PolicyState> Capture() {
        std::vector<PolicyState> result;
        result.reserve(kPolicies.size());
        for (const PolicyValue& policy : kPolicies) result.push_back(ReadDwordState(policy));
        return result;
    }

    void SaveOriginalIfNeeded(const std::vector<PolicyState>& original) {
        PrepareBackupDirectory();
        if (FileExists(backupPath_)) { (void)ReadBackup(); return; }
        std::vector<std::string> lines;
        for (const PolicyState& state : original) {
            lines.push_back(Base64Encode(state.policy->path) + "|" +
                Base64Encode(state.policy->name) + "|" + (state.exists ? "1" : "0") +
                "|" + std::to_string(state.value));
        }
        WriteUtf8LinesAtomically(backupPath_, lines, false);
    }

    void SaveAccessOriginalIfNeeded(const PolicyState& original) {
        PrepareBackupDirectory();
        if (FileExists(accessBackupPath_)) { (void)ReadAccessBackup(); return; }
        WriteUtf8LinesAtomically(accessBackupPath_, {
            "UpdateLock-ModernAccess|1",
            Base64Encode(original.policy->path) + "|" + Base64Encode(original.policy->name) + "|" +
                (original.exists ? "1" : "0") + "|" + std::to_string(original.value)}, false);
    }

    PolicyState ReadAccessBackup() const {
        const std::vector<std::string> lines = ReadUtf8Lines(accessBackupPath_);
        if (lines.size() != 2 || lines[0] != "UpdateLock-ModernAccess|1") {
            throw AppError(L"Windows Update 访问策略备份格式无效。" );
        }
        const std::vector<std::string> parts = Split(lines[1], '|');
        if (parts.size() != 4 || (parts[2] != "0" && parts[2] != "1") ||
            !SamePolicy(kDisableWindowsUpdateAccess, Base64Decode(parts[0]), Base64Decode(parts[1]))) {
            throw AppError(L"Windows Update 访问策略备份包含未允许项或无效值。" );
        }
        return PolicyState{&kDisableWindowsUpdateAccess, parts[2] == "1", ParseInt32(parts[3])};
    }

    std::vector<PolicyState> ReadBackup() const {
        const std::vector<std::string> lines = ReadUtf8Lines(backupPath_);
        if (lines.size() != kPolicies.size()) throw AppError(L"策略备份不完整。" );
        std::vector<PolicyState> parsed;
        for (const std::string& line : lines) {
            const std::vector<std::string> parts = Split(line, '|');
            if (parts.size() != 4) throw AppError(L"策略备份文件格式无效。" );
            const std::wstring path = Base64Decode(parts[0]);
            const std::wstring name = Base64Decode(parts[1]);
            const PolicyValue* allowed = FindPolicy(path, name);
            if (!allowed || (parts[2] != "0" && parts[2] != "1")) {
                throw AppError(L"策略备份包含未允许项或无效值。" );
            }
            for (const PolicyState& existing : parsed) {
                if (existing.policy == allowed) throw AppError(L"策略备份包含重复项。" );
            }
            parsed.push_back(PolicyState{allowed, parts[2] == "1", ParseInt32(parts[3])});
        }
        std::vector<PolicyState> ordered;
        for (const PolicyValue& policy : kPolicies) {
            const auto found = std::find_if(parsed.begin(), parsed.end(),
                [&policy](const PolicyState& state) { return state.policy == &policy; });
            if (found == parsed.end()) throw AppError(L"策略备份缺少必要项。" );
            ordered.push_back(*found);
        }
        return ordered;
    }

    static void RestoreStates(const std::vector<PolicyState>& states) {
        if (states.size() != kPolicies.size()) throw AppError(L"策略状态不完整。" );
        for (const PolicyState& state : states) {
            bool allowed = false;
            for (const PolicyValue& policy : kPolicies) if (state.policy == &policy) allowed = true;
            if (!allowed) throw AppError(L"策略状态包含未允许项。" );
            RestorePolicy(state);
        }
    }

    static void VerifyStates(const std::vector<PolicyState>& states) {
        for (const PolicyState& state : states) VerifyPolicy(state);
    }

    static std::wstring TryRestore(const std::vector<PolicyState>& states, const PolicyState& access) {
        try { RestoreStates(states); VerifyStates(states); RestorePolicy(access); VerifyPolicy(access); return std::wstring(); }
        catch (const AppError& error) { return error.message; }
        catch (...) { return L"回滚时发生未预期的原生运行时错误。"; }
    }

    static OperationResult DisableFailure(const std::vector<PolicyState>& before, const PolicyState& accessBefore,
        const std::wstring& error) {
        const std::wstring rollback = TryRestore(before, accessBefore);
        return rollback.empty()
            ? OperationResult{OperationOutcome::Failed,
                L"更新策略未完成写入，已恢复到操作前状态：\r\n" + error}
            : OperationResult{OperationOutcome::PartialSuccess,
                L"更新策略写入失败且回滚不完整。\r\n原始错误：" + error +
                L"\r\n回滚错误：" + rollback};
    }

    static OperationResult RestoreFailure(const std::vector<PolicyState>& before, const PolicyState& accessBefore,
        const std::wstring& error) {
        const std::wstring rollback = TryRestore(before, accessBefore);
        return rollback.empty()
            ? OperationResult{OperationOutcome::Failed,
                L"恢复失败，已返回到本次操作前状态：\r\n" + error}
            : OperationResult{OperationOutcome::PartialSuccess,
                L"恢复失败且无法完整返回到本次操作前状态。\r\n原始错误：" +
                error + L"\r\n回滚错误：" + rollback};
    }
};

const std::array<PolicyValue, 6> ModernUpdateController::kPolicies = {{
    {kWindowsUpdate, L"ExcludeWUDriversInQualityUpdate"},
    {kWindowsUpdate, L"SetUpdateNotificationLevel"},
    {kWindowsUpdate, L"UpdateNotificationLevel"},
    {kAutomaticUpdates, L"NoAutoUpdate"},
    {kAutomaticUpdates, L"NoAutoRebootWithLoggedOnUsers"},
    {kAutomaticUpdates, L"AUOptions"}
}};
const PolicyValue ModernUpdateController::kDisableWindowsUpdateAccess =
    {kWindowsUpdate, L"SetDisableUXWUAccess"};

struct ServiceState {
    DWORD startupType;
    bool delayed;
    DWORD status;
};

ScopedServiceHandle OpenWuauserv(DWORD access) {
    ScopedServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.value) ThrowWin32(L"OpenSCManager");
    SC_HANDLE raw = OpenServiceW(manager.value, L"wuauserv", access);
    if (!raw) ThrowWin32(L"OpenService(wuauserv)");
    return ScopedServiceHandle(raw);
}

DWORD QueryServiceStatusStable(DWORD timeoutMs) {
    ScopedServiceHandle service = OpenWuauserv(SERVICE_QUERY_STATUS);
    const DWORD start = GetTickCount();
    for (;;) {
        SERVICE_STATUS_PROCESS status = {};
        DWORD needed = 0;
        if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<BYTE*>(&status), sizeof(status), &needed)) ThrowWin32(L"QueryServiceStatusEx");
        if (status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_STOPPED ||
            status.dwCurrentState == SERVICE_PAUSED) return status.dwCurrentState;
        if (GetTickCount() - start >= timeoutMs) throw AppError(L"等待 wuauserv 稳定状态超时。" );
        Sleep(200);
    }
}

ServiceState ReadServiceState(DWORD timeoutMs) {
    const DWORD status = QueryServiceStatusStable(timeoutMs);
    if (status != SERVICE_RUNNING && status != SERVICE_STOPPED) {
        throw AppError(L"wuauserv 处于不支持的暂停状态。" );
    }
    ScopedServiceHandle service = OpenWuauserv(SERVICE_QUERY_CONFIG);
    DWORD needed = 0;
    QueryServiceConfigW(service.value, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !needed) ThrowWin32(L"QueryServiceConfig 大小");
    std::vector<BYTE> buffer(needed);
    auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (!QueryServiceConfigW(service.value, config, needed, &needed)) ThrowWin32(L"QueryServiceConfig");
    SERVICE_DELAYED_AUTO_START_INFO delayed = {};
    if (!QueryServiceConfig2W(service.value, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
        reinterpret_cast<BYTE*>(&delayed), sizeof(delayed), &needed)) ThrowWin32(L"QueryServiceConfig2");
    return ServiceState{config->dwStartType, delayed.fDelayedAutostart != FALSE, status};
}

void ChangeServiceStartup(DWORD startupType) {
    ScopedServiceHandle service = OpenWuauserv(SERVICE_CHANGE_CONFIG);
    if (!ChangeServiceConfigW(service.value, SERVICE_NO_CHANGE, startupType, SERVICE_NO_CHANGE,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) ThrowWin32(L"ChangeServiceConfig");
}

void ChangeServiceDelayed(bool delayed) {
    ScopedServiceHandle service = OpenWuauserv(SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
    SERVICE_DELAYED_AUTO_START_INFO info = {delayed ? TRUE : FALSE};
    if (!ChangeServiceConfig2W(service.value, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &info)) {
        ThrowWin32(L"ChangeServiceConfig2");
    }
}

void WaitForService(DWORD wanted, DWORD timeoutMs) {
    const DWORD start = GetTickCount();
    while (GetTickCount() - start < timeoutMs) {
        if (QueryServiceStatusStable(timeoutMs) == wanted) return;
        Sleep(200);
    }
    throw AppError(L"等待 wuauserv 状态超时。" );
}

void StopServiceSafe(DWORD timeoutMs) {
    const DWORD state = QueryServiceStatusStable(timeoutMs);
    if (state == SERVICE_STOPPED) return;
    if (state != SERVICE_RUNNING) throw AppError(L"wuauserv 不处于可安全停止状态。" );
    ScopedServiceHandle service = OpenWuauserv(SERVICE_STOP | SERVICE_QUERY_STATUS);
    SERVICE_STATUS status = {};
    if (!ControlService(service.value, SERVICE_CONTROL_STOP, &status)) ThrowWin32(L"停止 wuauserv");
    WaitForService(SERVICE_STOPPED, timeoutMs);
}

void StartServiceSafe(DWORD timeoutMs) {
    if (QueryServiceStatusStable(timeoutMs) == SERVICE_RUNNING) return;
    ScopedServiceHandle service = OpenWuauserv(SERVICE_START | SERVICE_QUERY_STATUS);
    if (!StartServiceW(service.value, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        ThrowWin32(L"启动 wuauserv");
    }
    WaitForService(SERVICE_RUNNING, timeoutMs);
}

void StopAndDisableWuauserv() {
    const DWORD state = QueryServiceStatusStable(30000);
    if (state != SERVICE_RUNNING && state != SERVICE_STOPPED) throw AppError(L"wuauserv 状态不稳定。" );
    StopServiceSafe(30000);
    ChangeServiceStartup(SERVICE_DISABLED);
    const ServiceState verified = ReadServiceState(30000);
    if (verified.startupType != SERVICE_DISABLED || verified.status != SERVICE_STOPPED) {
        throw AppError(L"wuauserv 停止或禁用后的 SCM 回读校验失败。" );
    }
}

void RestoreWuauserv(const ServiceState& original) {
    if (original.startupType < SERVICE_AUTO_START || original.startupType > SERVICE_DISABLED) {
        throw AppError(L"服务备份包含无效启动类型。" );
    }
    const DWORD current = QueryServiceStatusStable(30000);
    if (current != SERVICE_RUNNING && current != SERVICE_STOPPED) throw AppError(L"wuauserv 状态不稳定。" );
    if (original.status == SERVICE_RUNNING) {
        if (current == SERVICE_STOPPED) {
            ChangeServiceStartup(original.startupType == SERVICE_DISABLED ? SERVICE_DEMAND_START : original.startupType);
            StartServiceSafe(30000);
        }
        ChangeServiceStartup(original.startupType);
        ChangeServiceDelayed(original.delayed);
    } else {
        if (current == SERVICE_RUNNING) StopServiceSafe(30000);
        ChangeServiceStartup(original.startupType);
        ChangeServiceDelayed(original.delayed);
    }
}

bool IsWindowsUpdateInstallerBusy() {
    IUpdateSession* session = nullptr;
    const HRESULT created = CoCreateInstance(__uuidof(UpdateSession), nullptr,
        CLSCTX_INPROC_SERVER, __uuidof(IUpdateSession), reinterpret_cast<void**>(&session));
    if (FAILED(created) || !session) throw AppError(L"无法创建 Windows Update Agent 会话。" );
    IUpdateInstaller* installer = nullptr;
    const HRESULT madeInstaller = session->CreateUpdateInstaller(&installer);
    session->Release();
    if (FAILED(madeInstaller) || !installer) throw AppError(L"无法创建 Windows Update 安装器对象。" );
    VARIANT_BOOL busy = VARIANT_FALSE;
    const HRESULT queried = installer->get_IsBusy(&busy);
    installer->Release();
    if (FAILED(queried)) throw AppError(L"无法读取 Windows Update 安装状态。" );
    return busy != VARIANT_FALSE;
}

class Windows7UpdateController : public IUpdateController {
public:
    Windows7UpdateController() : backupPath_(BackupDirectory() + L"\\windows7-original-state-v1.txt") {}
    std::wstring DisplayName() const override { return L"Windows 7"; }
    std::wstring Description() const override { return L"通过 Windows 7 专用更新策略和 Windows Update 服务禁止自动更新与更新访问。"; }
    std::wstring Warning() const override { return L"Win7 模式仅处理 NoAutoUpdate、DisableWindowsUpdateAccess 和 wuauserv。\r\n不会修改 BITS、CryptSvc、TrustedInstaller、系统文件或更新缓存目录权限。"; }
    std::wstring Confirmation() const override { return L"这会设置 Windows 7 更新策略，并停止、禁用 Windows Update 服务 wuauserv。"; }
    std::wstring DisableButtonText() const override { return L"关闭所有 Windows 更新"; }
    bool CanRestore() const override { return FileExists(backupPath_); }
#ifdef UPDATELOCK_TEST
    void TestReadBackup() const { (void)ReadBackup(); }
    const std::wstring& TestBackupPath() const { return backupPath_; }
    void TestSetBackupPath(const std::wstring& path) { backupPath_ = path; }
#endif

    UpdateStatus GetStatus() const override {
        const bool automatic = IsValue(kNoAutoUpdate, 1);
        const bool access = IsValue(kDisableAccess, 1);
        const ServiceState service = ReadServiceState(15000);
        const bool startupDisabled = service.startupType == SERVICE_DISABLED;
        const bool stopped = service.status == SERVICE_STOPPED;
        const int count = automatic + access + startupDisabled + stopped;
        const StatusLevel level = count == 4 ? StatusLevel::Disabled : count == 0 ? StatusLevel::Enabled : StatusLevel::PartiallyDisabled;
        const std::wstring title = level == StatusLevel::Disabled ? L"Windows Update 已禁用" :
            level == StatusLevel::PartiallyDisabled ? L"Windows Update 部分禁用" : L"Windows Update 未禁用";
        return {level, title, {
            std::wstring(L"自动更新策略：") + (automatic ? L"已禁用" : L"未禁用") + L"    Windows Update 访问：" + (access ? L"已禁用" : L"未禁用"),
            std::wstring(L"Windows Update 服务启动：") + (startupDisabled ? L"已禁用" : StartupName(service.startupType)),
            std::wstring(L"Windows Update 服务状态：") + (stopped ? L"已停止" : L"正在运行")}};
    }

    OperationResult Disable() override {
        Win7State before;
        try {
            before = Capture();
            if (before.service.status == SERVICE_RUNNING && IsWindowsUpdateInstallerBusy()) {
                return {OperationOutcome::Failed, L"Windows Update 正在安装或卸载更新。为避免中断系统维护，本次未修改任何设置。"};
            }
        } catch (const AppError& e) { return {OperationOutcome::Failed, L"读取 Win7 当前状态失败，系统未修改：\r\n" + e.message}; }
        int completed = 0;
        try {
            SaveOriginalIfNeeded(before);
            SetDword(kNoAutoUpdate, 1); VerifyValue(kNoAutoUpdate, 1); ++completed;
            SetDword(kDisableAccess, 1); VerifyValue(kDisableAccess, 1); ++completed;
            StopAndDisableWuauserv(); ++completed;
            if (GetStatus().level != StatusLevel::Disabled) throw AppError(L"Win7 禁用后状态回读未全部满足。" );
            return {OperationOutcome::Success, L"Windows 7 更新策略和 wuauserv 已全部禁用，并已逐项回读确认。"};
        } catch (const AppError& e) {
            return DisableFailure(before, completed, e.message);
        } catch (...) {
            return DisableFailure(before, completed, L"发生未预期的原生运行时错误。");
        }
    }

    OperationResult Restore() override {
        Win7State before;
        try {
            before = Capture();
            if (before.service.status == SERVICE_RUNNING && IsWindowsUpdateInstallerBusy()) return {OperationOutcome::Failed, L"Windows Update 正在安装或卸载更新。为避免中断系统维护，本次未修改任何设置。"};
        } catch (const AppError& e) { return {OperationOutcome::Failed, L"读取 Win7 当前状态失败，系统未修改：\r\n" + e.message}; }
        try {
            const Win7State original = ReadBackup(); Apply(original); Verify(original);
            if (!DeleteFileW(backupPath_.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) return {OperationOutcome::PartialSuccess, L"Windows 7 原始状态已恢复并验证，但无法删除备份文件：\r\n" + Win32Message(GetLastError())};
            return {OperationOutcome::Success, L"Windows 7 更新策略和 wuauserv 已恢复到第一次禁用前的原始状态。"};
        } catch (const AppError& e) {
            return RestoreFailure(before, e.message);
        } catch (...) {
            return RestoreFailure(before, L"发生未预期的原生运行时错误。");
        }
    }

private:
    struct Win7State { PolicyState noAuto; PolicyState access; ServiceState service; };
    static const PolicyValue kNoAutoUpdate;
    static const PolicyValue kDisableAccess;
    std::wstring backupPath_;
    static bool IsValue(const PolicyValue& p, int32_t v) { const auto s=ReadDwordState(p); return s.exists && s.value==v; }
    static std::wstring StartupName(DWORD type) { return type==SERVICE_AUTO_START?L"自动":type==SERVICE_DEMAND_START?L"手动":type==SERVICE_DISABLED?L"已禁用":L"未知"; }
    static Win7State Capture() { return {ReadDwordState(kNoAutoUpdate), ReadDwordState(kDisableAccess), ReadServiceState(30000)}; }
    static void VerifyValue(const PolicyValue& p, int32_t v) { if(!IsValue(p,v)) throw AppError(std::wstring(p.name)+L" 写入后回读失败。" ); }
    void SaveOriginalIfNeeded(const Win7State& s) {
        PrepareBackupDirectory(); if(FileExists(backupPath_)){(void)ReadBackup();return;}
        std::vector<std::string> lines={"UpdateLock-Windows7|1",PolicyLine(s.noAuto),PolicyLine(s.access),
            "SERVICE|wuauserv|"+std::to_string(s.service.startupType)+"|"+(s.service.status==SERVICE_RUNNING?"1":"0")+"|"+(s.service.delayed?"1":"0")};
        WriteUtf8LinesAtomically(backupPath_,lines,true); (void)ReadBackup();
    }
    static std::string PolicyLine(const PolicyState& s){return "DWORD|"+Base64Encode(s.policy->path)+"|"+Base64Encode(s.policy->name)+"|"+(s.exists?"1":"0")+"|"+std::to_string(s.value);}
    static PolicyState ParsePolicy(const std::string& line,const PolicyValue& allowed){auto p=Split(line,'|');if(p.size()!=5||p[0]!="DWORD"||Base64Decode(p[1])!=allowed.path||Base64Decode(p[2])!=allowed.name||(p[3]!="0"&&p[3]!="1"))throw AppError(L"Win7 策略备份包含未允许项或无效值。" );return {&allowed,p[3]=="1",ParseInt32(p[4])};}
    Win7State ReadBackup() const {
        auto l=ReadUtf8Lines(backupPath_);if(l.size()!=4||l[0]!="UpdateLock-Windows7|1")throw AppError(L"Win7 原始状态备份格式或版本无效。" );
        auto service=Split(l[3],'|');if(service.size()!=5||service[0]!="SERVICE"||service[1]!="wuauserv"||(service[3]!="0"&&service[3]!="1")||(service[4]!="0"&&service[4]!="1"))throw AppError(L"Win7 服务备份格式无效。" );
        int32_t start=ParseInt32(service[2]);if(start<2||start>4)throw AppError(L"Win7 服务备份格式无效。" );
        const DWORD savedStatus = service[3] == "1" ? static_cast<DWORD>(SERVICE_RUNNING) : static_cast<DWORD>(SERVICE_STOPPED);
        return {ParsePolicy(l[1],kNoAutoUpdate),ParsePolicy(l[2],kDisableAccess),{static_cast<DWORD>(start),service[4]=="1",savedStatus}};
    }
    static void Apply(const Win7State& s){RestorePolicy(s.noAuto);RestorePolicy(s.access);RestoreWuauserv(s.service);}
    static void Verify(const Win7State& s){VerifyPolicy(s.noAuto);VerifyPolicy(s.access);auto a=ReadServiceState(30000);if(a.startupType!=s.service.startupType||a.delayed!=s.service.delayed||a.status!=s.service.status)throw AppError(L"wuauserv 恢复后状态与原始备份不一致。" );}
    static std::wstring TryApply(const Win7State& s){try{Apply(s);Verify(s);return L"";}catch(const AppError&e){return e.message;}catch(...){return L"回滚时发生未预期的原生运行时错误。";}}
    static OperationResult DisableFailure(const Win7State& before,int completed,const std::wstring& error){const std::wstring rollback=TryApply(before);if(!rollback.empty())return{OperationOutcome::PartialSuccess,L"Win7 禁用部分失败且回滚不完整。\r\n原始错误："+error+L"\r\n回滚错误："+rollback};if(completed>0)return{OperationOutcome::PartialSuccess,L"Win7 禁用执行到第 "+std::to_wstring(completed)+L" 个已验证步骤后失败；已完整恢复到操作前状态，当前没有保留部分禁用效果。\r\n失败原因："+error};return{OperationOutcome::Failed,L"Win7 禁用未完成，已确认系统仍为操作前状态：\r\n"+error};}
    static OperationResult RestoreFailure(const Win7State& before,const std::wstring& error){const std::wstring rollback=TryApply(before);return rollback.empty()?OperationResult{OperationOutcome::Failed,L"Win7 恢复失败，已返回到本次操作前状态：\r\n"+error}:OperationResult{OperationOutcome::PartialSuccess,L"Win7 恢复失败且无法完整返回到本次操作前状态。\r\n原始错误："+error+L"\r\n回滚错误："+rollback};}
};

const PolicyValue Windows7UpdateController::kNoAutoUpdate={kAutomaticUpdates,L"NoAutoUpdate"};
const PolicyValue Windows7UpdateController::kDisableAccess={kWindowsUpdate,L"DisableWindowsUpdateAccess"};

class Windows11UpgradeBlocker {
public:
    Windows11UpgradeBlocker() : backupPath_(BackupDirectory() + L"\\windows11-upgrade-backup-v1.txt") {}

    std::wstring Description() const {
        return L"仅在 Windows 10 上锁定当前功能版本，阻止正常 Windows Update 路径升级到 Windows 11。";
    }

    std::wstring Warning() const {
        return L"Windows 11 升级控制只写入 ProductVersion、TargetReleaseVersion 和 TargetReleaseVersionInfo。\r\n"
               L"不会禁用更新服务，不修改 TPM、Secure Boot 或硬件兼容性检查。";
    }

    std::wstring Confirmation() const {
        return L"这会把当前 Windows 10 锁定在当前实际功能版本，阻止正常 Windows Update 路径升级到 Windows 11。\r\n"
               L"不会自动把旧版 Windows 10 升级到 22H2，也不会修改 Windows 自动更新控制。";
    }

    std::wstring BlockButtonText() const { return L"禁止升级到 Windows 11"; }
    std::wstring RestoreButtonText() const { return L"恢复允许升级到 Windows 11"; }
    bool CanRestore(const VersionInfo& version) const {
        return IsWindows10(version) && FileExists(backupPath_);
    }

#ifdef UPDATELOCK_TEST
    const std::wstring& TestBackupPath() const { return backupPath_; }
    void TestSetBackupPath(const std::wstring& path) { backupPath_ = path; }
    std::array<RawRegistryState, 3> TestReadBackup() const { return ReadBackup(); }
    static UpdateStatus TestBuildStatus(const Windows10VersionInfo& version, bool anyValues,
        bool productTarget, bool targetTarget, bool infoTarget, const std::wstring& configuredInfo) {
        return BuildStatus(version, anyValues, productTarget, targetTarget, infoTarget, configuredInfo);
    }
#endif

    UpdateStatus GetStatus(const VersionInfo& version) const {
        if (!IsWindows10(version)) {
            if (version.major == 10 && version.build >= 22000) {
                return UpdateStatus{StatusLevel::Enabled,
                    L"Windows 11 升级状态：当前系统已是 Windows 11",
                    {L"当前系统已是 Windows 11；本功能不适用。"}};
            }
            return UpdateStatus{StatusLevel::Enabled,
                L"Windows 11 升级状态：当前系统不适用",
                {L"本功能只适用于 Windows 10，当前系统不会读取或写入升级锁定策略。"}};
        }

        const Windows10VersionInfo detected = Windows10VersionDetector::Detect(version);
        if (!detected.known) {
            return UpdateStatus{StatusLevel::PartiallyDisabled,
                L"Windows 11 升级状态：无法确认当前功能版本",
                {L"当前系统：Windows 10", L"OS Build：" + std::to_wstring(detected.build) +
                    (detected.revision ? L"." + std::to_wstring(detected.revision) : L""), detected.error}};
        }

        const std::array<RawRegistryState, 3> states = Capture();
        const bool productTarget = IsStringTarget(states[0], L"Windows 10");
        const bool targetTarget = IsRegistryDword(states[1], 1);
        const std::wstring configuredInfo = RawRegistryString(states[2]);
        const bool infoTarget = states[2].exists && states[2].type == REG_SZ &&
            configuredInfo == detected.functionalVersion;
        const bool anyValues = states[0].exists || states[1].exists || states[2].exists;
        return BuildStatus(detected, anyValues, productTarget, targetTarget, infoTarget, configuredInfo);
    }

    OperationResult Block(const VersionInfo& version) {
        const Windows10VersionInfo detected = Windows10VersionDetector::Detect(version);
        if (!detected.isWindows10) {
            return {OperationOutcome::Failed,
                L"“禁止升级到 Windows 11”只适用于 Windows 10，当前系统未修改。"};
        }
        if (!detected.known) return {OperationOutcome::Failed, detected.error};

        const std::array<RawRegistryState, 3> before = Capture();
        try {
            SaveOriginalIfNeeded(before);
            ApplyTarget(detected);
            const UpdateStatus status = GetStatus(version);
            if (status.title != L"Windows 11 升级状态：已阻止") {
                throw AppError(L"Windows 11 升级锁定写入后整体回读未达到目标状态。" );
            }
            return {OperationOutcome::Success,
                L"已将当前 Windows 10 锁定在功能版本 " + detected.functionalVersion + L"。\r\n\r\n"
                L"Windows 11 正常升级路径已阻止。"};
        } catch (const AppError& error) {
            return BlockFailure(before, error.message);
        } catch (...) {
            return BlockFailure(before, L"发生未预期的原生运行时错误。");
        }
    }

    OperationResult Restore(const VersionInfo& version) {
        if (!IsWindows10(version)) {
            return {OperationOutcome::Failed,
                L"“恢复允许升级到 Windows 11”只适用于 Windows 10，当前系统未修改。"};
        }
        const std::array<RawRegistryState, 3> before = Capture();
        try {
            const std::array<RawRegistryState, 3> original = ReadBackup();
            RestoreStates(original);
            VerifyStates(original);
            if (!DeleteFileW(backupPath_.c_str())) {
                const DWORD error = GetLastError();
                if (error != ERROR_FILE_NOT_FOUND) {
                    return {OperationOutcome::PartialSuccess,
                        L"Windows 11 升级策略已经恢复并验证，但无法删除备份文件：\r\n" +
                        Win32Message(error)};
                }
            }
            return {OperationOutcome::Success, L"已恢复允许升级到 Windows 11，并还原首次操作前的原始策略状态。"};
        } catch (const AppError& error) {
            return RestoreFailure(before, error.message);
        } catch (...) {
            return RestoreFailure(before, L"发生未预期的原生运行时错误。");
        }
    }

private:
    static const std::array<PolicyValue, 3> kPolicies;
    std::wstring backupPath_;

    static bool IsWindows10(const VersionInfo& version) {
        return version.major == 10 && version.minor == 0 && version.build < 22000;
    }

    static std::array<RawRegistryState, 3> Capture() {
        return {ReadRawRegistryState(kPolicies[0]), ReadRawRegistryState(kPolicies[1]),
                ReadRawRegistryState(kPolicies[2])};
    }

    static bool IsStringTarget(const RawRegistryState& state, const std::wstring& expected) {
        return state.exists && state.type == REG_SZ && RawRegistryString(state) == expected;
    }

    static UpdateStatus BuildStatus(const Windows10VersionInfo& version, bool anyValues,
        bool productTarget, bool targetTarget, bool infoTarget, const std::wstring& configuredInfo) {
        if (!anyValues) {
            return UpdateStatus{StatusLevel::Enabled, L"Windows 11 升级状态：允许", {
                L"当前系统：Windows 10 " + version.functionalVersion,
                L"OS Build：" + std::to_wstring(version.build) +
                    (version.revision ? L"." + std::to_wstring(version.revision) : L""),
                L"目标产品：未配置"}};
        }
        if (productTarget && targetTarget && infoTarget) {
            return UpdateStatus{StatusLevel::Disabled, L"Windows 11 升级状态：已阻止", {
                L"当前系统：Windows 10 " + version.functionalVersion,
                L"OS Build：" + std::to_wstring(version.build) +
                    (version.revision ? L"." + std::to_wstring(version.revision) : L""),
                L"锁定版本：Windows 10 " + version.functionalVersion}};
        }
        if (productTarget && targetTarget && !configuredInfo.empty() && !infoTarget) {
            return UpdateStatus{StatusLevel::PartiallyDisabled,
                L"Windows 11 升级状态：目标版本与当前系统不一致", {
                    L"当前系统：Windows 10 " + version.functionalVersion,
                    L"配置目标：Windows 10 " + configuredInfo,
                    L"请重新点击“禁止升级到 Windows 11”更新当前目标版本。"}};
        }
        return UpdateStatus{StatusLevel::PartiallyDisabled, L"Windows 11 升级状态：部分配置", {
            L"当前系统：Windows 10 " + version.functionalVersion,
            std::wstring(L"ProductVersion：") + (productTarget ? L"Windows 10" : L"未达到目标"),
            std::wstring(L"TargetReleaseVersion：") + (targetTarget ? L"1" : L"未达到目标"),
            std::wstring(L"TargetReleaseVersionInfo：") + (infoTarget ? version.functionalVersion : L"未达到目标")}};
    }

    void SaveOriginalIfNeeded(const std::array<RawRegistryState, 3>& original) {
        PrepareBackupDirectory();
        if (FileExists(backupPath_)) { (void)ReadBackup(); return; }
        std::vector<std::string> lines{"UpdateLock-Windows11Upgrade|1"};
        for (const RawRegistryState& state : original) {
            lines.push_back("RAW|" + Base64Encode(state.policy->path) + "|" +
                Base64Encode(state.policy->name) + "|" + (state.exists ? "1" : "0") + "|" +
                std::to_string(state.type) + "|" + Base64EncodeBytes(state.data));
        }
        WriteUtf8LinesAtomically(backupPath_, lines, false);
    }

    std::array<RawRegistryState, 3> ReadBackup() const {
        const std::vector<std::string> lines = ReadUtf8Lines(backupPath_);
        if (lines.size() != 4 || lines[0] != "UpdateLock-Windows11Upgrade|1") {
            throw AppError(L"Windows 11 升级备份格式无效。" );
        }
        std::array<RawRegistryState, 3> result{};
        for (size_t i = 0; i < kPolicies.size(); ++i) {
            const std::vector<std::string> parts = Split(lines[i + 1], '|');
            if (parts.size() != 6 || parts[0] != "RAW" || (parts[3] != "0" && parts[3] != "1")) {
                throw AppError(L"Windows 11 升级备份包含无效项目。" );
            }
            const std::wstring path = Base64Decode(parts[1]);
            const std::wstring name = Base64Decode(parts[2]);
            const PolicyValue* allowed = nullptr;
            for (const PolicyValue& policy : kPolicies) {
                if (SamePolicy(policy, path, name)) allowed = &policy;
            }
            if (!allowed) throw AppError(L"Windows 11 升级备份包含未允许项目。" );
            for (size_t j = 0; j < i; ++j) {
                if (result[j].policy == allowed) throw AppError(L"Windows 11 升级备份包含重复项目。" );
            }
            const int32_t type = ParseInt32(parts[4]);
            const std::vector<BYTE> data = Base64DecodeBytes(parts[5]);
            if (type < 0 || (parts[3] == "0" && (type != 0 || !data.empty())) ||
                (parts[3] == "1" && type == 0)) {
                throw AppError(L"Windows 11 升级备份值类型无效。" );
            }
            result[i] = RawRegistryState{allowed, parts[3] == "1", static_cast<DWORD>(type), data};
        }
        for (const PolicyValue& policy : kPolicies) {
            bool found = false;
            for (const RawRegistryState& state : result) if (state.policy == &policy) found = true;
            if (!found) throw AppError(L"Windows 11 升级备份缺少必要项目。" );
        }
        return result;
    }

    static void RestoreStates(const std::array<RawRegistryState, 3>& states) {
        for (const RawRegistryState& state : states) RestoreRawRegistryState(state);
    }

    static void VerifyStates(const std::array<RawRegistryState, 3>& states) {
        for (const RawRegistryState& state : states) VerifyRawRegistryState(state);
    }

    static void ApplyTarget(const Windows10VersionInfo& version) {
        const RawRegistryState product = MakeRegistryStringState(kPolicies[0], L"Windows 10");
        SetRawRegistryState(product); VerifyRawRegistryState(product);
        const RawRegistryState target = MakeRegistryDwordState(kPolicies[1], 1);
        SetRawRegistryState(target); VerifyRawRegistryState(target);
        const RawRegistryState info = MakeRegistryStringState(kPolicies[2], version.functionalVersion);
        SetRawRegistryState(info); VerifyRawRegistryState(info);
    }

    static std::wstring TryRestore(const std::array<RawRegistryState, 3>& states) {
        try { RestoreStates(states); VerifyStates(states); return std::wstring(); }
        catch (const AppError& error) { return error.message; }
        catch (...) { return L"回滚时发生未预期的原生运行时错误。"; }
    }

    static OperationResult BlockFailure(const std::array<RawRegistryState, 3>& before,
        const std::wstring& error) {
        const std::wstring rollback = TryRestore(before);
        return rollback.empty()
            ? OperationResult{OperationOutcome::Failed, L"Windows 11 升级锁定未完成，已恢复到操作前状态：\r\n" + error}
            : OperationResult{OperationOutcome::PartialSuccess,
                L"Windows 11 升级锁定失败且回滚不完整。\r\n原始错误：" + error +
                L"\r\n回滚错误：" + rollback};
    }

    static OperationResult RestoreFailure(const std::array<RawRegistryState, 3>& before,
        const std::wstring& error) {
        const std::wstring rollback = TryRestore(before);
        return rollback.empty()
            ? OperationResult{OperationOutcome::Failed, L"Windows 11 升级恢复失败，已返回到本次操作前状态：\r\n" + error}
            : OperationResult{OperationOutcome::PartialSuccess,
                L"Windows 11 升级恢复失败且回滚不完整。\r\n原始错误：" + error +
                L"\r\n回滚错误：" + rollback};
    }
};

const std::array<PolicyValue, 3> Windows11UpgradeBlocker::kPolicies = {{
    {kWindowsUpdate, L"ProductVersion"},
    {kWindowsUpdate, L"TargetReleaseVersion"},
    {kWindowsUpdate, L"TargetReleaseVersionInfo"}
}};

struct UiContext {
    std::unique_ptr<IUpdateController> controller;
    Windows11UpgradeBlocker upgradeBlocker;
    VersionInfo version{};
    HWND system = nullptr;
    HWND description = nullptr;
    HWND status = nullptr;
    HWND details = nullptr;
    HWND disableButton = nullptr;
    HWND restoreButton = nullptr;
    HWND upgradeStatus = nullptr;
    HWND upgradeDetails = nullptr;
    HWND upgradeDisableButton = nullptr;
    HWND upgradeRestoreButton = nullptr;
    HWND warning = nullptr;
    HFONT normalFont = nullptr;
    HFONT titleFont = nullptr;
    HFONT statusFont = nullptr;
    HBRUSH backgroundBrush = nullptr;
    HBRUSH statusBrush = nullptr;
    HBRUSH upgradeBrush = nullptr;
    HBRUSH warningBrush = nullptr;
    COLORREF statusColor = RGB(0, 120, 70);
    COLORREF upgradeStatusColor = RGB(0, 120, 70);
    int dpi = 96;
};

int ScaleForDpi(int value, int dpi) {
    return MulDiv(value, dpi, 96);
}

void FillRoundedPanel(HDC dc, const RECT& rect, COLORREF fill, COLORREF border,
    int radius) {
    HBRUSH brush = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ oldBrush = SelectObject(dc, brush);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, radius, radius);
    SelectObject(dc, oldPen);
    SelectObject(dc, oldBrush);
    DeleteObject(pen);
    DeleteObject(brush);
}

void DrawOwnerButton(const DRAWITEMSTRUCT& item) {
    wchar_t text[160] = {};
    GetWindowTextW(item.hwndItem, text, static_cast<int>(std::size(text)));
    const bool primary = item.CtlID == IDC_DISABLE || item.CtlID == IDC_UPGRADE_DISABLE;
    const bool disabled = (item.itemState & ODS_DISABLED) != 0;
    const bool pressed = (item.itemState & ODS_SELECTED) != 0;
    COLORREF fill = primary ? RGB(20, 112, 194) : RGB(255, 255, 255);
    COLORREF border = primary ? RGB(20, 112, 194) : RGB(181, 190, 201);
    COLORREF foreground = primary ? RGB(255, 255, 255) : RGB(38, 50, 64);
    if (pressed && !disabled) {
        fill = primary ? RGB(13, 86, 151) : RGB(233, 238, 244);
    }
    if (disabled) {
        fill = RGB(239, 242, 246);
        border = RGB(211, 217, 224);
        foreground = RGB(145, 153, 163);
    }
    RECT rect = item.rcItem;
    FillRoundedPanel(item.hDC, rect, fill, border, 10);
    SetBkMode(item.hDC, TRANSPARENT);
    SetTextColor(item.hDC, foreground);
    HGDIOBJ oldFont = SelectObject(item.hDC,
        reinterpret_cast<HGDIOBJ>(SendMessageW(item.hwndItem, WM_GETFONT, 0, 0)));
    DrawTextW(item.hDC, text, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(item.hDC, oldFont);
    if ((item.itemState & ODS_FOCUS) && !disabled) {
        RECT focus = rect;
        InflateRect(&focus, -5, -5);
        DrawFocusRect(item.hDC, &focus);
    }
}

void SetControlFont(HWND control, HFONT font) {
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

std::wstring JoinDetails(const std::vector<std::wstring>& details) {
    std::wstring result;
    for (size_t i = 0; i < details.size(); ++i) {
        if (i) result += L"\r\n";
        result += details[i];
    }
    return result;
}

std::wstring BuildSystemLabel(const VersionInfo& version, const std::wstring& displayName) {
    std::wstring result = L"当前系统：" + displayName;
    if (version.major == 10 && version.minor == 0 && version.build < 22000) {
        try {
            const Windows10VersionInfo detected = Windows10VersionDetector::Detect(version);
            if (detected.known) {
                result += L"  功能版本：" + detected.functionalVersion;
                if (detected.source == Windows10VersionSource::BuildMapping) result += L"（根据 Build 识别）";
            }
        } catch (const AppError&) {
            // Keep startup usable; the upgrade panel reports detailed detection errors.
        }
    }
    result += L"  Build：" + std::to_wstring(version.build);
    return result;
}

void RefreshUi(HWND window, UiContext& ui) {
    (void)window;
    try {
        const UpdateStatus status = ui.controller->GetStatus();
        SetWindowTextW(ui.status, (L"状态：" + status.title).c_str());
        SetWindowTextW(ui.details, JoinDetails(status.details).c_str());
        ui.statusColor = status.level == StatusLevel::Disabled ? RGB(0, 120, 70) :
                         status.level == StatusLevel::PartiallyDisabled ? RGB(184, 108, 0) : RGB(170, 38, 38);
        EnableWindow(ui.restoreButton, ui.controller->CanRestore() ? TRUE : FALSE);
        InvalidateRect(ui.status, nullptr, TRUE);
    } catch (const AppError& error) {
        SetWindowTextW(ui.status, L"状态读取失败");
        SetWindowTextW(ui.details, error.message.c_str());
        ui.statusColor = RGB(170, 38, 38);
        EnableWindow(ui.restoreButton, ui.controller->CanRestore() ? TRUE : FALSE);
        InvalidateRect(ui.status, nullptr, TRUE);
    }

    try {
        const UpdateStatus status = ui.upgradeBlocker.GetStatus(ui.version);
        SetWindowTextW(ui.upgradeStatus, status.title.c_str());
        SetWindowTextW(ui.upgradeDetails, JoinDetails(status.details).c_str());
        ui.upgradeStatusColor = status.level == StatusLevel::Disabled ? RGB(0, 120, 70) :
            status.level == StatusLevel::PartiallyDisabled ? RGB(184, 108, 0) : RGB(38, 91, 135);
        EnableWindow(ui.upgradeDisableButton,
            ui.version.major == 10 && ui.version.minor == 0 && ui.version.build < 22000);
        EnableWindow(ui.upgradeRestoreButton, ui.upgradeBlocker.CanRestore(ui.version) ? TRUE : FALSE);
        InvalidateRect(ui.upgradeStatus, nullptr, TRUE);
    } catch (const AppError& error) {
        SetWindowTextW(ui.upgradeStatus, L"Windows 11 升级状态：读取失败");
        SetWindowTextW(ui.upgradeDetails, error.message.c_str());
        ui.upgradeStatusColor = RGB(170, 38, 38);
        EnableWindow(ui.upgradeDisableButton, FALSE);
        EnableWindow(ui.upgradeRestoreButton, FALSE);
        InvalidateRect(ui.upgradeStatus, nullptr, TRUE);
    }
}

void ShowOperationResult(HWND owner, const OperationResult& result) {
    const UINT icon = result.outcome == OperationOutcome::Success ? MB_ICONINFORMATION :
                      result.outcome == OperationOutcome::PartialSuccess ? MB_ICONWARNING : MB_ICONERROR;
    const wchar_t* title = result.outcome == OperationOutcome::Success ? L"操作完成" :
                           result.outcome == OperationOutcome::PartialSuccess ? L"操作部分完成" : L"操作失败";
    MessageBoxW(owner, result.message.c_str(), title, MB_OK | icon);
}

LRESULT WindowProcImpl(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    UiContext* ui = reinterpret_cast<UiContext*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    switch (message) {
    case WM_CREATE: {
        auto create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        ui = reinterpret_cast<UiContext*>(create->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(ui));
        HDC windowDc = GetDC(window);
        if (!windowDc) ThrowWin32(L"读取窗口 DPI");
        const int dpi = GetDeviceCaps(windowDc, LOGPIXELSY);
        ReleaseDC(window, windowDc);
        ui->dpi = dpi;
        ui->backgroundBrush = CreateSolidBrush(RGB(246, 248, 251));
        ui->statusBrush = CreateSolidBrush(RGB(244, 250, 247));
        ui->upgradeBrush = CreateSolidBrush(RGB(244, 248, 252));
        ui->warningBrush = CreateSolidBrush(RGB(255, 249, 235));
        if (!ui->backgroundBrush || !ui->statusBrush || !ui->upgradeBrush || !ui->warningBrush) {
            ThrowWin32(L"创建界面画刷");
        }
        const auto scale = [dpi](int value) { return ScaleForDpi(value, dpi); };
        ui->normalFont = CreateFontW(-MulDiv(9, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        ui->titleFont = CreateFontW(-MulDiv(16, dpi, 72), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        ui->statusFont = CreateFontW(-MulDiv(12, dpi, 72), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

        HWND title = CreateWindowExW(0, L"STATIC", kAppName, WS_CHILD | WS_VISIBLE,
            scale(30), scale(21), scale(435), scale(39), window, nullptr, nullptr, nullptr);
        HWND author = CreateWindowExW(0, L"STATIC", L"作者：啊常用户", WS_CHILD | WS_VISIBLE | SS_RIGHT,
            scale(465), scale(30), scale(140), scale(24), window, nullptr, nullptr, nullptr);
        ui->system = CreateWindowExW(0, L"STATIC", BuildSystemLabel(ui->version, ui->controller->DisplayName()).c_str(), WS_CHILD | WS_VISIBLE,
            scale(34), scale(68), scale(570), scale(24), window, reinterpret_cast<HMENU>(IDC_SYSTEM), nullptr, nullptr);
        ui->description = CreateWindowExW(0, L"STATIC", ui->controller->Description().c_str(), WS_CHILD | WS_VISIBLE,
            scale(34), scale(96), scale(570), scale(46), window, reinterpret_cast<HMENU>(IDC_DESCRIPTION), nullptr, nullptr);
        ui->status = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            scale(46), scale(172), scale(550), scale(30), window, reinterpret_cast<HMENU>(IDC_STATUS), nullptr, nullptr);
        ui->details = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            scale(46), scale(211), scale(550), scale(80), window, reinterpret_cast<HMENU>(IDC_DETAILS), nullptr, nullptr);
        ui->disableButton = CreateWindowExW(0, L"BUTTON", ui->controller->DisableButtonText().c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, scale(26), scale(334), scale(282), scale(52),
            window, reinterpret_cast<HMENU>(IDC_DISABLE), nullptr, nullptr);
        ui->restoreButton = CreateWindowExW(0, L"BUTTON", L"恢复到运行本软件前的状态",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, scale(332), scale(334), scale(282), scale(52),
            window, reinterpret_cast<HMENU>(IDC_RESTORE), nullptr, nullptr);
        HWND upgradeLabel = CreateWindowExW(0, L"STATIC", L"Windows 11 升级控制", WS_CHILD | WS_VISIBLE,
            scale(34), scale(397), scale(570), scale(24), window, nullptr, nullptr, nullptr);
        ui->upgradeStatus = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            scale(46), scale(424), scale(550), scale(30), window, reinterpret_cast<HMENU>(IDC_UPGRADE_STATUS), nullptr, nullptr);
        ui->upgradeDetails = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            scale(46), scale(458), scale(550), scale(65), window, reinterpret_cast<HMENU>(IDC_UPGRADE_DETAILS), nullptr, nullptr);
        ui->upgradeDisableButton = CreateWindowExW(0, L"BUTTON", ui->upgradeBlocker.BlockButtonText().c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, scale(26), scale(530), scale(282), scale(52),
            window, reinterpret_cast<HMENU>(IDC_UPGRADE_DISABLE), nullptr, nullptr);
        ui->upgradeRestoreButton = CreateWindowExW(0, L"BUTTON", ui->upgradeBlocker.RestoreButtonText().c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, scale(332), scale(530), scale(282), scale(52),
            window, reinterpret_cast<HMENU>(IDC_UPGRADE_RESTORE), nullptr, nullptr);
        const std::wstring warningText = ui->controller->Warning() + L"\r\n" + ui->upgradeBlocker.Warning();
        ui->warning = CreateWindowExW(0, L"STATIC", warningText.c_str(), WS_CHILD | WS_VISIBLE,
            scale(42), scale(608), scale(555), scale(100), window, reinterpret_cast<HMENU>(IDC_WARNING), nullptr, nullptr);
        for (HWND control : {title, author, ui->system, ui->description, ui->details,
             ui->disableButton, ui->restoreButton, upgradeLabel, ui->upgradeDetails,
             ui->upgradeDisableButton, ui->upgradeRestoreButton, ui->warning}) SetControlFont(control, ui->normalFont);
        SetControlFont(title, ui->titleFont);
        SetControlFont(ui->status, ui->statusFont);
        SetControlFont(upgradeLabel, ui->statusFont);
        SetControlFont(ui->upgradeStatus, ui->statusFont);
        RefreshUi(window, *ui);
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT paint = {};
        HDC dc = BeginPaint(window, &paint);
        RECT client = {};
        GetClientRect(window, &client);
        FillRect(dc, &client, ui && ui->backgroundBrush ? ui->backgroundBrush :
            reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1));
        if (ui) {
            const auto scale = [ui](int value) { return ScaleForDpi(value, ui->dpi); };
            RECT statusPanel = {scale(26), scale(153), scale(614), scale(313)};
            RECT upgradePanel = {scale(26), scale(386), scale(614), scale(594)};
            RECT warningPanel = {scale(26), scale(594), scale(614), scale(718)};
            FillRoundedPanel(dc, statusPanel, RGB(244, 250, 247), RGB(211, 225, 216), scale(12));
            FillRoundedPanel(dc, upgradePanel, RGB(244, 248, 252), RGB(208, 220, 234), scale(12));
            FillRoundedPanel(dc, warningPanel, RGB(255, 249, 235), RGB(238, 218, 169), scale(12));
        }
        EndPaint(window, &paint);
        return 0;
    }
    case WM_COMMAND:
        if (!ui) break;
        if (LOWORD(wParam) == IDC_DISABLE && HIWORD(wParam) == BN_CLICKED) {
            const std::wstring prompt = ui->controller->Confirmation() + L"\r\n\r\n是否继续？";
            if (MessageBoxW(window, prompt.c_str(), L"确认关闭更新", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return 0;
            EnableWindow(ui->disableButton, FALSE); EnableWindow(ui->restoreButton, FALSE);
            EnableWindow(ui->upgradeDisableButton, FALSE); EnableWindow(ui->upgradeRestoreButton, FALSE);
            try {
                const OperationResult result = ui->controller->Disable();
                ShowOperationResult(window, result);
            } catch (...) {
                MessageBoxW(window, L"发生未预期错误。操作未能完成，请重新检查当前状态。", L"操作失败", MB_OK | MB_ICONERROR);
            }
            RefreshUi(window, *ui);
            EnableWindow(ui->disableButton, TRUE); return 0;
        }
        if (LOWORD(wParam) == IDC_RESTORE && HIWORD(wParam) == BN_CLICKED) {
            if (MessageBoxW(window, L"这会恢复本软件第一次修改前保存的原始状态。\r\n\r\n是否继续？",
                L"确认恢复", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return 0;
            EnableWindow(ui->disableButton, FALSE); EnableWindow(ui->restoreButton, FALSE);
            EnableWindow(ui->upgradeDisableButton, FALSE); EnableWindow(ui->upgradeRestoreButton, FALSE);
            try {
                const OperationResult result = ui->controller->Restore();
                ShowOperationResult(window, result);
            } catch (...) {
                MessageBoxW(window, L"发生未预期错误。恢复未能完成，请重新检查当前状态。", L"操作失败", MB_OK | MB_ICONERROR);
            }
            RefreshUi(window, *ui);
            EnableWindow(ui->disableButton, TRUE); return 0;
        }
        if (LOWORD(wParam) == IDC_UPGRADE_DISABLE && HIWORD(wParam) == BN_CLICKED) {
            const std::wstring prompt = ui->upgradeBlocker.Confirmation() + L"\r\n\r\n是否继续？";
            if (MessageBoxW(window, prompt.c_str(), L"确认禁止升级到 Windows 11",
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return 0;
            EnableWindow(ui->disableButton, FALSE); EnableWindow(ui->restoreButton, FALSE);
            EnableWindow(ui->upgradeDisableButton, FALSE); EnableWindow(ui->upgradeRestoreButton, FALSE);
            try {
                const OperationResult result = ui->upgradeBlocker.Block(ui->version);
                ShowOperationResult(window, result);
            } catch (...) {
                MessageBoxW(window, L"发生未预期错误。操作未能完成，请重新检查当前状态。",
                    L"操作失败", MB_OK | MB_ICONERROR);
            }
            RefreshUi(window, *ui);
            EnableWindow(ui->disableButton, TRUE); return 0;
        }
        if (LOWORD(wParam) == IDC_UPGRADE_RESTORE && HIWORD(wParam) == BN_CLICKED) {
            if (MessageBoxW(window,
                L"这会恢复 Windows 11 升级策略到本软件第一次修改前的原始状态。\r\n\r\n是否继续？",
                L"确认恢复 Windows 11 升级允许状态",
                MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return 0;
            EnableWindow(ui->disableButton, FALSE); EnableWindow(ui->restoreButton, FALSE);
            EnableWindow(ui->upgradeDisableButton, FALSE); EnableWindow(ui->upgradeRestoreButton, FALSE);
            try {
                const OperationResult result = ui->upgradeBlocker.Restore(ui->version);
                ShowOperationResult(window, result);
            } catch (...) {
                MessageBoxW(window, L"发生未预期错误。恢复未能完成，请重新检查当前状态。",
                    L"操作失败", MB_OK | MB_ICONERROR);
            }
            RefreshUi(window, *ui);
            EnableWindow(ui->disableButton, TRUE); return 0;
        }
        break;
    case WM_DRAWITEM:
        if (ui && (wParam == IDC_DISABLE || wParam == IDC_RESTORE ||
            wParam == IDC_UPGRADE_DISABLE || wParam == IDC_UPGRADE_RESTORE)) {
            DrawOwnerButton(*reinterpret_cast<DRAWITEMSTRUCT*>(lParam));
            return TRUE;
        }
        break;
    case WM_CTLCOLORSTATIC:
        if (ui) {
            HDC dc = reinterpret_cast<HDC>(wParam);
            HWND control = reinterpret_cast<HWND>(lParam);
            SetBkMode(dc, TRANSPARENT);
            if (control == ui->status || control == ui->details) {
                SetTextColor(dc, control == ui->status ? ui->statusColor : RGB(48, 61, 73));
                SetBkColor(dc, RGB(244, 250, 247));
                return reinterpret_cast<LRESULT>(ui->statusBrush);
            }
            if (control == ui->upgradeStatus || control == ui->upgradeDetails) {
                SetTextColor(dc, control == ui->upgradeStatus ? ui->upgradeStatusColor : RGB(48, 61, 73));
                SetBkColor(dc, RGB(244, 248, 252));
                return reinterpret_cast<LRESULT>(ui->upgradeBrush);
            }
            if (control == ui->warning) {
                SetTextColor(dc, RGB(133, 78, 0));
                SetBkColor(dc, RGB(255, 249, 235));
                return reinterpret_cast<LRESULT>(ui->warningBrush);
            }
            SetTextColor(dc, RGB(32, 43, 55));
            SetBkColor(dc, RGB(246, 248, 251));
            return reinterpret_cast<LRESULT>(ui->backgroundBrush);
        }
        break;
    case WM_DESTROY:
        if (ui) {
            if (ui->normalFont) DeleteObject(ui->normalFont);
            if (ui->titleFont) DeleteObject(ui->titleFont);
            if (ui->statusFont) DeleteObject(ui->statusFont);
            if (ui->backgroundBrush) DeleteObject(ui->backgroundBrush);
            if (ui->statusBrush) DeleteObject(ui->statusBrush);
            if (ui->upgradeBrush) DeleteObject(ui->upgradeBrush);
            if (ui->warningBrush) DeleteObject(ui->warningBrush);
        }
        PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) noexcept {
    try {
        return WindowProcImpl(window, message, wParam, lParam);
    } catch (const AppError& error) {
        MessageBoxW(window, error.message.c_str(), kAppName, MB_OK | MB_ICONERROR);
    } catch (...) {
        MessageBoxW(window, L"窗口处理发生未预期错误。系统设置不会被继续修改。",
            kAppName, MB_OK | MB_ICONERROR);
    }
    return message == WM_CREATE ? static_cast<LRESULT>(-1) : 0;
}

std::unique_ptr<IUpdateController> CreateController(const VersionInfo& version) {
    if (version.productType != VER_NT_WORKSTATION) throw AppError(L"本工具仅支持 Windows 工作站系统。" );
    if (version.major == 6 && version.minor == 1) return std::unique_ptr<IUpdateController>(new Windows7UpdateController());
    if (version.major == 10 && version.build >= 22000) return std::unique_ptr<IUpdateController>(new ModernUpdateController(L"Windows 11"));
    if (version.major == 10) return std::unique_ptr<IUpdateController>(new ModernUpdateController(L"Windows 10"));
    throw AppError(L"本工具仅支持 Windows 7、Windows 10 和 Windows 11。当前系统不会被修改。" );
}

} // namespace

#ifndef UPDATELOCK_TEST
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(com)) {
        MessageBoxW(nullptr, L"无法初始化 Windows 组件。", kAppName, MB_OK | MB_ICONERROR);
        return 1;
    }
    PSECURITY_DESCRIPTOR mutexDescriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &mutexDescriptor, nullptr)) {
        MessageBoxW(nullptr, L"无法创建跨会话锁权限。系统不会被修改。", kAppName, MB_OK | MB_ICONERROR);
        CoUninitialize(); return 1;
    }
    SECURITY_ATTRIBUTES mutexSecurity = {sizeof(mutexSecurity), mutexDescriptor, FALSE};
    ScopedHandle mutex(CreateMutexW(&mutexSecurity, TRUE, kMutexName));
    const DWORD mutexError = GetLastError();
    LocalFree(mutexDescriptor);
    if (!mutex.value) {
        MessageBoxW(nullptr, (L"无法建立跨会话操作锁：\r\n" + Win32Message(mutexError)).c_str(), kAppName, MB_OK | MB_ICONERROR);
        CoUninitialize(); return 1;
    }
    if (mutexError == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"更新控制工具已在运行。请关闭另一个窗口后再试。", kAppName, MB_OK | MB_ICONINFORMATION);
        CoUninitialize(); return 0;
    }
    try {
        UiContext ui;
        ui.version = ReadWindowsVersion();
        ui.controller = CreateController(ui.version);
        INITCOMMONCONTROLSEX controls = {sizeof(controls), ICC_STANDARD_CLASSES};
        InitCommonControlsEx(&controls);
        WNDCLASSEXW wc = {sizeof(wc)};
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = instance;
        wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_APP_ICON));
        wc.hIconSm = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        wc.lpszClassName = L"AchangUser.UpdateLock.Native";
        if (!RegisterClassExW(&wc)) ThrowWin32(L"注册窗口类");
        HDC screenDc = GetDC(nullptr);
        if (!screenDc) ThrowWin32(L"读取屏幕 DPI");
        const int windowDpi = GetDeviceCaps(screenDc, LOGPIXELSY);
        ReleaseDC(nullptr, screenDc);
        RECT rect = {0, 0, ScaleForDpi(640, windowDpi), ScaleForDpi(730, windowDpi)};
        AdjustWindowRectEx(&rect, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE, 0);
        HWND window = CreateWindowExW(0, wc.lpszClassName, kAppName,
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            CW_USEDEFAULT, CW_USEDEFAULT, rect.right - rect.left, rect.bottom - rect.top,
            nullptr, nullptr, instance, &ui);
        if (!window) ThrowWin32(L"创建主窗口");
        HICON icon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_APP_ICON));
        SendMessageW(window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(icon));
        ShowWindow(window, showCommand);
        UpdateWindow(window);
        MSG message = {};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            if (!IsDialogMessageW(window, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
        }
    } catch (const AppError& error) {
        MessageBoxW(nullptr, error.message.c_str(), kAppName, MB_OK | MB_ICONERROR);
        CoUninitialize(); return 1;
    } catch (...) {
        MessageBoxW(nullptr, L"发生未预期错误。系统设置不会被继续修改。", kAppName, MB_OK | MB_ICONERROR);
        CoUninitialize(); return 1;
    }
    CoUninitialize();
    return 0;
}
#endif
