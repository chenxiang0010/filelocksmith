//! Windows API 封装（公共模块）
//!
//! std.os.windows 里只带了 NtQuerySystemInformation / NtQueryObject 和极少数
//! kernel32 声明，其余这里统一补上，业务模块只 import 本文件，不直接 extern。

const std = @import("std");
const windows = std.os.windows;
const ntdll = windows.ntdll;

pub const HANDLE = windows.HANDLE;
pub const DWORD = windows.DWORD;
pub const ULONG = windows.ULONG;
pub const ULONG_PTR = windows.ULONG_PTR;
pub const WCHAR = windows.WCHAR;
pub const BOOL = windows.BOOL;
pub const NTSTATUS = windows.NTSTATUS;
pub const UNICODE_STRING = windows.UNICODE_STRING;
pub const PVOID = windows.PVOID;

pub const INVALID_HANDLE_VALUE = windows.INVALID_HANDLE_VALUE;
pub const MAX_PATH = 260;

pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = @enumFromInt(@as(u32, 0xC0000004));
pub const STATUS_SUCCESS: NTSTATUS = .SUCCESS;

// ---------------------------------------------------------------- kernel32

pub extern "kernel32" fn OpenProcess(
    dwDesiredAccess: u32,
    bInheritHandle: BOOL,
    dwProcessId: DWORD,
) callconv(.winapi) ?HANDLE;

pub extern "kernel32" fn DuplicateHandle(
    hSourceProcessHandle: HANDLE,
    hSourceHandle: HANDLE,
    hTargetProcessHandle: HANDLE,
    lpTargetHandle: *HANDLE,
    dwDesiredAccess: u32,
    bInheritHandle: BOOL,
    dwOptions: u32,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn CreateFileW(
    lpFileName: [*:0]const u16,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: ?*anyopaque,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: ?HANDLE,
) callconv(.winapi) HANDLE;

pub extern "kernel32" fn GetFileType(hFile: HANDLE) callconv(.winapi) DWORD;

pub extern "kernel32" fn GetFullPathNameW(
    lpFileName: [*:0]const u16,
    nBufferLength: DWORD,
    lpBuffer: [*]u16,
    lpFilePart: ?*?[*:0]u16,
) callconv(.winapi) DWORD;

pub extern "kernel32" fn GetFileAttributesW(
    lpFileName: [*:0]const u16,
) callconv(.winapi) DWORD;

pub extern "kernel32" fn QueryFullProcessImageNameW(
    hProcess: HANDLE,
    dwFlags: DWORD,
    lpExeName: [*]u16,
    lpdwSize: *DWORD,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn EnumProcesses(
    lpidProcess: [*]DWORD,
    cb: DWORD,
    lpcbNeeded: *DWORD,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn CreateEventW(
    lpEventAttributes: ?*anyopaque,
    bManualReset: BOOL,
    bInitialState: BOOL,
    lpName: ?[*:0]const u16,
) callconv(.winapi) ?HANDLE;

pub extern "kernel32" fn SetEvent(hEvent: HANDLE) callconv(.winapi) BOOL;

pub extern "kernel32" fn WaitForSingleObject(
    hHandle: HANDLE,
    dwMilliseconds: DWORD,
) callconv(.winapi) DWORD;

pub extern "kernel32" fn CreateThread(
    lpThreadAttributes: ?*anyopaque,
    dwStackSize: usize,
    lpStartAddress: *const fn (?*anyopaque) callconv(.winapi) DWORD,
    lpParameter: ?*anyopaque,
    dwCreationFlags: DWORD,
    lpThreadId: ?*DWORD,
) callconv(.winapi) ?HANDLE;

pub extern "kernel32" fn TerminateProcess(
    hProcess: HANDLE,
    uExitCode: u32,
) callconv(.winapi) BOOL;

pub extern "kernel32" fn GetLastError() callconv(.winapi) u32;

// ---------------------------------------------------------------- advapi32

pub const LUID = extern struct {
    LowPart: u32,
    HighPart: i32,
};

pub const LUID_AND_ATTRIBUTES = extern struct {
    Luid: LUID,
    Attributes: u32,
};

pub const TOKEN_PRIVILEGES = extern struct {
    PrivilegeCount: u32,
    Privileges: [1]LUID_AND_ATTRIBUTES,
};

pub const TOKEN_USER = extern struct {
    User: SID_AND_ATTRIBUTES,
};

pub const SID_AND_ATTRIBUTES = extern struct {
    Sid: *anyopaque,
    Attributes: u32,
};

pub const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
pub const TOKEN_QUERY: u32 = 0x0008;
pub const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;

pub extern "advapi32" fn OpenProcessToken(
    ProcessHandle: HANDLE,
    DesiredAccess: u32,
    TokenHandle: *?HANDLE,
) callconv(.winapi) BOOL;

pub extern "advapi32" fn LookupPrivilegeValueW(
    lpSystemName: ?[*:0]const u16,
    lpName: [*:0]const u16,
    lpLuid: *LUID,
) callconv(.winapi) BOOL;

pub extern "advapi32" fn AdjustTokenPrivileges(
    TokenHandle: HANDLE,
    DisableAllPrivileges: BOOL,
    NewState: ?*TOKEN_PRIVILEGES,
    BufferLength: u32,
    PreviousState: ?*TOKEN_PRIVILEGES,
    ReturnLength: ?*u32,
) callconv(.winapi) BOOL;

pub extern "advapi32" fn GetTokenInformation(
    TokenHandle: HANDLE,
    TokenInformationClass: u32,
    TokenInformation: ?*anyopaque,
    TokenInformationLength: u32,
    ReturnLength: *u32,
) callconv(.winapi) BOOL;

pub extern "advapi32" fn LookupAccountSidW(
    lpSystemName: ?[*:0]const u16,
    lpSid: *anyopaque,
    lpName: [*]u16,
    cchName: *u32,
    lpReferencedDomainName: [*]u16,
    cchReferencedDomainName: *u32,
    peUse: *u32,
) callconv(.winapi) BOOL;

// ---------------------------------------------------------------- psapi

pub extern "psapi" fn EnumProcessModules(
    hProcess: HANDLE,
    lphModule: [*]HANDLE,
    cb: DWORD,
    lpcbNeeded: *DWORD,
) callconv(.winapi) BOOL;

pub extern "psapi" fn GetModuleFileNameExW(
    hProcess: HANDLE,
    hModule: ?HANDLE,
    lpFilename: [*]u16,
    nSize: DWORD,
) callconv(.winapi) DWORD;

// ---------------------------------------------------------------- ntdll

pub const OBJECT_NAME_INFORMATION_CLASS: windows.OBJECT.INFORMATION_CLASS = .Name;
pub const SYSTEM_EXTENDED_HANDLE_INFORMATION: windows.SYSTEM.INFORMATION_CLASS =
    @enumFromInt(64);

pub fn ntQueryObject(
    handle: HANDLE,
    class: windows.OBJECT.INFORMATION_CLASS,
    out: PVOID,
    len: ULONG,
    ret_len: ?*ULONG,
) NTSTATUS {
    return ntdll.NtQueryObject(handle, class, out, len, ret_len);
}

pub fn ntQuerySystemInformation(
    class: windows.SYSTEM.INFORMATION_CLASS,
    out: PVOID,
    len: ULONG,
    ret_len: ?*ULONG,
) NTSTATUS {
    return ntdll.NtQuerySystemInformation(class, out, len, ret_len);
}

pub inline fn ntSuccess(status: NTSTATUS) bool {
    return status == STATUS_SUCCESS;
}

// ---------------------------------------------------------------- 常量

pub const FILE_TYPE_DISK: u32 = 0x0001;
pub const FILE_SHARE_READ: u32 = 0x00000001;
pub const FILE_SHARE_WRITE: u32 = 0x00000002;
pub const FILE_SHARE_DELETE: u32 = 0x00000004;
pub const OPEN_EXISTING: u32 = 3;
pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;

pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const PROCESS_TERMINATE: u32 = 0x0001;

pub const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;
pub const FALSE: BOOL = .FALSE;
pub const TRUE: BOOL = .TRUE;
pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 258;
pub const TOKEN_USER_CLASS: u32 = 1;
pub const SE_DEBUG_NAME_W: *const [16:0]u16 = std.unicode.wtf8ToWtf16LeStringLiteral("SeDebugPrivilege");

pub fn getCurrentProcess() HANDLE {
    return windows.GetCurrentProcess();
}

pub fn closeHandle(h: ?HANDLE) void {
    if (h) |handle| windows.CloseHandle(handle);
}

/// 0.17 的 Allocator 没有 dupeZ，这里补一个。
pub fn dupeZ(allocator: std.mem.Allocator, comptime T: type, slice: []const T) ![:0]T {
    const out = try allocator.allocSentinel(T, slice.len, 0);
    @memcpy(out[0..slice.len], slice);
    return out;
}

pub fn succeeded(result: BOOL) bool {
    return result.toBool();
}


/// std.ascii 没有 u16 版本的不区分大小写比较，std.os.windows 里有。
pub fn eqlIgnoreCaseWtf16(a: []const u16, b: []const u16) bool {
    return windows.eqlIgnoreCaseWtf16(a, b);
}
