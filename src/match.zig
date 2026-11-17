//! 目标路径 → NT 内核路径，以及内核路径匹配
//!
//! 对应 PowerToys 的 NtdllExtensions::path_to_kernel_name 和
//! FileLocksmith.cpp 里的 kernel_paths_contain。

const std = @import("std");
const win32 = @import("win32.zig");

pub const Target = struct {
    /// \Device\HarddiskVolume3\...（已去掉结尾反斜杠）
    kernel: []u16,
    /// 用户输入的绝对路径，仅用于展示
    display: []u16,
    is_dir: bool,
};

/// 打开路径，取它的 NT 对象名，得到内核路径。
pub fn pathToKernelName(allocator: std.mem.Allocator, path: []const u16) !?[]u16 {
    const path_z = try win32.dupeZ(allocator, u16, path);
    defer allocator.free(path_z);

    const handle = win32.CreateFileW(
        path_z.ptr,
        0, // 只要元数据，不需要读权限
        win32.FILE_SHARE_READ | win32.FILE_SHARE_WRITE | win32.FILE_SHARE_DELETE,
        null,
        win32.OPEN_EXISTING,
        win32.FILE_FLAG_BACKUP_SEMANTICS, // 允许打开目录
        null,
    );
    if (handle == win32.INVALID_HANDLE_VALUE) return null;
    defer win32.closeHandle(handle);

    var buffer: [win32.MAX_PATH * 4]u8 align(@alignOf(win32.UNICODE_STRING)) = undefined;
    var ret: win32.ULONG = 0;
    const status = win32.ntQueryObject(
        handle,
        win32.OBJECT_NAME_INFORMATION_CLASS,
        &buffer,
        @intCast(buffer.len),
        &ret,
    );
    if (!win32.ntSuccess(status)) return null;

    const us: *const win32.UNICODE_STRING = @ptrCast(@alignCast(&buffer));
    const slice = us.slice();
    if (slice.len == 0) return null;
    return try allocator.dupe(u16, slice);
}

pub fn makeTarget(
    allocator: std.mem.Allocator,
    raw_path: []const u16,
) !?Target {
    var full_buf: [win32.MAX_PATH * 4]u16 = undefined;
    const raw_z = try win32.dupeZ(allocator, u16, raw_path);
    defer allocator.free(raw_z);

    const full_len = win32.GetFullPathNameW(
        raw_z.ptr,
        full_buf.len,
        &full_buf,
        null,
    );
    if (full_len == 0 or full_len >= full_buf.len) return null;
    const full = full_buf[0..full_len];

    const kernel = (try pathToKernelName(allocator, full)) orelse return null;
    errdefer allocator.free(kernel);
    const trimmed = trimSlashes(kernel);

    const full_z = try win32.dupeZ(allocator, u16, full);
    defer allocator.free(full_z);
    const attr = win32.GetFileAttributesW(full_z.ptr);
    const is_dir = attr != 0xFFFFFFFF and (attr & win32.FILE_ATTRIBUTE_DIRECTORY) != 0;

    return Target{
        .kernel = trimmed,
        .display = try allocator.dupe(u16, full),
        .is_dir = is_dir,
    };
}

fn trimSlashes(path: []u16) []u16 {
    var len = path.len;
    while (len > 1 and (path[len - 1] == '\\' or path[len - 1] == '/')) len -= 1;
    return path[0..len];
}

/// 内核路径命中判断：
/// - 文件：完全相同
/// - 目录：完全相同，或以内核目录路径 + '\' 开头
pub fn matches(name: []const u16, target: *const Target) bool {
    if (name.len < target.kernel.len) return false;
    if (!win32.eqlIgnoreCaseWtf16(name[0..target.kernel.len], target.kernel)) return false;
    if (name.len == target.kernel.len) return true;
    if (!target.is_dir) return false;
    return name[target.kernel.len] == '\\' or name[target.kernel.len] == '/';
}
