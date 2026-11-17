//! filelocksmith 的 Zig 实现
//!
//! 用法: filelocksmith.exe [--kill] <路径1> [路径2 ...]

const std = @import("std");
const allocator = std.heap.c_allocator;

const match = @import("match.zig");
const scan = @import("scan.zig");
const win32 = @import("win32.zig");

/// 取不到名字/用户时的占位符（u16）
const unknown: []const u16 = &.{'?'};

pub fn main(init: std.process.Init) !void {
    const args_slice = try init.minimal.args.toSlice(init.arena.allocator());
    const io = init.io;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buffer);
    const stderr = &stderr_writer.interface;

    var kill = false;

    // help 子命令
    if (args_slice.len > 1) {
        const sub = args_slice[1];
        if (std.mem.eql(u8, sub, "help") or std.mem.eql(u8, sub, "--help") or std.mem.eql(u8, sub, "-h")) {
            try printUsage(stdout);
            try stdout.flush();
            return;
        }
    }

    // 过滤出真正的路径参数，同时识别 --kill（位置任意）
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(allocator);
    for (args_slice[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--kill")) {
            kill = true;
        } else {
            try paths.append(allocator, arg);
        }
    }

    if (paths.items.len == 0) {
        if (args_slice.len <= 1) {
            // 完全没参数：当作 help 正常退出，不当成错误
            try printUsage(stdout);
            try stdout.flush();
            return;
        }
        try stderr.print("缺少路径参数，运行 filelocksmith.exe help 查看用法\n", .{});
        try stderr.flush();
        return error.MissingArguments;
    }

    enableDebugPrivilege();

    // argv 在 Windows 上是 WTF-8，转成 WTF-16 再交给 Win32
    var targets = std.ArrayList(match.Target).empty;
    defer {
        for (targets.items) |t| {
            allocator.free(t.kernel);
            allocator.free(t.display);
        }
        targets.deinit(allocator);
    }

    for (paths.items) |arg| {
        const wide = try std.unicode.wtf8ToWtf16LeAlloc(allocator, arg);
        defer allocator.free(wide);

        const target = (try match.makeTarget(allocator, wide)) orelse {
            try stderr.print("跳过（无法打开）: {s}\n", .{arg});
            continue;
        };
        try targets.append(allocator, target);
    }

    if (targets.items.len == 0) {
        try stderr.print("没有可检查的路径\n", .{});
        try stderr.flush();
        return error.NoValidPaths;
    }

    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const tmp = scratch.allocator();

    for (targets.items) |t| {
        try stdout.print("检查: {s}\n", .{try std.unicode.wtf16LeToWtf8Alloc(tmp, t.display)});
    }

    var pids = scan.PidSet{};
    defer pids.deinit();

    try scan.scanHandles(targets.items, &pids);
    try scan.scanModules(targets.items, &pids);

    if (pids.items.items.len == 0) {
        try stdout.print("没有进程占用这些文件。\n", .{});
        try stdout.flush();
    } else {
        // 列宽按显示宽度（中文占 2 格）而不是字节数计算
        const pid_col = 8;
        const user_col = 34;
        try stdout.print("\n", .{});
        try padTo(stdout, "PID", pid_col);
        try padTo(stdout, "用户", user_col);
        try stdout.print("进程\n", .{});

        for (pids.items.items) |pid| {
            var user_buf: [300]u16 = undefined;
            var name_buf: [win32.MAX_PATH]u16 = undefined;
            const user = pidToUser(pid, &user_buf);
            const name = pidToName(pid, &name_buf);

            var num_buf: [16]u8 = undefined;
            const pid_str = try std.fmt.bufPrint(&num_buf, "{d}", .{pid});
            try padTo(stdout, pid_str, pid_col);

            const user_utf8 = try std.unicode.wtf16LeToWtf8Alloc(tmp, user);
            try padTo(stdout, user_utf8, user_col);
            try stdout.print("{s}\n", .{try std.unicode.wtf16LeToWtf8Alloc(tmp, name)});

            if (kill) {
                const process = win32.OpenProcess(win32.PROCESS_TERMINATE, win32.FALSE, pid);
                if (process) |handle| {
                    defer win32.closeHandle(handle);
                    if (win32.succeeded(win32.TerminateProcess(handle, 0))) {
                        try stdout.print("  已结束\n", .{});
                    } else {
                        try stdout.print("  结束失败 (错误 {d})\n", .{win32.GetLastError()});
                    }
                } else {
                    try stdout.print("  结束失败 (错误 {d})\n", .{win32.GetLastError()});
                }
            }
        }
    }
    try stdout.flush();
}

fn printUsage(w: *std.Io.Writer) !void {
    try w.print(
        \\filelocksmith —— 查看/结束占用文件的进程
        \\
        \\用法:
        \\  filelocksmith.exe <路径...>             列出占用这些文件的进程
        \\  filelocksmith.exe --kill <路径...>      列出并结束占用进程
        \\  filelocksmith.exe help                  显示本帮助
        \\
        \\说明:
        \\  路径可以是文件、目录或驱动器。传目录时会递归检查整个子树。
        \\  不加 --kill 时只列出，不做任何修改。
        \\  不传参数等同于 help。
        \\
        \\示例:
        \\  filelocksmith.exe D:\a.txt
        \\  filelocksmith.exe "C:\Program Files"
        \\  filelocksmith.exe --kill D:\a.txt
        \\
    , .{});
}

/// 按终端显示宽度补空格（CJK 等宽字符算 2 格）
fn padTo(w: *std.Io.Writer, text: []const u8, width: usize) !void {
    try w.writeAll(text);
    var used: usize = 0;
    var i: usize = 0;
    while (i < text.len) {
        const len = std.unicode.utf8ByteSequenceLength(text[i]) catch 1;
        if (i + len > text.len) {
            used += 1;
            i += 1;
            continue;
        }
        const cp = std.unicode.utf8Decode(text[i..][0..len]) catch {
            used += 1;
            i += len;
            continue;
        };
        used += codepointWidth(cp);
        i += len;
    }
    var pad = if (used < width) width - used else 0;
    while (pad > 0) : (pad -= 1) try w.writeAll(" ");
}

/// 粗略的东亚宽字符判定（覆盖 CJK 汉字、假名、谚文、全角标点）
fn codepointWidth(cp: u21) usize {
    if (cp >= 0x1100 and cp <= 0x115F) return 2; // 谚文字母
    if (cp >= 0x2E80 and cp <= 0xA4CF) return 2; // CJK 部首 ~ 彝文
    if (cp >= 0xAC00 and cp <= 0xD7A3) return 2; // 谚文音节
    if (cp >= 0xF900 and cp <= 0xFAFF) return 2; // CJK 兼容汉字
    if (cp >= 0xFE30 and cp <= 0xFE6F) return 2; // CJK 兼容形式
    if (cp >= 0xFF00 and cp <= 0xFF60) return 2; // 全角形式
    if (cp >= 0xFFE0 and cp <= 0xFFE6) return 2; // 全角符号
    return 1;
}

fn enableDebugPrivilege() void {
    var token: ?win32.HANDLE = null;
    if (!win32.succeeded(win32.OpenProcessToken(win32.getCurrentProcess(), win32.TOKEN_ADJUST_PRIVILEGES, &token)))
        return;
    defer win32.closeHandle(token);

    var luid: win32.LUID = undefined;
    if (!win32.succeeded(win32.LookupPrivilegeValueW(null, win32.SE_DEBUG_NAME_W, &luid))) return;

    var tp = win32.TOKEN_PRIVILEGES{
        .PrivilegeCount = 1,
        .Privileges = .{.{ .Luid = luid, .Attributes = win32.SE_PRIVILEGE_ENABLED }},
    };
    _ = win32.AdjustTokenPrivileges(token.?, win32.FALSE, &tp, @sizeOf(win32.TOKEN_PRIVILEGES), null, null);
}

fn pidToName(pid: win32.DWORD, buffer: []u16) []const u16 {
    const process = win32.OpenProcess(win32.PROCESS_QUERY_LIMITED_INFORMATION, win32.FALSE, pid) orelse
        return unknown;
    defer win32.closeHandle(process);

    var size: win32.DWORD = @intCast(buffer.len);
    if (!win32.succeeded(win32.QueryFullProcessImageNameW(process, 0, buffer.ptr, &size))) return unknown;
    return buffer[0..size];
}

fn pidToUser(pid: win32.DWORD, buffer: []u16) []const u16 {
    const process = win32.OpenProcess(win32.PROCESS_QUERY_LIMITED_INFORMATION, win32.FALSE, pid) orelse
        return unknown;

    var token: ?win32.HANDLE = null;
    if (!win32.succeeded(win32.OpenProcessToken(process, win32.TOKEN_QUERY, &token))) {
        win32.closeHandle(process);
        return unknown;
    }
    defer win32.closeHandle(token);
    defer win32.closeHandle(process);

    var size: u32 = 0;
    _ = win32.GetTokenInformation(token.?, win32.TOKEN_USER_CLASS, null, 0, &size);
    if (size == 0) return unknown;

    const buf = allocator.alloc(u8, size) catch return unknown;
    defer allocator.free(buf);
    if (!win32.succeeded(win32.GetTokenInformation(token.?, win32.TOKEN_USER_CLASS, buf.ptr, size, &size)))
        return unknown;

    const token_user: *win32.TOKEN_USER = @ptrCast(@alignCast(buf.ptr));
    var name_buf: [128]u16 = undefined;
    var domain_buf: [128]u16 = undefined;
    var name_len: u32 = name_buf.len;
    var domain_len: u32 = domain_buf.len;
    var use: u32 = 0;

    if (!win32.succeeded(win32.LookupAccountSidW(
        null,
        token_user.User.Sid,
        &name_buf,
        &name_len,
        &domain_buf,
        &domain_len,
        &use,
    ))) return unknown;

    if (domain_len + 1 + name_len < buffer.len) {
        @memcpy(buffer[0..domain_len], domain_buf[0..domain_len]);
        buffer[domain_len] = '\\';
        @memcpy(buffer[domain_len + 1 ..][0..name_len], name_buf[0..name_len]);
        return buffer[0 .. domain_len + 1 + name_len];
    }
    return unknown;
}
