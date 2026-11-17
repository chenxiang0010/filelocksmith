//! 扫描器：文件句柄扫描 + 模块扫描 → 占用进程集合
//!
//! 对应 PowerToys 的 FileLocksmith.cpp::find_processes_recursive。

const std = @import("std");
const win32 = @import("win32.zig");
const ntscan = @import("ntscan.zig");
const match = @import("match.zig");

pub const PidSet = struct {
    items: std.ArrayList(win32.DWORD) = .empty,

    pub fn deinit(self: *PidSet) void {
        self.items.deinit(std.heap.c_allocator);
    }

    pub fn add(self: *PidSet, pid: win32.DWORD) !void {
        for (self.items.items) |existing| {
            if (existing == pid) return;
        }
        try self.items.append(std.heap.c_allocator, pid);
    }
};

/// 全系统句柄表扫描。返回命中的 PID。
pub fn scanHandles(
    targets: []const match.Target,
    pids: *PidSet,
) !void {
    const allocator = std.heap.c_allocator;

    var capacity: usize = 1 << 16;
    var buffer: []u8 = undefined;
    while (true) {
        if (capacity > (1 << 30)) return error.TooLarge;
        buffer = try allocator.alloc(u8, capacity);
        var needed: win32.ULONG = 0;
        const status = win32.ntQuerySystemInformation(
            win32.SYSTEM_EXTENDED_HANDLE_INFORMATION,
            buffer.ptr,
            @intCast(capacity),
            &needed,
        );
        if (status == win32.STATUS_INFO_LENGTH_MISMATCH) {
            allocator.free(buffer);
            capacity = if (needed > capacity) needed else capacity * 2;
            continue;
        }
        if (!win32.ntSuccess(status)) {
            allocator.free(buffer);
            return error.QueryFailed;
        }
        break;
    }
    defer allocator.free(buffer);

    const info: *const ntscan.HandleInfoEx = @ptrCast(@alignCast(buffer.ptr));
    const entries = info.entries();

    var worker = ntscan.NameQueryWorker{};
    defer worker.deinit();

    const current = win32.getCurrentProcess();

    // pid → 进程句柄缓存，避免对每个句柄重复 OpenProcess（PowerToys 同样做法）
    var process_cache = std.AutoHashMap(win32.DWORD, win32.HANDLE).init(allocator);
    defer {
        var it = process_cache.valueIterator();
        while (it.next()) |h| win32.closeHandle(h.*);
        process_cache.deinit();
    }

    var i: usize = 0;
    while (i < info.NumberOfHandles) : (i += 1) {
        const entry = entries[i];
        const pid: win32.DWORD = @truncate(entry.UniqueProcessId);
        if (pid == 0) continue;

        const process = process_cache.get(pid) orelse blk: {
            const opened = win32.OpenProcess(win32.PROCESS_DUP_HANDLE, win32.FALSE, pid) orelse continue;
            process_cache.put(pid, opened) catch {
                win32.closeHandle(opened);
                continue;
            };
            break :blk opened;
        };

        var copy: win32.HANDLE = undefined;
        if (!win32.succeeded(win32.DuplicateHandle(
            process,
            @ptrFromInt(entry.HandleValue),
            current,
            &copy,
            0,
            win32.FALSE,
            win32.DUPLICATE_SAME_ACCESS,
        ))) continue;

        // worker 接管 copy 的所有权（包括超时情形由线程关闭）
        const name = (try worker.query(allocator, copy)) orelse {
            // 超时：worker 已重置，句柄归线程；继续用新实例
            worker = ntscan.NameQueryWorker{};
            continue;
        };
        defer if (name.len > 0) allocator.free(name);

        if (name.len == 0) continue;

        for (targets) |*t| {
            if (match.matches(name, t)) {
                try pids.add(pid);
                break;
            }
        }
    }
}

/// 正在运行的 exe 是被映射的映像节而不是文件句柄，需单独扫模块。
pub fn scanModules(
    targets: []const match.Target,
    pids: *PidSet,
) !void {
    const allocator = std.heap.c_allocator;

    const max_processes: usize = 4096;
    var pid_buffer: []win32.DWORD = try allocator.alloc(win32.DWORD, max_processes);
    defer allocator.free(pid_buffer);

    var needed: win32.DWORD = 0;
    if (!win32.succeeded(win32.EnumProcesses(pid_buffer.ptr, @intCast(pid_buffer.len * @sizeOf(win32.DWORD)), &needed)))
        return;

    const count = needed / @sizeOf(win32.DWORD);

    var module_buf: [512]win32.HANDLE = undefined;
    var path_buf: [win32.MAX_PATH]u16 = undefined;

    for (pid_buffer[0..count]) |pid| {
        if (pid == 0) continue;
        const process = win32.OpenProcess(
            win32.PROCESS_QUERY_INFORMATION | win32.PROCESS_VM_READ,
            win32.FALSE,
            pid,
        ) orelse continue;
        // 不能让 defer 跨循环迭代累积：用块作用域保证每轮结束就关掉
        defer win32.closeHandle(process);

        var needed_bytes: win32.DWORD = 0;
        // 注意：这里判断的是「失败才 continue」。写成 .toBool() 会反过来，
        // 成功枚举到模块时反而跳过，导致模块扫描整条路径失效。
        if (!win32.succeeded(win32.EnumProcessModules(
            process,
            &module_buf,
            @intCast(module_buf.len * @sizeOf(win32.HANDLE)),
            &needed_bytes,
        ))) continue;

        var module_count = needed_bytes / @sizeOf(win32.HANDLE);
        if (module_count > module_buf.len) module_count = module_buf.len;

        for (module_buf[0..module_count]) |module| {
            const len = win32.GetModuleFileNameExW(
                process,
                module,
                &path_buf,
                path_buf.len,
            );
            if (len == 0) continue;

            const kernel = (try match.pathToKernelName(allocator, path_buf[0..len])) orelse continue;
            defer allocator.free(kernel);

            for (targets) |*t| {
                if (match.matches(kernel, t)) {
                    try pids.add(pid);
                    break;
                }
            }
        }
    }
}
