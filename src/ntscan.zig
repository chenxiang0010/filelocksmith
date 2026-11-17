//! 句柄扫描：枚举全系统句柄 → 取内核路径 → 匹配目标
//!
//! 对应 PowerToys 的 NtdllExtensions.cpp::handles() + FileNameQueryWorker。

const std = @import("std");
const win32 = @import("win32.zig");

const HANDLE = win32.HANDLE;
const DWORD = win32.DWORD;
const ULONG = win32.ULONG;
const ULONG_PTR = win32.ULONG_PTR;

/// SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
pub const HandleEntry = extern struct {
    Object: ?*anyopaque,
    UniqueProcessId: ULONG_PTR,
    HandleValue: ULONG_PTR,
    GrantedAccess: ULONG,
    CreatorBackTraceIndex: u16,
    ObjectTypeIndex: u16,
    HandleAttributes: ULONG,
    Reserved: ULONG,
};

/// SYSTEM_HANDLE_INFORMATION_EX
pub const HandleInfoEx = extern struct {
    NumberOfHandles: ULONG_PTR,
    Reserved: ULONG_PTR,
    Handles: [1]HandleEntry,

    pub fn entries(self: *const HandleInfoEx) [*]const HandleEntry {
        return @ptrCast(&self.Handles);
    }
};

pub const query_timeout_ms: DWORD = 200;
pub const query_buffer_size: usize = 64 * 1024;

const State = enum(i32) { busy = 0, done = 1, abandoned = 2 };

/// 与 PowerToys 的 NameQueryBlock 等价：辅助线程与主线程共享的请求/响应块。
const QueryBlock = struct {
    request_event: HANDLE,
    done_event: HANDLE,
    file_handle: ?HANDLE = null,
    status: win32.NTSTATUS = win32.STATUS_SUCCESS,
    is_disk: bool = false,
    state: std.atomic.Value(i32) = .init(@intFromEnum(State.done)),
    buffer: [query_buffer_size]u8 align(@alignOf(win32.UNICODE_STRING)) = undefined,
};

/// NtQueryObject 在个别同步句柄上会无限期阻塞且没有超时参数，
/// 所以查询放到辅助线程里跑，超时就放弃并把这个句柄交给线程去关。
pub const NameQueryWorker = struct {
    block: ?*QueryBlock = null,

    pub fn deinit(self: *NameQueryWorker) void {
        const block = self.block orelse return;
        block.file_handle = null;
        _ = win32.SetEvent(block.request_event);
        self.block = null;
    }

    /// 接管 file_handle 的所有权。返回内核路径；若是非磁盘句柄或查询失败返回空串；
    /// 查询超时返回 null（此时 worker 已被重置，调用方需继续用同一个实例）。
    pub fn query(
        self: *NameQueryWorker,
        allocator: std.mem.Allocator,
        handle: HANDLE,
    ) !?[]u16 {
        if (self.block == null) {
            const block = try createBlock();
            self.block = block;
        }
        const block = self.block.?;

        block.file_handle = handle;
        block.is_disk = false;
        block.state.store(@intFromEnum(State.busy), .release);
        _ = win32.SetEvent(block.request_event);

        if (win32.WaitForSingleObject(block.done_event, query_timeout_ms) != win32.WAIT_OBJECT_0) {
            // 尝试抢占：如果线程还在 busy，就把它改成 abandoned，
            // 句柄所有权转移给线程（线程会负责 CloseHandle）。
            if (block.state.cmpxchgStrong(
                @intFromEnum(State.busy),
                @intFromEnum(State.abandoned),
                .acq_rel,
                .acquire,
            ) == null) {
                self.block = null; // 线程负责释放 block
                return null;
            }
            // 恰好抢在完成瞬间超时，把完成信号吃掉
            _ = win32.WaitForSingleObject(block.done_event, 0xFFFFFFFF);
        }

        // 辅助线程已经用完句柄，先关掉再继续（这里的分配失败不能泄漏句柄）
        win32.closeHandle(handle);

        if (!block.is_disk or !win32.ntSuccess(block.status)) return &.{};

        const us: *const win32.UNICODE_STRING =
            @ptrCast(@alignCast(&block.buffer));
        const slice = us.slice();
        return try allocator.dupe(u16, slice);
    }

    fn createBlock() !*QueryBlock {
        const allocator = std.heap.c_allocator;
        // 注意：allocator.create 不做默认值初始化，必须显式写一遍，
        // 否则 state / file_handle 是未定义内存。
        const block = try allocator.create(QueryBlock);
        block.* = .{
            .request_event = undefined,
            .done_event = undefined,
        };
        block.request_event = win32.CreateEventW(null, win32.FALSE, win32.FALSE, null) orelse {
            allocator.destroy(block);
            return error.CreateEventFailed;
        };
        block.done_event = win32.CreateEventW(null, win32.FALSE, win32.FALSE, null) orelse {
            win32.closeHandle(block.request_event);
            allocator.destroy(block);
            return error.CreateEventFailed;
        };
        // 用虚空指针传参，但它的生命周期由线程自己管理（见 threadMain）
        const thread = win32.CreateThread(null, 0, threadMain, block, 0, null) orelse {
            win32.closeHandle(block.request_event);
            win32.closeHandle(block.done_event);
            allocator.destroy(block);
            return error.CreateThreadFailed;
        };
        win32.closeHandle(thread);
        return block;
    }

    fn threadMain(param: ?*anyopaque) callconv(.winapi) DWORD {
        const allocator = std.heap.c_allocator;
        const block: *QueryBlock = @ptrCast(@alignCast(param.?));

        while (true) {
            _ = win32.WaitForSingleObject(block.request_event, 0xFFFFFFFF);

            const handle = block.file_handle orelse break;

            block.is_disk = win32.GetFileType(handle) == win32.FILE_TYPE_DISK;
            if (block.is_disk) {
                var ret_len: ULONG = 0;
                block.status = win32.ntQueryObject(
                    handle,
                    win32.OBJECT_NAME_INFORMATION_CLASS,
                    @ptrCast(&block.buffer),
                    query_buffer_size,
                    &ret_len,
                );
            }

            if (block.state.cmpxchgStrong(
                @intFromEnum(State.busy),
                @intFromEnum(State.done),
                .acq_rel,
                .acquire,
            )) |prev| {
                if (prev == @intFromEnum(State.abandoned)) {
                    // 主线程已放弃，句柄所有权归我们
                    win32.closeHandle(handle);
                    break;
                }
            }

            _ = win32.SetEvent(block.done_event);
        }

        win32.closeHandle(block.request_event);
        win32.closeHandle(block.done_event);
        allocator.destroy(block);
        return 0;
    }
};
