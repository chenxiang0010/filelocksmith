const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "filelocksmith",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.link_libc = true;
    exe.root_module.linkSystemLibrary("advapi32", .{});
    exe.root_module.linkSystemLibrary("psapi", .{});

    b.installArtifact(exe);

    // zls 保存即检查
    const check = b.step("check", "Check if filelocksmith compiles");
    check.dependOn(&exe.step);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run filelocksmith");
    run_step.dependOn(&run.step);
}
