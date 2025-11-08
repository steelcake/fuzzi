const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const fuzzi = @import("fuzzi");

const FuzzType = struct {
    name: [:0]const u8,
};

fn fuzz_fuzz(ctx: *anyopaque, input: *fuzzi.FuzzInput, dbg_alloc: Allocator) fuzzi.Error!void {
    std.debug.assert(@as(*u32, @ptrCast(@alignCast(ctx))).* == 69);

    var arena = ArenaAllocator.init(dbg_alloc);
    defer arena.deinit();
    const alloc = arena.allocator();

    const MAX_RECURSION_DEPTH = 64;
    _ = try input.auto(FuzzType, alloc, MAX_RECURSION_DEPTH);
}

test fuzz_fuzz {
    var ctx: u32 = 69;
    fuzzi.fuzz_test(@ptrCast(&ctx), fuzz_fuzz, 1 << 20);
}
