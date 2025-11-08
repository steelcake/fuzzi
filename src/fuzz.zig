const std = @import("std");
const Allocator = std.mem.Allocator;

const fuzzi = @import("fuzzi");

fn fuzz_kaboom(ctx: *anyopaque, input: *fuzzi.FuzzInput, dbg_alloc: Allocator) fuzzi.Error!void {
    _ = ctx;
    _ = input;
    _ = dbg_alloc;
}

test fuzz_kaboom {
    var ctx: u32 = 69;
    fuzzi.fuzz_test(@ptrCast(&ctx), fuzz_kaboom, 1024);
}
