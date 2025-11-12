//! Allocator that fails after X bytes of memory allocations.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

const Self = @This();

inner: Allocator,
total: usize,
limit: usize,

pub fn init(inner: Allocator, limit: usize) Self {
    return Self{
        .inner = inner,
        .total = 0,
        .limit = limit,
    };
}

pub fn allocator(self: *Self) Allocator {
    return .{
        .ptr = self,
        .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        },
    };
}

fn alloc(
    ctx: *anyopaque,
    len: usize,
    alignment: Alignment,
    return_address: usize,
) ?[*]u8 {
    const self: *Self = @ptrCast(@alignCast(ctx));

    if (self.total + len > self.limit) {
        return null;
    }

    const out = self.inner.rawAlloc(len, alignment, return_address) orelse return null;
    self.total += len;

    return out;
}

fn resize(
    ctx: *anyopaque,
    memory: []u8,
    alignment: Alignment,
    new_len: usize,
    return_address: usize,
) bool {
    _ = ctx;
    _ = memory;
    _ = alignment;
    _ = new_len;
    _ = return_address;
    unreachable;
}

fn remap(
    ctx: *anyopaque,
    memory: []u8,
    alignment: Alignment,
    new_len: usize,
    return_address: usize,
) ?[*]u8 {
    _ = ctx;
    _ = memory;
    _ = alignment;
    _ = new_len;
    _ = return_address;
    unreachable;
}

fn free(
    ctx: *anyopaque,
    memory: []u8,
    alignment: Alignment,
    return_address: usize,
) void {
    _ = ctx;
    _ = memory;
    _ = alignment;
    _ = return_address;
    unreachable;
}
