const std = @import("std");
const Allocator = std.mem.Allocator;
const DebugAllocator = std.heap.DebugAllocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;

const InternalErr = error{
    OutOfMemory,
    InputTooShort,
    MaxRecursionDepthExceeded,
};

pub const Error = error{
    FuzzInputOutOfMemory,
    FuzzInputTooShort,
    FuzzInputMaxRecursionDepthExceeded,
};

pub const FuzzInput = struct {
    input: []const u8,

    fn int(self: *FuzzInput, comptime T: type) InternalErr!T {
        const size = @sizeOf(T);
        if (self.input.len < size) {
            return InternalErr.InputTooShort;
        }
        const i = std.mem.readVarInt(T, self.input[0..size], .little);
        self.input = self.input[size..];
        return i;
    }

    // Taken from https://github.com/ziglang/zig/blob/852a1f718a306aa0a540c527a0c23d50b9f0db08/lib/std/Random.zig#L295
    // license: https://github.com/ziglang/zig/blob/852a1f718a306aa0a540c527a0c23d50b9f0db08/LICENSE
    fn float64(self: *FuzzInput) InternalErr!f64 {
        const rand = try self.int(u64);
        var rand_lz: u64 = @clz(rand);
        if (rand_lz >= 12) {
            rand_lz = 12;
            while (true) {
                // It is astronomically unlikely for this loop to execute more than once.
                const addl_rand_lz = @clz(try self.int(u64));
                rand_lz += addl_rand_lz;
                if (addl_rand_lz != 64) {
                    @branchHint(.likely);
                    break;
                }
                if (rand_lz >= 1022) {
                    rand_lz = 1022;
                    break;
                }
            }
        }
        const mantissa = rand & 0xFFFFFFFFFFFFF;
        const exponent = (1022 - rand_lz) << 52;
        return @bitCast(exponent | mantissa);
    }

    fn float(self: *FuzzInput, comptime T: type) InternalErr!T {
        const f = try self.float64();
        return @floatCast(f);
    }

    fn boolean(self: *FuzzInput) InternalErr!bool {
        if (self.input.len == 0) {
            return InternalErr.InputTooShort;
        }
        const byte = self.input[0];
        self.input = self.input[1..];
        return byte % 2 == 0;
    }

    fn slice_len(self: *FuzzInput, comptime ElemT: type) InternalErr!usize {
        const len = try self.int(usize);

        if (@sizeOf(ElemT) == 0) {
            return len;
        }

        if (@sizeOf(ElemT) > self.input.len) {
            return InternalErr.InputTooShort;
        }

        return len % (self.input.len / @sizeOf(ElemT));
    }

    fn int_array(
        self: *FuzzInput,
        comptime T: type,
        comptime N: comptime_int,
    ) InternalErr![N]T {
        const needed_bytes = @sizeOf(T) * N;
        if (self.input.len < needed_bytes) {
            return InternalErr.InputTooShort;
        }

        var out: [N]T = undefined;
        @memcpy(@as([]u8, @ptrCast(&out)), self.input[0..needed_bytes]);

        self.input = self.input[needed_bytes..];

        return out;
    }

    fn int_array_sentinel(
        self: *FuzzInput,
        comptime T: type,
        comptime N: comptime_int,
        comptime Sentinel: T,
    ) InternalErr![N:Sentinel]T {
        const needed_bytes = @sizeOf(T) * N;
        if (self.input.len < needed_bytes) {
            return InternalErr.InputTooShort;
        }

        var out: [N:Sentinel]T = undefined;
        @memcpy(@as([]u8, @ptrCast(&out)), self.input[0..needed_bytes]);

        for (out) |*o| {
            if (o.* == Sentinel) {
                o.* +%= 1;
            }
        }

        self.input = self.input[needed_bytes..];

        return out;
    }

    fn auto_array(
        self: *FuzzInput,
        comptime T: type,
        comptime N: comptime_int,
        alloc: Allocator,
        max_depth: u8,
        depth: u8,
    ) InternalErr![N]T {
        switch (@typeInfo(T)) {
            .int => return try self.int_array(T, N),
            else => {},
        }

        var out: [N]T = undefined;
        for (0..N) |idx| {
            out[idx] = try self.auto(T, alloc, max_depth, depth + 1);
        }
        return out;
    }

    fn auto_array_sentinel(
        self: *FuzzInput,
        comptime T: type,
        comptime N: comptime_int,
        comptime Sentinel: T,
    ) InternalErr![N:Sentinel]T {
        switch (@typeInfo(T)) {
            .int => return try self.int_array_sentinel(T, N, Sentinel),
            else => comptime unreachable,
        }
    }

    fn int_slice(
        self: *FuzzInput,
        comptime T: type,
        len: usize,
        alloc: Allocator,
    ) InternalErr![]T {
        const needed_bytes = @sizeOf(T) * len;

        if (needed_bytes > self.input.len) {
            return InternalErr.InputTooShort;
        }

        const slice = try alloc.alloc(T, len);
        @memcpy(
            @as([]u8, @ptrCast(slice)),
            self.input[0..needed_bytes],
        );

        self.input = self.input[needed_bytes..];

        return slice;
    }

    fn int_slice_sentinel(
        self: *FuzzInput,
        comptime T: type,
        comptime Sentinel: T,
        len: usize,
        alloc: Allocator,
    ) InternalErr![:Sentinel]T {
        const needed_bytes = @sizeOf(T) * len;

        if (needed_bytes > self.input.len) {
            return InternalErr.InputTooShort;
        }

        const slice = try alloc.allocSentinel(T, len, Sentinel);
        @memcpy(
            @as([]u8, @ptrCast(slice)),
            self.input[0..needed_bytes],
        );

        for (slice) |*s| {
            if (s.* == Sentinel) {
                s.* +%= 1;
            }
        }

        self.input = self.input[needed_bytes..];

        return slice;
    }

    fn auto_slice(
        self: *FuzzInput,
        comptime T: type,
        len: usize,
        alloc: Allocator,
        max_depth: u8,
        depth: u8,
    ) InternalErr![]T {
        switch (@typeInfo(T)) {
            .int => return try self.int_slice(
                self,
                T,
                len,
                alloc,
            ),
            else => {},
        }

        const slice = try alloc.alloc(T, len);
        for (0..len) |idx| {
            slice[idx] = try self.auto(
                T,
                alloc,
                max_depth,
                depth + 1,
            );
        }
        return slice;
    }

    fn auto_slice_sentinel(
        self: *FuzzInput,
        comptime T: type,
        comptime Sentinel: T,
        len: usize,
        alloc: Allocator,
    ) InternalErr![:Sentinel]T {
        switch (@typeInfo(T)) {
            .int => return try self.int_slice_sentinel(
                T,
                Sentinel,
                len,
                alloc,
            ),
            else => comptime unreachable,
        }
    }

    fn auto_ptr(
        self: *FuzzInput,
        comptime T: type,
        alloc: Allocator,
        max_depth: u8,
        depth: u8,
    ) InternalErr!*T {
        const p = try alloc.create(T);
        p.* = try self.auto(T, alloc, max_depth, depth + 1);

        return p;
    }

    pub fn auto(
        self: *FuzzInput,
        comptime T: type,
        alloc: Allocator,
        max_depth: u8,
    ) Error!T {
        return self.auto_impl(T, alloc, max_depth, 0) catch |e| {
            return switch (e) {
                InternalErr.MaxRecursionDepthExceeded => Error.FuzzInputMaxRecursionDepthExceeded,
                InternalErr.OutOfMemory => Error.FuzzInputOutOfMemory,
                InternalErr.InputTooShort => Error.FuzzInputTooShort,
            };
        };
    }

    fn auto_impl(
        self: *FuzzInput,
        comptime T: type,
        alloc: Allocator,
        max_depth: u8,
        depth: u8,
    ) InternalErr!T {
        if (depth == max_depth) {
            return InternalErr.MaxRecursionDepthExceeded;
        }

        switch (@typeInfo(T)) {
            .int => return try self.int(T),
            .float => return try self.float(T),
            .void => return {},
            .bool => return try self.boolean(),
            .array => |arr_info| {
                if (arr_info.sentinel) |sentinel| {
                    return try self.auto_array_sentinel(
                        arr_info.child,
                        arr_info.len,
                        sentinel,
                        alloc,
                    );
                } else {
                    return try self.auto_array(
                        arr_info.child,
                        arr_info.len,
                        alloc,
                        max_depth,
                        depth,
                    );
                }
            },
            .pointer => |ptr_info| {
                switch (ptr_info.size) {
                    .one => {
                        if (ptr_info.sentinel()) {
                            comptime unreachable;
                        }
                        return try self.auto_ptr(
                            ptr_info.child,
                            alloc,
                            max_depth,
                            depth,
                        );
                    },
                    .many => comptime unreachable,
                    .slice => {
                        const len = try self.slice_len(ptr_info.child);
                        if (ptr_info.sentinel()) |sentinel| {
                            return try self.auto_slice_sentinel(
                                ptr_info.child,
                                sentinel,
                                len,
                                alloc,
                            );
                        } else {
                            return try self.auto_slice(
                                ptr_info.child,
                                len,
                                alloc,
                                max_depth,
                                depth,
                            );
                        }
                    },
                    .c => comptime unreachable,
                }
            },
            .optional => |opt_info| {
                if (try self.boolean()) {
                    return try self.auto(
                        opt_info.child,
                        alloc,
                        max_depth,
                        depth + 1,
                    );
                } else {
                    return null;
                }
            },
            .@"struct" => |struct_info| {
                if (struct_info.fields.len == 0) {
                    return T{};
                }

                var out: T = undefined;

                inline for (struct_info.fields) |field_info| {
                    @field(out, field_info.name) = try self.auto_impl(
                        field_info.type,
                        alloc,
                        max_depth,
                        depth + 1,
                    );
                }

                return out;
            },
            .@"enum" => |enum_info| {
                if (enum_info.fields.len == 0) {
                    return T{};
                }

                var field_idx: usize = 0;

                const max_idx = enum_info.fields.len;
                const idx = (try self.int(usize)) % max_idx;

                inline for (enum_info.fields) |field_info| {
                    if (field_idx == idx) {
                        return @enumFromInt(field_info.value);
                    } else {
                        field_idx += 1;
                    }
                }
            },
            .@"union" => |union_info| {
                if (union_info.fields.len == 0) {
                    return T{};
                }

                var field_idx: usize = 0;

                const max_idx = union_info.fields.len;
                const idx = (try self.int(usize)) % max_idx;

                inline for (union_info.fields) |field_info| {
                    if (field_idx == idx) {
                        const child = try self.auto(
                            field_info.type,
                            alloc,
                            max_depth,
                            depth + 1,
                        );
                        return @unionInit(T, field_info.name, child);
                    } else {
                        field_idx += 1;
                    }
                }
            },
            .vector => |vec_info| {
                return try self.auto_array(
                    vec_info.child,
                    vec_info.len,
                    alloc,
                    max_depth,
                    depth + 1,
                );
            },
            .error_set => {
                comptime unreachable;
            },
            .error_union => {
                comptime unreachable;
            },
            else => comptime unreachable,
        }
    }
};

const FuzzContext = struct {
    fb_alloc: *FixedBufferAllocator,
    impl: FuzzOne,
    user_ctx: *anyopaque,
};

pub const FuzzOne = *const fn (ctx: *anyopaque, input: *FuzzInput, dbg_alloc: Allocator) Error!void;

fn test_one(
    ctx: FuzzContext,
    input: []const u8,
) anyerror!void {
    ctx.fb_alloc.reset();

    var dbg_allocator = DebugAllocator(.{
        .backing_allocator_zeroes = false,
    }){
        .backing_allocator = ctx.fb_alloc.allocator(),
    };
    const dbg_alloc = dbg_allocator.allocator();
    defer {
        switch (dbg_allocator.deinit()) {
            .ok => {},
            .leak => |leak| {
                std.debug.panic("LEAK: {any}", .{leak});
            },
        }
    }

    var fuzz_input = FuzzInput{ .input = input };

    ctx.impl(ctx.user_ctx, &fuzz_input, dbg_alloc) catch {
        return;
    };
}

pub fn fuzz_test(ctx: *anyopaque, impl: FuzzOne, alloc_cap: usize) void {
    const mem = std.heap.page_allocator.alloc(u8, alloc_cap) catch unreachable;
    defer std.heap.page_allocator.free(mem);

    var fb_alloc = FixedBufferAllocator.init(mem);

    std.testing.fuzz(
        FuzzContext{
            .impl = impl,
            .fb_alloc = &fb_alloc,
            .user_ctx = ctx,
        },
        test_one,
        .{},
    ) catch unreachable;
}
