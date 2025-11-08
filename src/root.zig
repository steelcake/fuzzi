const std = @import("std");
const Allocator = std.mem.Allocator;
const DebugAllocator = std.heap.DebugAllocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;
const Prng = std.Random.DefaultPrng;

/// Use a separate error type internally so it is easy to coerce from OutOfMemory or similar errors.
/// Map it to public error type so we can safely ignore fuzzin.Error at the end of fuzzing.
///
/// If we don't do this user might do something like `try alloc.alloc()` in their fuzz function
///     and we would ignore the potential OutOfMemory silently because we are ignoring this error set.
const InternalErr = error{
    OutOfMemory,
    InputTooShort,
    MaxRecursionDepthExceeded,
};

/// Errors that can happen when generating structured fuzz input.
/// These are intended to be transparently passed on so the fuzzing process
/// can ignore these errors and continue.
///
/// This functionality might cause the actual fuzzing to never run
///     if the generated type is impossible to generate (could be because of recursion depth).
/// User can add a `std.debug.assert(try input.int(u8) != 69);` at the end of the fuzz function
///     to test if the fuzzing is actually able to run.
pub const Error = error{
    FuzzInputOutOfMemory,
    FuzzInputTooShort,
    FuzzInputMaxRecursionDepthExceeded,
};

/// Structured fuzz input generator. Creates valid (as far as the language type system goes)
///     instances requested types.
///
/// Example usage can be like `try input.auto([]u128, alloc, 64);`
pub const FuzzInput = struct {
    input: []const u8,

    /// Generate requested type using the allocator.
    ///
    /// Example usage can be like `try input.auto([]u128, alloc, 64);`
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

    fn int(self: *FuzzInput, comptime T: type) InternalErr!T {
        const size = @sizeOf(T);
        if (self.input.len < size) {
            return InternalErr.InputTooShort;
        }
        const i = std.mem.readVarInt(T, self.input[0..size], .little);
        self.input = self.input[size..];
        return i;
    }

    fn float64(self: *FuzzInput) InternalErr!f64 {
        const seed = try self.int(u64);
        var prng = Prng.init(seed);
        return prng.random().float(f64);
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

        for (0..N) |idx| {
            if (out[idx] == Sentinel) {
                out[idx] +%= 1;
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
            out[idx] = try self.auto_impl(T, alloc, max_depth, depth + 1);
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
            else => unreachable,
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
                T,
                len,
                alloc,
            ),
            else => {},
        }

        const slice = try alloc.alloc(T, len);
        for (0..len) |idx| {
            slice[idx] = try self.auto_impl(
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
            else => unreachable,
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
        p.* = try self.auto_impl(T, alloc, max_depth, depth + 1);

        return p;
    }

    fn auto_impl(
        self: *FuzzInput,
        comptime T: type,
        alloc: Allocator,
        max_depth: u8,
        depth: u8,
    ) InternalErr!T {
        if (depth >= max_depth) {
            return InternalErr.MaxRecursionDepthExceeded;
        }

        switch (@typeInfo(T)) {
            .int => return try self.int(T),
            .float => return try self.float(T),
            .void => return {},
            .bool => return try self.boolean(),
            .array => |arr_info| {
                if (arr_info.sentinel()) |sentinel| {
                    return try self.auto_array_sentinel(
                        arr_info.child,
                        arr_info.len,
                        sentinel,
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
                        return try self.auto_ptr(
                            ptr_info.child,
                            alloc,
                            max_depth,
                            depth,
                        );
                    },
                    .many => unreachable,
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
                    .c => unreachable,
                }
            },
            .optional => |opt_info| {
                if (try self.boolean()) {
                    return try self.auto_impl(
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

                unreachable;
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
                        const child = try self.auto_impl(
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

                unreachable;
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
                unreachable;
            },
            .error_union => {
                unreachable;
            },
            else => unreachable,
        }
    }
};

const FuzzContext = struct {
    fb_alloc: *FixedBufferAllocator,
    impl: FuzzOne,
    user_ctx: *anyopaque,
};

/// Signature for the fuzz function that implements a single run
///
/// `ctx` is a user defined parameter to make it possible to pass static arrays or similar
///     expensive-to-construct structures that would slow the fuzzing too much if they are
///     constructed for every individual run.
///
/// `dbg_alloc` is a debug allocator instance that will be checked for leaks after every run
///     of the fuzzing function.
///
/// This function is expected to never pass actual failure errors. It should only propagate the
///     errors coming from `input.auto` or any other input generation related errors.
///
/// This function should handle failures by doing something lile `maybe_fail() catch unreachable;`
pub const FuzzOne = *const fn (
    ctx: *anyopaque,
    input: *FuzzInput,
    dbg_alloc: Allocator,
) Error!void;

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

/// Take the parameters and start a fuzz test. This function will internally call
///     `impl` with different fuzz inputs.
///
/// `ctx` will be passed into the `impl` function for every run so it can have a user defined context.
///
/// `ctx` is a user defined parameter to make it possible to pass static arrays or similar
///     expensive-to-construct structures that would slow the fuzzing too much if they are
///     constructed for every individual run.
///
/// `alloc_cap` is the amount of memory that will be allocated once and will be made available to the `impl`
///     function for every run, in the form of a `std.heap.DebugAllocator`.
///
/// `impl` function is expected to never pass actual failure errors. It should only propagate the
///     errors coming from `input.auto` or any other input generation related errors.
///
/// `impl` should handle failures by doing something lile `maybe_fail() catch unreachable;`
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
