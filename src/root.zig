const std = @import("std");
const Allocator = std.mem.Allocator;
const DebugAllocator = std.heap.DebugAllocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;
const Prng = std.Random.DefaultPrng;

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

/// same as `alloc.alloc` but maps the error to `fuzzin.Error`
pub fn allocate(comptime T: type, len: usize, alloc: Allocator) Error![]T {
    return alloc.alloc(T, len) catch |e| {
        switch (e) {
            error.OutOfMemory => return Error.FuzzInputOutOfMemory,
        }
    };
}

/// same as `alloc.allocSentinel` but maps the error to `fuzzin.Error`
pub fn allocate_sentinel(
    comptime T: type,
    comptime sentinel: T,
    len: usize,
    alloc: Allocator,
) Error![:sentinel]T {
    return alloc.allocSentinel(T, len, sentinel) catch |e| {
        switch (e) {
            error.OutOfMemory => return Error.FuzzInputOutOfMemory,
        }
    };
}

/// same as `alloc.create` but maps the error to `fuzzin.Error`
pub fn create(comptime T: type, alloc: Allocator) Error!*T {
    return alloc.create(T) catch |e| {
        switch (e) {
            error.OutOfMemory => return Error.FuzzInputOutOfMemory,
        }
    };
}

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
        return try self.auto_impl(T, alloc, max_depth, 0);
    }

    /// Consume the next `len` bytes from fuzz input
    pub fn bytes(self: *FuzzInput, len: usize) Error![]const u8 {
        if (self.input.len < len) {
            return Error.FuzzInputTooShort;
        }

        const out = self.input.ptr[0..len];

        self.input = self.input[len..];

        return out;
    }

    /// Consume all remaining bytes of fuzz input
    pub fn all_bytes(self: *FuzzInput) []const u8 {
        const out = self.input;
        self.input = &.{};
        return out;
    }

    pub fn int(self: *FuzzInput, comptime T: type) Error!T {
        const size = @sizeOf(T);
        if (self.input.len < size) {
            return Error.FuzzInputTooShort;
        }

        const out: T = @bitCast(@as(*const [size]u8, @ptrCast(self.input.ptr)).*);
        self.input = self.input[size..];

        return out;
    }

    fn float64(self: *FuzzInput) Error!f64 {
        const seed = try self.int(u64);
        var prng = Prng.init(seed);
        return prng.random().float(f64);
    }

    pub fn float(self: *FuzzInput, comptime T: type) Error!T {
        const f = try self.float64();
        return @floatCast(f);
    }

    pub fn boolean(self: *FuzzInput) Error!bool {
        if (self.input.len == 0) {
            return Error.FuzzInputTooShort;
        }
        const byte = self.input.ptr[0];
        self.input = self.input[1..];
        return byte % 2 == 0;
    }

    pub fn slice_len(self: *FuzzInput, comptime ElemT: type) Error!usize {
        const len = try self.int(usize);

        if (@sizeOf(ElemT) == 0) {
            return len;
        }

        if (@sizeOf(ElemT) > self.input.len) {
            return Error.FuzzInputTooShort;
        }

        return (len % (self.input.len / @sizeOf(ElemT))) / 2;
    }

    pub fn int_array(
        self: *FuzzInput,
        comptime T: type,
        comptime N: comptime_int,
    ) Error![N]T {
        const needed_bytes = @sizeOf(T) * N;
        if (self.input.len < needed_bytes) {
            return Error.FuzzInputTooShort;
        }

        const out: [needed_bytes]u8 align(@sizeOf(T)) = @as(
            *const [needed_bytes]u8,
            @ptrCast(self.input.ptr),
        ).*;
        self.input = self.input[needed_bytes..];

        return @bitCast(out);
    }

    pub fn int_array_sentinel(
        self: *FuzzInput,
        comptime T: type,
        comptime N: comptime_int,
        comptime Sentinel: T,
    ) Error![N:Sentinel]T {
        const needed_bytes = @sizeOf(T) * N;
        if (self.input.len < needed_bytes) {
            return Error.FuzzInputTooShort;
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

    pub fn auto_array(
        self: *FuzzInput,
        comptime T: type,
        comptime N: comptime_int,
        alloc: Allocator,
        max_depth: u8,
        depth: u8,
    ) Error![N]T {
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

    pub fn auto_array_sentinel(
        self: *FuzzInput,
        comptime T: type,
        comptime N: comptime_int,
        comptime Sentinel: T,
    ) Error![N:Sentinel]T {
        switch (@typeInfo(T)) {
            .int => return try self.int_array_sentinel(T, N, Sentinel),
            else => @compileError("sentinels aren't supported for non-integer arrays"),
        }
    }

    pub fn int_slice(
        self: *FuzzInput,
        comptime T: type,
        len: usize,
        alloc: Allocator,
    ) Error![]T {
        const needed_bytes = @sizeOf(T) * len;

        if (needed_bytes > self.input.len) {
            return Error.FuzzInputTooShort;
        }

        const slice = try allocate(T, len, alloc);

        @memcpy(
            @as([]u8, @ptrCast(slice)),
            self.input[0..needed_bytes],
        );

        self.input = self.input[needed_bytes..];

        return slice;
    }

    pub fn int_slice_sentinel(
        self: *FuzzInput,
        comptime T: type,
        comptime Sentinel: T,
        len: usize,
        alloc: Allocator,
    ) Error![:Sentinel]T {
        const needed_bytes = @sizeOf(T) * len;

        if (needed_bytes > self.input.len) {
            return Error.FuzzInputTooShort;
        }

        const slice = try allocate_sentinel(T, Sentinel, len, alloc);
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

    pub fn auto_slice(
        self: *FuzzInput,
        comptime T: type,
        len: usize,
        alloc: Allocator,
        max_depth: u8,
        depth: u8,
    ) Error![]T {
        switch (@typeInfo(T)) {
            .int => return try self.int_slice(
                T,
                len,
                alloc,
            ),
            else => {},
        }

        const slice = try allocate(T, len, alloc);

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

    pub fn auto_slice_sentinel(
        self: *FuzzInput,
        comptime T: type,
        comptime Sentinel: T,
        len: usize,
        alloc: Allocator,
    ) Error![:Sentinel]T {
        switch (@typeInfo(T)) {
            .int => return try self.int_slice_sentinel(
                T,
                Sentinel,
                len,
                alloc,
            ),
            else => @compileError("sentinels aren't supported for non-integer slices"),
        }
    }

    pub fn auto_ptr(
        self: *FuzzInput,
        comptime T: type,
        alloc: Allocator,
        max_depth: u8,
        depth: u8,
    ) Error!*T {
        const p = try create(T, alloc);

        p.* = try self.auto_impl(T, alloc, max_depth, depth + 1);

        return p;
    }

    pub fn auto_impl(
        self: *FuzzInput,
        comptime T: type,
        alloc: Allocator,
        max_depth: u8,
        depth: u8,
    ) Error!T {
        if (depth >= max_depth) {
            return Error.FuzzInputMaxRecursionDepthExceeded;
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
                    .many => @compileError("many-pointer isn't supported"),
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
                    .c => @compileError("c pointers aren't supported"),
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

                @panic("enum variant not found. this should never happen");
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

                @panic("union variant not found. this should never happen");
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
                @compileError("error sets aren't supported");
            },
            .error_union => {
                @compileError("error unions aren't supported");
            },
            else => @compileError("unsupported type"),
        }
    }
};

fn FuzzContext(comptime UserContext: type) type {
    return struct {
        const Self = @This();

        fb_alloc: *FixedBufferAllocator,
        impl: *const fn (
            ctx: UserContext,
            input: *FuzzInput,
            dbg_alloc: Allocator,
        ) Error!void,
        user_ctx: UserContext,

        fn test_one(
            self: Self,
            input: []const u8,
        ) anyerror!void {
            self.fb_alloc.reset();

            var dbg_allocator = DebugAllocator(.{
                .backing_allocator_zeroes = false,
            }){
                .backing_allocator = self.fb_alloc.allocator(),
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

            self.impl(self.user_ctx, &fuzz_input, dbg_alloc) catch {
                return;
            };
        }
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
/// `impl` should handle failures by doing something lile `maybe_fail() catch unreachable;` so
///     it crashes the fuzzing process with the error.
pub fn fuzz_test(
    comptime Context: type,
    ctx: Context,
    impl: *const fn (
        ctx: Context,
        input: *FuzzInput,
        dbg_alloc: Allocator,
    ) Error!void,
    alloc_cap: usize,
) void {
    const Ctx = FuzzContext(Context);

    const mem = std.heap.page_allocator.alloc(u8, alloc_cap) catch unreachable;
    defer std.heap.page_allocator.free(mem);

    var fb_alloc = FixedBufferAllocator.init(mem);

    std.testing.fuzz(
        Ctx{
            .impl = impl,
            .fb_alloc = &fb_alloc,
            .user_ctx = ctx,
        },
        Ctx.test_one,
        .{},
    ) catch unreachable;
}
