const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{
    OutOfMemory,
    InputTooShort,
};

pub const FuzzInput = struct {
    input: []const u8,

    pub fn init(input: []const u8) FuzzInput {
        return .{
            .input = input,
        };
    }

    pub fn int(self: *FuzzInput, comptime T: type) Error!T {
        const size = @sizeOf(T);
        if (self.data.len < size) {
            return Error.InputTooShort;
        }
        const i = std.mem.readVarInt(T, self.data[0..size], .little);
        self.data = self.data[size..];
        return i;
    }

    // Taken from https://github.com/ziglang/zig/blob/852a1f718a306aa0a540c527a0c23d50b9f0db08/lib/std/Random.zig#L295
    // license: https://github.com/ziglang/zig/blob/852a1f718a306aa0a540c527a0c23d50b9f0db08/LICENSE
    fn float64(self: *FuzzInput) Error!f64 {
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

    pub fn float(self: *FuzzInput, comptime T: type) Error!T {
        const f = try self.float64();
        return @floatCast(f);
    }

    pub fn boolean(self: *FuzzInput) Error!bool {
        if (self.data.len == 0) {
            return Error.InputTooShort;
        }
        const byte = self.data[0];
        self.data = self.data[1..];
        return byte % 2 == 0;
    }

    pub fn slice_len(self: *FuzzInput, comptime ElemT: type) Error!usize {
        const len = try self.int(usize);

        if (@sizeOf(ElemT) == 0) {
            return len;
        }

        return len % (self.input.len / @sizeOf(ElemT));
    }

    pub fn int_array(self: *FuzzInput, comptime T: type, comptime N: comptime_int) Error![N]T {
        const needed_bytes = @sizeOf(T) * N;
        if (self.input.len < needed_bytes) {
            return Error.InputTooShort;
        }

        var out: [N]T = undefined;
        @memcpy(@as([]u8, @ptrCast(&out)), self.input[0..needed_bytes]);

        self.input = self.input[needed_bytes..];

        return out;
    }

    pub fn int_array_sentinel(
        self: *FuzzInput,
        comptime T: type,
        comptime N: comptime_int,
        comptime Sentinel: T,
    ) Error![N:Sentinel]T {
        const needed_bytes = @sizeOf(T) * N;
        if (self.input.len < needed_bytes) {
            return Error.InputTooShort;
        }

        var out: [N:Sentinel]T = undefined;
        @memcpy(@as([]u8, @ptrCast(&out)), self.input[0..needed_bytes]);

        self.input = self.input[needed_bytes..];

        return out;
    }

    pub fn auto_array(
        self: *FuzzInput,
        comptime T: type,
        comptime N: comptime_int,
        alloc: Allocator,
    ) Error![N]T {
        switch (@typeInfo(T)) {
            .int => return try self.int_array(T, N),
            else => {},
        }

        var out: [N]T = undefined;
        for (0..N) |idx| {
            out[idx] = try self.auto(T, alloc);
        }
        return out;
    }

    pub fn auto_array_sentinel(
        self: *FuzzInput,
        comptime T: type,
        comptime N: comptime_int,
        comptime Sentinel: T,
        alloc: Allocator,
    ) Error![N:Sentinel]T {
        switch (@typeInfo(T)) {
            .int => return try self.int_array_sentinel(T, N, Sentinel),
            else => {},
        }

        var out: [N:Sentinel]T = undefined;
        for (0..N) |idx| {
            out[idx] = try self.auto(T, alloc);
        }
        return out;
    }

    pub fn int_slice(
        self: *FuzzInput,
        comptime T: type,
        len: usize,
        alloc: Allocator,
    ) Error![]T {
        const needed_bytes = @sizeOf(T) * len;

        if (needed_bytes > self.input.len) {
            return Error.InputTooShort;
        }

        const slice = try alloc.alloc(T, len);
        @memcpy(@as([]u8, @ptrCast(slice)), self.input[0..needed_bytes]);

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
            return Error.InputTooShort;
        }

        const slice = try alloc.allocSentinel(T, len, Sentinel);
        @memcpy(@as([]u8, @ptrCast(slice)), self.input[0..needed_bytes]);

        self.input = self.input[needed_bytes..];

        return slice;
    }

    pub fn auto_slice(
        self: *FuzzInput,
        comptime T: type,
        len: usize,
        alloc: Allocator,
    ) Error![]T {
        switch (@typeInfo(T)) {
            .int => return try self.int_slice(self, T, len, alloc),
            else => {},
        }

        const slice = try alloc.alloc(T, len);
        for (0..len) |idx| {
            slice[idx] = try self.auto(T, alloc);
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
            .int => return try self.int_slice_sentinel(self, T, Sentinel, len, alloc),
            else => {},
        }

        const slice = try alloc.allocSentinel(T, len, Sentinel);
        for (0..len) |idx| {
            slice[idx] = try self.auto(T, alloc);
        }
        return slice;
    }

    pub fn auto_ptr(self: *FuzzInput, comptime T: type, alloc: Allocator) Error!*T {
        const p = try alloc.create(T);
        p.* = try self.auto(T, alloc);

        return p;
    }

    pub fn auto(self: *FuzzInput, comptime T: type, alloc: Allocator) Error!T {
        switch (@typeInfo(T)) {
            .int => return try self.int(T),
            .float => return try self.float(T),
            .void => return {},
            .bool => return try self.boolean(),
            .array => |arr_info| {
                if (arr_info.sentinel) |sentinel| {
                    return try self.auto_array_sentinel(arr_info.child, arr_info.len, sentinel, alloc);
                } else {
                    return try self.auto_array(arr_info.child, arr_info.len, alloc);
                }
            },
            .pointer => |ptr_info| {
                switch (ptr_info.size) {
                    .one => {
                        if (ptr_info.sentinel()) {
                            @compileError("single pointer with sentinel not supported.");
                        }
                        return try self.auto_ptr(ptr_info.child, alloc);
                    },
                    .many => @compileError("many pointers aren't supported"),
                    .slice => {
                        const len = try self.slice_len(ptr_info.child);
                        if (ptr_info.sentinel()) |sentinel| {
                            return try self.auto_slice_sentinel(ptr_info.child, sentinel, len, alloc);
                        } else {
                            return try self.auto_slice(ptr_info.child, len, alloc);
                        }
                    },
                    .c => @compileError("c pointers aren't supported"),
                }
            },
            .optional => |opt_info| {
                if (try self.boolean()) {
                    return try self.auto(opt_info.child, alloc);
                } else {
                    return null;
                }
            },
            .@"struct" => |struct_info| {},
            .@"enum" => |enum_info| {},
            .@"union" => |union_info| {},
            .vector => |vec_info| {},
            .error_union => |err_uni_info| {},
            .error_set => |err_set_info| {},
        }
    }
};
