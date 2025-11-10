const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const fuzzin = @import("fuzzin");

const example = @import("./example.zig");

const MAX_INPUT_DEPTH = 64;

// Generate test for given type
fn FuzzTest(comptime T: type) type {
    return struct {
        fn do_fuzz(
            ctx: void,
            input: *fuzzin.FuzzInput,
            dbg_alloc: Allocator,
        ) fuzzin.Error!void {
            _ = ctx;

            var arena = ArenaAllocator.init(dbg_alloc);
            defer arena.deinit();
            const alloc = arena.allocator();

            // just check that the type generation works
            _ = try input.auto(T, alloc, MAX_INPUT_DEPTH);
        }

        test {
            fuzzin.fuzz_test(
                void,
                {},
                do_fuzz,
                1 << 10,
            );
        }
    };
}

test {
    _ = example;
    _ = FuzzTest(i256);
    _ = FuzzTest(f16);
    _ = FuzzTest(bool);
    _ = FuzzTest([1]u8);
    _ = FuzzTest([1:2]u8);
    _ = FuzzTest([]i16);
    _ = FuzzTest(?u8);
    _ = FuzzTest(struct {
        name: []const u8,
        age: i128,
    });
    _ = FuzzTest(enum { x, y });
    _ = FuzzTest(union(enum) { x: u8, y: [:3]u8 });
    _ = FuzzTest(@Vector(4, f32));
}
