const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const fuzzin = @import("fuzzin");

const MAX_INPUT_DEPTH = 64;

/// Type to check if the FuzzInput is able to generate all implemented types properly
const FuzzType = struct {
    name: [:0]const u8,
    nested: ?*const FuzzType,
    nesteds: ?[]const FuzzType,
    nesteds2: ?[]FuzzType,
    nested_arr: ?[3]*FuzzType,
    age: u256,
    age2: i128,
    age3: i8,
    ages: []const i32,
    ages2: []u64,
    ages3: []i16,
    opt: union(enum) {
        a: u32,
        b: enum(u128) {
            x = 123213,
            d = 6969,
            c,
        },
    },
    vec: @Vector(8, u32),
    floa: f16,
    floatt: f32,
    floatttt: f64,
    bools: []bool,
    bools2: [15]bool,
    arr: [69:5]u32,
};

/// Validate an instance of `FuzzType` so we can make sure the `FuzzInput` generated it properly
fn validate(t: *const FuzzType) void {
    std.debug.assert(std.mem.findScalar(u8, t.name, 0) == null);

    if (t.nested) |n| {
        validate(n);
    }

    if (t.nesteds) |*nn| {
        for (nn.*) |*n| {
            validate(n);
        }
    }

    if (t.nesteds2) |*nn| {
        for (nn.*) |*n| {
            validate(n);
        }
    }

    if (t.nested_arr) |x| {
        for (x) |n| {
            validate(n);
        }
    }

    std.debug.assert(std.mem.findScalar(u32, &t.arr, 5) == null);

    // kaboom
    // enable to check if everything is running properly and the fuzzer is able to crash
    // std.debug.assert(t.arr[31] != 69);
}

/// Implements a single fuzz run
fn fuzz_fuzz(
    // We can use this to pass expensive-to-construct objects like large allocations.
    // This can be used to make fuzzing runs faster while being able to use these expensive-to-construct objects.
    ctx: *u32,
    // `FuzzInput` is used to generate structured input for our fuzz function.
    // It generates valid (as far as the type system of the language goes) instances of the requested types.
    input: *fuzzin.FuzzInput,
    // debug allocator, this allocator will be reset and checked for leaks after every fuzz run.
    dbg_alloc: Allocator,
) fuzzin.Error!void {
    // check that the context was passed properly;
    std.debug.assert(ctx.* == 69);

    // We use an arena allocator to be able to deallocate the `FuzzType` object.
    // This is the intended allocation scheme for calling `FuzzInput.auto`.
    var arena = ArenaAllocator.init(dbg_alloc);
    defer arena.deinit();

    // We are limiting the maximum allocation that can be done through this arena allocator to
    // 512KB which is half of our total budget. Since we configured 1MB of memory limit on the `dbg_alloc`
    var limited_alloc = fuzzin.LimitedAllocator.init(arena.allocator(), 1 << 9);
    const alloc = limited_alloc.allocator();

    const t = try input.auto(FuzzType, alloc, MAX_INPUT_DEPTH);

    // Make sure the generated type is valid
    validate(&t);

    // kaboom
    // enable to check if everything is running properly and the fuzzer is able to crash
    // std.debug.assert((try input.bytes(32))[31] != 69);
    //

    _ = input.all_bytes();
}

// This is how we trigger the fuzz testing
test {
    // dummy context to check that it is passed into `fuzz_fuzz` function properly
    var ctx: u32 = 69;

    fuzzin.fuzz_test(
        *u32,
        // pass the context
        &ctx,
        // call `fuzz_fuzz` for individual fuzz runs.
        fuzz_fuzz,
        // Allocate 1MB of memory once and re-use it as a DebugAllocator for every individual fuzz run.
        1 << 20,
    );
}
