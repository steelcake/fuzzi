const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const fuzzi = @import("fuzzi");

const FuzzType = struct {
    name: [:0]const u8,
    nested: ?*const FuzzType,
    nesteds: []const FuzzType,
    nesteds2: []FuzzType,
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
    arr: [69:5]u32,
};

fn validate(t: *const FuzzType) void {
    std.debug.assert(std.mem.findScalar(u8, t.name, 0) == null);

    if (t.nested) |n| {
        validate(n);
    }

    for (t.nesteds) |*n| {
        validate(n);
    }

    for (t.nesteds2) |*n| {
        validate(n);
    }

    std.debug.assert(std.mem.findScalar(u32, &t.arr, 5) == null);

    // kaboom
    // std.debug.assert(t.arr[31] != 69);
}

fn fuzz_fuzz(
    ctx: *anyopaque,
    input: *fuzzi.FuzzInput,
    dbg_alloc: Allocator,
) fuzzi.Error!void {
    std.debug.assert(@as(*u32, @ptrCast(@alignCast(ctx))).* == 69);

    var arena = ArenaAllocator.init(dbg_alloc);
    defer arena.deinit();
    const alloc = arena.allocator();

    const MAX_RECURSION_DEPTH = 64;
    const t = try input.auto(FuzzType, alloc, MAX_RECURSION_DEPTH);
    validate(&t);
}

test fuzz_fuzz {
    var ctx: u32 = 69;
    fuzzi.fuzz_test(@ptrCast(&ctx), fuzz_fuzz, 1 << 20);
}
