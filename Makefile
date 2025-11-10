fuzz:
	zig build fuzz --fuzz -Doptimize=ReleaseSafe -j32
fuzz_debug:
	zig build fuzz --fuzz -Doptimize=Debug -j32
