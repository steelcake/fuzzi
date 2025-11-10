fuzz:
	zig build fuzz --fuzz -Doptimize=ReleaseSafe -j32
