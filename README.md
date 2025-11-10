# fuzzin

Utility library for writing fuzz tests in zig.

It provides:
- Structured input generation.
- Leak checking allocator. 
- Static context.

See [example.zig](./src/example.zig) for example usage.

See [Makefile](./Makefile) for example command to run fuzz tests.

See [build.zig](./build.zig) for example fuzz target setup.

Run with `-Doptimize=ReleaseSafe` to do fuzzing effectively. But switch to
`-Doptimize=Debug` when a crash is found since the stack traces in `ReleaseSafe` aren't accurate.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

