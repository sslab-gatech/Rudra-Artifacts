# Test Rust Package

This directory contains a fairly simple [Rust crate](https://doc.rust-lang.org/book/ch07-01-packages-and-crates.html).
The crate contains two bugs that Rudra detects and generates reports for.

## Bugs

1. A type called `Container` that implements `Send` and `Sync` unconditionally,
   allowing for thread safety issues and memory-safety issues in concurrent
   execution.

2. A function called `map_reference` that takes a mutable reference to a type
   `T` and a mapping function from `T` to `T`. It then applies the mapping
   function to change the underlying value of the mutable reference in an unsafe
   way that is not [exception safe](https://doc.rust-lang.org/nomicon/exception-safety.html).
