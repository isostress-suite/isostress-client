// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! ISOSTRESS_RS-1.0.0 -- binary entry point.
//!
//! Layout convention: all module source files are **laid flat in the project root**, included via `#[path]`;
//! no `src/`, `tests/`, or `interop/` subdirectories. The same module tree is declared
//! in `lib.rs`, which exposes the crate as a library; this file only wires up `main`.
//! The fuzz target under `fuzz/` depends on that library target.
//!
//! A future consolidation may collapse these modules into a **single source file**.

fn main() {
    isostress_rs::cli::main();
}
