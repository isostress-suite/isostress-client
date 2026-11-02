// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! ISOSTRESS_RS-1.0.0 -- binary entry point.
//!
//! Current layout: all module source files are **laid flat in the project root**, included via `#[path]`;
//! there is no `src/`, `tests/`, or `interop/` subdirectory. Flatness is the current state, not a
//! collection requirement: implementations follow the ordinary engineering layout of the language in use.
//! The same module tree is declared in `lib.rs`, which exposes the crate as a library; this file only
//! wires up `main`. The fuzz target under `fuzz/` depends on that library target.

fn main() {
    isostress_rs::cli::main();
}
