## 2025-11-25 - Grouping Clap Arguments
**Learning:** Utilizing the `help_heading` attribute directly within the `#[arg()]` macro in `clap` structs is an excellent and low-effort way to logically group related CLI flags in the `--help` output.
**Action:** Apply `help_heading` to group related arguments together in all future CLI tools that use `clap`.

## 2025-11-25 - Coloring Error Messages
**Learning:** When using the `colored` crate, explicitly constructing error message prefixes like `"error:".red().bold()` directly within an `eprintln!` macro provides a cleaner and more standardized way to format error outputs than attempting to format the entire string or using default unstyled prints.
**Action:** Always wrap crucial error or warning prefixes in `.red().bold()` (or similar) when printing to standard error to draw the user's attention.
