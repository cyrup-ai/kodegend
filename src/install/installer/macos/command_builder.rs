//! Command builder for macOS privileged execution.

use std::path::PathBuf;

/// Builder for privileged command execution on macOS.
///
/// This struct constructs shell commands that will be executed with elevated
/// privileges via the KodegenHelper app and osascript.
#[derive(Debug)]
pub(super) struct CommandBuilder {
    /// Program to execute
    pub(super) program: PathBuf,

    /// Arguments for the program
    pub(super) args: Vec<String>,
}

impl CommandBuilder {
    /// Create a new command builder.
    pub(super) fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
        }
    }

    /// Add multiple command line arguments.
    pub(super) fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }
}
