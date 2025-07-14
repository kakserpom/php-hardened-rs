use anyhow::anyhow;
use anyhow::bail;
use ext_php_rs::types::{ZendCallable, ZendClassObject, Zval};
use ext_php_rs::{php_class, php_function, php_impl, wrap_function};
use ext_php_rs::{
    php_print,
    types::{ArrayKey, ZendHashTable},
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::io::Read;
use std::time::{Duration, Instant};

use crate::shell_command::PipeMode::{CallbackMode, IgnoreMode, PassthroughMode};
use anyhow::Result;
use ext_php_rs::builders::ModuleBuilder;
use libc::{F_GETFL, F_SETFL, O_NONBLOCK, fcntl};
use std::os::unix::io::AsRawFd;
use std::process::{Command, Stdio};

/// Safe subprocess launcher.
///
/// Allows you to build up a command invocation with arguments, optionally configure
/// a timeout (seconds), and execute it without shell interpolation.
/// Returns exit codes or captures stdout/stderr.
#[php_class]
#[php(name = "Hardened\\ShellCommand")]
#[derive(Debug)]
pub struct ShellCommand {
    executable: String,
    args: Vec<String>,
    timeout: Option<Duration>,
    inherit_env: Option<BTreeSet<String>>,
    pass_env: BTreeMap<String, String>,
    out_pipe_mode: PipeMode,
    err_pipe_mode: PipeMode,
    top_level_commands: Option<Vec<String>>,
}

#[derive(Debug)]
enum PipeMode {
    IgnoreMode,
    PassthroughMode,
    CallbackMode(Zval),
}

#[php_impl]
impl ShellCommand {
    /// Constructs a new ShellCommand for the given program path.
    ///
    /// # Parameters
    /// - `executable`: `string` Path to the executable or command name.
    ///
    /// # Notes
    /// - Does not validate existence until execution.
    fn __construct(executable: String, arguments: Option<&ZendHashTable>) -> Result<Self> {
        let mut command = Self::executable(executable);
        if let Some(arguments) = arguments {
            if arguments.has_numerical_keys() {
                for (i, value) in arguments.values().enumerate() {
                    if let Some(string) = value.string() {
                        command.args.push(string);
                    } else if let Some(int) = value.long() {
                        command.args.push(int.to_string());
                    } else {
                        bail!("argument {i}: value can only be string or int");
                    }
                }
            } else {
                for (key, value) in arguments {
                    match key {
                        ArrayKey::String(_) | ArrayKey::Str(_) => {
                            command.args.push(format!("--{key}"));
                        }
                        ArrayKey::Long(_) => {}
                    }
                    if let Some(string) = value.string() {
                        command.args.push(string);
                    } else if let Some(int) = value.long() {
                        command.args.push(int.to_string());
                    } else {
                        bail!("argument {key:?}: value can only be string or int");
                    }
                }
            }
        }
        Ok(command)
    }

    /// Enable passthrough mode for both stdout and stderr:
    /// PHP will receive all child-process output directly.
    fn passthrough_both(
        self_: &mut ZendClassObject<ShellCommand>,
    ) -> &mut ZendClassObject<ShellCommand> {
        self_.err_pipe_mode = PassthroughMode;
        self_.out_pipe_mode = PassthroughMode;
        self_
    }

    /// Enable passthrough mode for stdout only.
    fn passthrough_stdout(
        self_: &mut ZendClassObject<ShellCommand>,
    ) -> &mut ZendClassObject<ShellCommand> {
        self_.out_pipe_mode = PassthroughMode;
        self_
    }

    /// Enable passthrough mode for stderr only.
    fn passthrough_stderr(
        self_: &mut ZendClassObject<ShellCommand>,
    ) -> &mut ZendClassObject<ShellCommand> {
        self_.err_pipe_mode = PassthroughMode;
        self_
    }

    /// Silently ignore both stdout and stderr.
    fn ignore_both(
        self_: &mut ZendClassObject<ShellCommand>,
    ) -> &mut ZendClassObject<ShellCommand> {
        self_.err_pipe_mode = IgnoreMode;
        self_.out_pipe_mode = IgnoreMode;
        self_
    }

    /// Silently ignore stdout.
    fn ignore_stdout(
        self_: &mut ZendClassObject<ShellCommand>,
    ) -> &mut ZendClassObject<ShellCommand> {
        self_.out_pipe_mode = IgnoreMode;
        self_
    }

    /// Silently ignore stderr.
    fn ignore_stderr(
        self_: &mut ZendClassObject<ShellCommand>,
    ) -> &mut ZendClassObject<ShellCommand> {
        self_.err_pipe_mode = IgnoreMode;
        self_
    }

    /// Pipe both stdout and stderr through a PHP callable.
    ///
    /// The callable will be invoked for each chunk of output.
    fn pipe_callback_both<'a>(
        self_: &'a mut ZendClassObject<ShellCommand>,
        callable: &Zval,
    ) -> &'a mut ZendClassObject<ShellCommand> {
        self_.err_pipe_mode = CallbackMode(callable.shallow_clone());
        self_.out_pipe_mode = CallbackMode(callable.shallow_clone());
        self_
    }

    /// Pipe stdout through a PHP callable.
    fn pipe_callback_stdout<'a>(
        self_: &'a mut ZendClassObject<ShellCommand>,
        callable: &Zval,
    ) -> &'a mut ZendClassObject<ShellCommand> {
        self_.out_pipe_mode = CallbackMode(callable.shallow_clone());
        self_
    }

    /// Pipe stderr through a PHP callable.
    fn pipe_callback_stderr<'a>(
        self_: &'a mut ZendClassObject<ShellCommand>,
        callable: &Zval,
    ) -> &'a mut ZendClassObject<ShellCommand> {
        self_.err_pipe_mode = CallbackMode(callable.shallow_clone());
        self_
    }

    /// Merge in additional environment variables for the child process.
    ///
    /// Existing passed-env map is extended.
    fn pass_envs(
        self_: &mut ZendClassObject<ShellCommand>,
        map: HashMap<String, String>,
    ) -> &mut ZendClassObject<ShellCommand> {
        self_.pass_env.extend(map);
        self_
    }

    /// Replace the child-process environment with exactly the given map.
    fn pass_env_only(
        self_: &mut ZendClassObject<ShellCommand>,
        map: HashMap<String, String>,
    ) -> &mut ZendClassObject<ShellCommand> {
        self_.pass_env.clear();
        self_.pass_env.extend(map);
        self_
    }

    /// Inherit _all_ parent environment variables.
    fn inherit_all_envs(&mut self) {
        self.inherit_env = None;
    }

    /// Inherit only the specified environment variable names.
    fn inherit_envs(&mut self, envs: Vec<String>) {
        match self.inherit_env.as_mut() {
            None => {
                let _ = self.inherit_env.insert(BTreeSet::from_iter(envs));
            }
            Some(set) => {
                set.extend(envs);
            }
        }
    }
    /// Pass a single environment variable to the child.
    fn pass_env(&mut self, key: &str, value: &str) {
        self.pass_env.insert(key.to_string(), value.to_string());
    }

    /// Append numeric or flag-style arguments from a PHP table.
    ///
    /// Numeric keys => positional args; string keys => `--key value`.
    fn pass_args<'a>(
        #[allow(unused_variables)] self_: &'a mut ZendClassObject<ShellCommand>,
        #[allow(unused_variables)] arguments: &'a ZendHashTable,
    ) -> Result<&'a mut ZendClassObject<ShellCommand>> {
        if arguments.has_numerical_keys() {
            for (i, value) in arguments.values().enumerate() {
                if let Some(string) = value.string() {
                    self_.args.push(string);
                } else if let Some(int) = value.long() {
                    self_.args.push(int.to_string());
                } else {
                    bail!("argument {i}: value can only be string or int");
                }
            }
        } else {
            for (key, value) in arguments {
                match key {
                    ArrayKey::String(_) | ArrayKey::Str(_) => {
                        self_.args.push(format!("--{key}"));
                    }
                    ArrayKey::Long(_) => {}
                }
                if let Some(string) = value.string() {
                    self_.args.push(string);
                } else if let Some(int) = value.long() {
                    self_.args.push(int.to_string());
                } else {
                    bail!("argument {key:?}: value can only be string or int");
                }
            }
        }
        Ok(self_)
    }

    /// Adds one argument to the command line.
    ///
    /// # Parameters
    /// - `arg`: `string` A single argument (will not be interpreted by a shell).
    fn pass_arg(
        self_: &mut ZendClassObject<ShellCommand>,
        arg: String,
    ) -> &mut ZendClassObject<ShellCommand> {
        self_.args.push(arg);
        self_
    }

    /// Sets an execution timeout in seconds.
    ///
    /// # Parameters
    /// - `seconds`: `int` Maximum time to wait before killing the process.
    ///
    /// # Notes
    /// - If the process does not exit within this period, it will be terminated.
    fn set_timeout(
        self_: &mut ZendClassObject<ShellCommand>,
        seconds: u64,
    ) -> &mut ZendClassObject<ShellCommand> {
        self_.timeout = Some(Duration::from_secs(seconds));
        self_
    }

    /// Sets an execution timeout in milliseconds.
    ///
    /// # Parameters
    /// - `milliseconds`: `int` Maximum time to wait before killing the process.
    ///
    /// # Notes
    /// - If the process does not exit within this period, it will be terminated.
    fn set_timeout_ms(
        self_: &mut ZendClassObject<ShellCommand>,
        milliseconds: u64,
    ) -> &mut ZendClassObject<ShellCommand> {
        self_.timeout = Some(Duration::from_secs(milliseconds));
        self_
    }

    ///
    /// # Parameters
    /// - `string $cmdline` Full command line to run.
    ///
    /// # Returns
    /// - `ShellCommand`
    ///
    /// # Exceptions
    /// - Throws `Exception` on parse errors or if disallowed characters are present.
    pub fn safe_from_string(command_line: &str) -> Result<Self> {
        // 1) Basic sanity
        if command_line.trim().is_empty() {
            bail!("command line must not be empty");
        }

        // 2) Split into tokens (handles quotes, backslashes, etc.)
        let parts = shell_words::split(command_line)
            .map_err(|e| anyhow!("failed to parse command line: {}", e))?;

        if parts.is_empty() {
            bail!("no command found");
        }

        // 3) Disallow only NUL bytes (no real need to forbid any shell metachars,
        //    since we do *not* use a shell interpreter)
        for tok in &parts {
            if tok.contains('\0') {
                bail!("invalid character in token {:?}", tok);
            }
        }

        // 4) The first part is the executable, the rest are args
        let executable = parts[0].clone();
        let mut self_ = Self::executable(executable);
        self_.args.extend(parts.into_iter().skip(1));
        Ok(self_)
    }

    /// Exactly like `shell_exec()`: pass the *raw* string to `/bin/sh -c`
    /// and record the top-level command names.
    ///
    /// # Parameters
    /// - `string $cmdline` Full shell-style command line to run.
    ///
    /// # Returns
    /// - `ShellCommand`
    ///
    /// # Exceptions
    /// - Throws `Exception` on parse errors (e.g. empty line).
    pub fn shell_from_string(cmdline: &str) -> Result<Self> {
        let line = cmdline.trim();
        if line.is_empty() {
            bail!("command line must not be empty");
        }

        // 1) split on top-level unquoted separators (;, |, &&, ||)
        let mut cmds = Vec::new();
        let mut buf = String::new();
        let mut in_sq = false;
        let mut in_dq = false;
        let mut prev = '\0';

        for c in line.chars() {
            // very basic state machine
            if c == '"' && !in_sq {
                in_dq = !in_dq;
            } else if c == '\'' && !in_dq {
                in_sq = !in_sq;
            }

            // look for separators only when not inside quotes
            if !in_sq && !in_dq {
                // check for || and &&
                if (prev == '|' && c == '|') || (prev == '&' && c == '&') {
                    // treat the double-char token as break, but don't record it
                    let seg = buf.trim();
                    if !seg.is_empty() {
                        cmds.push(seg.to_string());
                    }
                    buf.clear();
                    prev = '\0';
                    continue;
                }
                if matches!(c, ';' | '|' | '&') {
                    // single-char separator
                    let seg = buf.trim();
                    if !seg.is_empty() {
                        cmds.push(seg.to_string());
                    }
                    buf.clear();
                    prev = c;
                    continue;
                }
            }

            buf.push(c);
            prev = c;
        }
        if !buf.trim().is_empty() {
            cmds.push(buf.trim().to_string());
        }

        // 2) for each top-level segment, shell-split it and take the first token
        let mut top_level_commands = Vec::new();
        for seg in &cmds {
            let parts = shell_words::split(seg)
                .map_err(|e| anyhow!("failed to parse segment `{}`: {}", seg, e))?;
            if let Some(first) = parts.get(0) {
                top_level_commands.push(first.clone());
            }
        }
        let mut self_ = Self::shell();
        self_.args.extend(["-c".into(), line.to_string()]);
        self_.top_level_commands = Some(top_level_commands);
        Ok(self_)
    }

    /// Constructs a new ShellCommand for the given program path.
    ///
    /// # Parameters
    /// - `executable`: `string` Path to the executable or command name.
    ///
    /// # Notes
    /// - Does not validate existence until execution.
    fn executable(executable: String) -> Self {
        Self {
            executable,
            args: Vec::new(),
            timeout: None,
            pass_env: Default::default(),
            out_pipe_mode: IgnoreMode,
            err_pipe_mode: IgnoreMode,
            inherit_env: None,
            top_level_commands: None,
        }
    }

    /// Returns the list of top-level command names parsed from the original shell line.
    ///
    /// # Returns
    /// - `Option<Vec<String>>`:
    ///   - `Some(vec)` when `shell_from_string()` was used and top-level commands were recorded;
    ///   - `None` otherwise.
    fn top_level_commands(&self) -> Option<Vec<String>> {
        self.top_level_commands.clone()
    }

    /// Constructs a new `ShellCommand` using the user’s login shell.
    ///
    /// Looks up the `SHELL` environment variable, or falls back to `/bin/sh` if unset.
    ///
    /// # Returns
    /// - `ShellCommand`: with `executable` set to the shell path and no arguments.
    fn shell() -> Self {
        Self::executable(env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string()))
    }

    /// Runs the command, streaming stdout/stderr live (according to configured pipe modes),
    /// enforces the configured timeout, and optionally captures output into PHP variables.
    ///
    /// # Parameters
    /// - `stdout`: `?string &$stdout`
    ///   Optional reference to a PHP variable; if provided, the collected stdout will be written here.
    /// - `stderr`: `?string &$stderr`
    ///   Optional reference to a PHP variable; if provided, the collected stderr will be written here.
    ///
    /// # Returns
    /// - `int`
    ///   The process’s exit code (`0` on success, `-1` if killed by signal or timed out).
    ///
    /// # Exceptions
    /// - Throws `Exception` if the process cannot be spawned.
    /// Runs the command, streaming both stdout and stderr live, with a timeout and
    /// selected environment variables passed through.
    pub fn run(
        &mut self,
        mut capture_stdout: Option<&mut Zval>,
        mut capture_stderr: Option<&mut Zval>,
    ) -> Result<i64> {
        let mut stdout_buf = capture_stdout.is_some().then(String::new);
        let mut stderr_buf = capture_stderr.is_some().then(String::new);
        let mut cmd = Command::new(&self.executable);
        cmd.args(&self.args);
        if let Some(inherit_env) = self.inherit_env.as_ref() {
            cmd.env_clear();
            cmd.envs(env::vars().filter(|&(ref k, _)| inherit_env.contains(k)));
        }
        cmd.envs(self.pass_env.iter());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|err| anyhow!("Failed to spawn process: {err}"))?;

        let mut out = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();

        for fd in &[out.as_raw_fd(), err.as_raw_fd()] {
            unsafe {
                let flags = fcntl(*fd, F_GETFL);
                if flags < 0 {
                    return Err(anyhow!("fcntl F_GETFL failed"));
                }
                if fcntl(*fd, F_SETFL, flags | O_NONBLOCK) < 0 {
                    return Err(anyhow!("fcntl F_SETFL failed"));
                }
            }
        }
        let select_timeout = Duration::from_millis(100);
        let mut buf = [0u8; 4096];
        let start = Instant::now();
        loop {
            let mut rfds: libc::fd_set = unsafe { std::mem::zeroed() };
            let out_fd = out.as_raw_fd();
            let err_fd = err.as_raw_fd();
            unsafe {
                libc::FD_ZERO(&mut rfds);
                libc::FD_SET(out_fd, &mut rfds);
                libc::FD_SET(err_fd, &mut rfds);
            }
            if let Some(timeout) = self.timeout {
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    let _ = child.kill();
                    return Ok(-1);
                }
            }
            let mut tv = libc::timeval {
                tv_sec: select_timeout.as_secs() as _,
                tv_usec: (select_timeout.subsec_micros()) as _,
            };

            let nfds = std::cmp::max(out_fd, err_fd) + 1;
            let ready = unsafe {
                libc::select(
                    nfds,
                    &mut rfds,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut tv,
                )
            };
            if ready < 0 {
                return Err(anyhow!("select failed"));
            }
            if ready == 0 {
                let _ = child
                    .kill()
                    .map_err(|e| anyhow!("Failed to kill on timeout: {e}"))?;
                return Ok(-1);
            }

            if unsafe { libc::FD_ISSET(out_fd, &mut rfds) } {
                match out.read(&mut buf) {
                    Ok(0) => {}
                    Ok(n) => {
                        match &self.out_pipe_mode {
                            IgnoreMode => {}
                            PassthroughMode => {
                                php_print!("{}", String::from_utf8_lossy(&buf[..n]));
                            }
                            CallbackMode(callback) => {
                                ZendCallable::new(callback)
                                    .map_err(|err| anyhow!("{err}"))?
                                    .try_call(vec![&String::from_utf8_lossy(&buf[..n]).to_string()])
                                    .map_err(|err| anyhow!("{err}"))?;
                            }
                        }
                        if let Some(s) = stdout_buf.as_mut() {
                            s.push_str(&*String::from_utf8_lossy(&buf[..n]));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(anyhow!("{e}")),
                }
            }
            if unsafe { libc::FD_ISSET(err_fd, &mut rfds) } {
                match err.read(&mut buf) {
                    Ok(0) => {}
                    Ok(n) => {
                        match &self.err_pipe_mode {
                            IgnoreMode => {}
                            PassthroughMode => {
                                php_print!("{}", String::from_utf8_lossy(&buf[..n]));
                            }
                            CallbackMode(callback) => {
                                ZendCallable::new(callback)
                                    .map_err(|err| anyhow!("{err}"))?
                                    .try_call(vec![&String::from_utf8_lossy(&buf[..n]).to_string()])
                                    .map_err(|err| anyhow!("{err}"))?;
                            }
                        }
                        if let Some(s) = stderr_buf.as_mut() {
                            s.push_str(&*String::from_utf8_lossy(&buf[..n]));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(anyhow!("{e}")),
                }
            }

            if let Some(_) = child.try_wait().map_err(|e| anyhow!("{e}"))? {
                break;
            }
        }

        let status = child.wait().map_err(|e| anyhow!("{e}"))?;

        if let Some(zval) = capture_stderr.as_mut()
            && let Some(buf) = stderr_buf
        {
            zval.set_string(buf.as_str(), false).unwrap();
        }

        if let Some(zval) = capture_stdout.as_mut()
            && let Some(buf) = stdout_buf
        {
            zval.set_string(buf.as_str(), false).unwrap();
        }
        Ok(status.code().unwrap_or(-1) as i64)
    }
}

pub(crate) fn build(module: ModuleBuilder) -> ModuleBuilder {
    module
        .class::<ShellCommand>()
        .function(wrap_function!(safe_exec))
        .function(wrap_function!(shell_exec))
}

#[php_function]
#[php(name = "Hardened\\shell_exec")]
/// Execute a shell command via the user’s login shell, enforcing top-level command checks.
///
/// # Parameters
/// - `string $command`: Full shell-style command line to run (e.g. `"ls -la /tmp"`).
/// - `string[]|null $expectedCommands`: Optional list of allowed top-level command names
///   (the first word of each pipeline segment). If provided, any top-level command not in this list
///   will abort with an exception to prevent injection.
///
/// # Returns
/// - `string|null`: On success, returns the command’s stdout output as a string (or exit code as string if non-zero).
///   Returns `null` only on error spawning the process.
///
/// # Exceptions
/// - Throws `Exception` if parsing fails, an unexpected top-level command is detected, or command execution fails.
pub fn shell_exec(command: &str, expected_commands: Option<Vec<String>>) -> Result<Option<Zval>> {
    let mut self_ = ShellCommand::shell_from_string(command)?;
    match (expected_commands, &self_.top_level_commands) {
        (Some(expected_commands), Some(top_level_commands)) => {
            for top_level_command in top_level_commands.into_iter() {
                if !expected_commands.contains(&top_level_command) {
                    bail!(
                        "Unexpected top-level command: {top_level_command:?}.
    Possible injection attempt. Requires investigation.
    Full argument value {command:?}
    Expected top-level commands: {expected_commands:?}
                        "
                    );
                }
            }
        }
        _ => {}
    };
    let mut out = Zval::new();
    let code = self_.run(Some(&mut out), None)?;
    if code != 0 {
        out.set_string(code.to_string().as_str(), false).unwrap();
    }
    Ok(Some(out))
}

#[php_function]
#[php(name = "Hardened\\safe_exec")]
/// Execute a single command (no shell), splitting arguments safely without interpolation.
///
/// # Parameters
/// - `string $command`: The command to run, in shell-word syntax (quoted or unquoted).
/// - `array|null $arguments`: Optional associative or indexed array of additional arguments:
///   - Indexed (numeric) arrays append values in order.
///   - Associative arrays use keys as `--key` flags followed by their value.
///
/// # Returns
/// - `string|null`: On success, returns captured stdout as a string (or exit code as string if non-zero).
///   Returns `null` only on error spawning the process.
///
/// # Exceptions
/// - Throws `Exception` if parsing fails or process execution fails.
pub fn safe_exec(command: &str, arguments: Option<&ZendHashTable>) -> Result<Option<Zval>> {
    let mut command = ShellCommand::safe_from_string(command)?;
    if let Some(arguments) = arguments {
        if arguments.has_numerical_keys() {
            for (i, value) in arguments.values().enumerate() {
                if let Some(string) = value.string() {
                    command.args.push(string);
                } else if let Some(int) = value.long() {
                    command.args.push(int.to_string());
                } else {
                    bail!("argument {i}: value can only be string or int");
                }
            }
        } else {
            for (key, value) in arguments {
                match key {
                    ArrayKey::String(_) | ArrayKey::Str(_) => {
                        command.args.push(format!("--{key}"));
                    }
                    ArrayKey::Long(_) => {}
                }
                if let Some(string) = value.string() {
                    command.args.push(string);
                } else if let Some(int) = value.long() {
                    command.args.push(int.to_string());
                } else {
                    bail!("argument {key:?}: value can only be string or int");
                }
            }
        }
    }
    let mut out = Zval::new();
    let code = command.run(Some(&mut out), None)?;
    if code != 0 {
        out.set_string(code.to_string().as_str(), false).unwrap();
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use crate::{run_php_example, run_php_test};

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("shell-command")?;
        Ok(())
    }

    #[test]
    fn php_test() -> anyhow::Result<()> {
        run_php_test("shell-command")?;
        Ok(())
    }
}
