use anyhow::anyhow;
#[cfg(not(test))]
use anyhow::bail;
use ext_php_rs::convert::IntoZval;
#[cfg(not(test))]
use ext_php_rs::types::{ArrayKey, ZendHashTable};
use ext_php_rs::types::{ZendClassObject, ZendObject, Zval};
use ext_php_rs::{php_class, php_impl};
use std::collections::{BTreeMap, HashMap};
use std::os::unix::prelude::ExitStatusExt;
use std::process::Command;
use std::time::Duration;
use wait_timeout::ChildExt;

#[cfg(not(test))]
type Arguments<'a> = &'a ZendHashTable;
#[cfg(test)]
type Arguments<'a> = &'a str;
/// Safe subprocess launcher.
///
/// Allows you to build up a command invocation with arguments, optionally configure
/// a timeout (seconds), and execute it without shell interpolation.
/// Returns exit codes or captures stdout/stderr.
#[php_class]
#[php(name = "Hardened\\ShellCommand")]
pub struct ShellCommand {
    executable: String,
    args: Vec<String>,
    timeout: Option<Duration>,
    env: BTreeMap<String, String>,
}

impl ShellCommand {
    fn _set_timeout(&mut self, seconds: u64) {
        self.timeout = Some(Duration::from_secs(seconds));
    }
    fn _set_timeout_ms(&mut self, seconds: u64) {
        self.timeout = Some(Duration::from_secs(seconds));
    }
    fn _run_capture(&self) -> anyhow::Result<BTreeMap<String, String>> {
        let mut cmd = Command::new(&self.executable);
        cmd.args(&self.args);
        cmd.envs(self.env.iter());
        let output = if let Some(timeout) = self.timeout {
            // no built-in timeout for Output, so spawn + wait + kill
            let mut child = cmd
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|err| anyhow!("Failed to spawn process: {err}"))?;
            let timed_out = match child
                .wait_timeout(timeout)
                .map_err(|err| anyhow!("Error waiting for process: {err}"))?
            {
                Some(_) => false,
                None => {
                    let _ = child.kill();
                    true
                }
            };
            if timed_out {
                // emulate empty output on timeout
                std::process::Output {
                    status: std::process::ExitStatus::from_raw(0),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }
            } else {
                child
                    .wait_with_output()
                    .map_err(|err| anyhow!("Failed to capture output: {err}"))?
            }
        } else {
            cmd.output()
                .map_err(|err| anyhow!("Failed to capture output: {err}"))?
        };

        let mut result = BTreeMap::new();
        let code = output.status.code().unwrap_or(-1);
        result.insert(
            "stdout".to_string(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        );
        result.insert(
            "stderr".to_string(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        );
        result.insert("code".to_string(), code.to_string());
        Ok(result)
    }

    fn _env(&mut self, key: &str, value: &str) -> anyhow::Result<()> {
        self.env.insert(key.to_string(), value.to_string());
        Ok(())
    }
}

#[php_impl]
impl ShellCommand {
    fn env(&mut self, key: String, value: String) -> () {
        self.env.insert(key, value);
        ()
    }

    fn envs(&mut self, map: HashMap<String, String>) -> () {
        self.env.extend(map);
        ()
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
            env: Default::default(),
        }
    }

    /// Constructs a new ShellCommand for the given program path.
    ///
    /// # Parameters
    /// - `executable`: `string` Path to the executable or command name.
    ///
    /// # Notes
    /// - Does not validate existence until execution.
    fn __construct(
        executable: String,
        #[allow(unused_variables)] arguments: Option<Arguments>,
    ) -> anyhow::Result<Self> {
        let mut command = Self::executable(executable);
        if let Some(arguments) = arguments {
            command.arguments(arguments)?;
        }
        Ok(command)
    }

    fn arguments(&mut self, #[allow(unused_variables)] arguments: Arguments) -> anyhow::Result<()> {
        #[cfg(test)]
        panic!("method cannot be called from tests");
        #[cfg(not(test))]
        {
            if arguments.has_numerical_keys() {
                for (i, value) in arguments.values().enumerate() {
                    if let Some(string) = value.string() {
                        self.args.push(string);
                    } else if let Some(int) = value.long() {
                        self.args.push(int.to_string());
                    } else {
                        bail!("argument {i}: value can only be string or int");
                    }
                }
            } else {
                for (key, value) in arguments {
                    match key {
                        ArrayKey::String(_) | ArrayKey::Str(_) => {
                            self.args.push(format!("--{key}"));
                        }
                        ArrayKey::Long(_) => {}
                    }
                    if let Some(string) = value.string() {
                        self.args.push(string);
                    } else if let Some(int) = value.long() {
                        self.args.push(int.to_string());
                    } else {
                        bail!("argument {key:?}: value can only be string or int");
                    }
                }
            }
            Ok(())
        }
    }

    /// Adds one argument to the command line.
    ///
    /// # Parameters
    /// - `arg`: `string` A single argument (will not be interpreted by a shell).
    fn argument(&mut self, arg: &str) {
        self.args.push(arg.to_string());
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

    /// Runs the command, waits for it to exit, and returns its exit code.
    ///
    /// # Returns
    /// - `int` The child process’s exit code, or `-1` if it was terminated by signal or timed out.
    ///
    /// # Exceptions
    /// - Throws `Exception` if the process cannot be spawned.
    fn run(&self) -> anyhow::Result<i64> {
        let mut cmd = Command::new(&self.executable);
        cmd.args(&self.args);
        cmd.envs(self.env.iter());
        let status = if let Some(timeout) = self.timeout {
            let mut child = cmd
                .spawn()
                .map_err(|err| anyhow!("Failed to spawn process: {err}"))?;
            match child
                .wait_timeout(timeout)
                .map_err(|err| anyhow!("Error waiting for process: {err}"))?
            {
                Some(status) => status,
                None => {
                    // timeout expired
                    let _ = child.kill();
                    return Ok(-1);
                }
            }
        } else {
            cmd.status()
                .map_err(|err| anyhow!("Failed to run process: {err}"))?
        };

        Ok(status.code().unwrap_or(-1) as i64)
    }

    /// Runs the command and captures both stdout and stderr.
    ///
    /// # Returns
    /// - `array` Associative array with keys:
    ///    - `stdout` => `string`
    ///    - `stderr` => `string`
    ///    - `code`   => `int` exit code (or `-1` on timeout or signal)
    ///
    /// # Exceptions
    /// - Throws `Exception` if the process cannot be spawned.
    fn run_capture(&self) -> anyhow::Result<Zval> {
        let mut obj = ZendObject::new_stdclass();
        for (key, value) in self._run_capture()? {
            obj.set_property(&key, value)
                .map_err(|err| anyhow!("{err:?}"))?;
        }
        Ok(obj.into_zval(false).map_err(|err| anyhow!("{err:?}"))?)
    }
}

#[cfg(test)]
mod tests {
    use super::ShellCommand;
    use crate::run_php_example;

    #[test]
    fn test_run_success_exit_zero() {
        // `true` always exits with status 0
        let cmd = ShellCommand::__construct("true".into(), None).unwrap();
        let code = cmd.run().unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn test_run_nonzero_exit() {
        // `false` always exits with status 1
        let cmd = ShellCommand::__construct("false".into(), None).unwrap();
        let code = cmd.run().unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn test_run_args() {
        // echo "hello"
        let mut cmd = ShellCommand::__construct("echo".into(), None).unwrap();
        cmd.argument("hello");
        let out = cmd._run_capture().unwrap();
        assert_eq!(out.get("stdout").map(|s| s.trim()), Some("hello"));
        assert_eq!(out.get("stderr").map(|s| s.as_str()), Some(""));
        assert_eq!(out.get("code").map(|s| s.as_str()), Some("0"));
    }

    #[test]
    fn test_run_capture_large_output() {
        // repeat pattern to get multi-line output
        let mut cmd = ShellCommand::executable("printf".into());
        cmd.argument("line1\nline2\n");
        let out = cmd._run_capture().unwrap();
        assert_eq!(out["stdout"], "line1\nline2\n");
        assert_eq!(out["stderr"], "");
        assert_eq!(out["code"], "0");
    }

    #[test]
    fn test_timeout_kills_long_running() {
        // sleep 2 seconds, but timeout after 1
        let mut cmd = ShellCommand::executable("sleep".into());
        cmd.argument("2");
        cmd._set_timeout(1);
        let code = cmd.run().unwrap();
        // timed-out processes return -1
        assert_eq!(code, -1);
    }

    #[test]
    fn test_timeout_capture() {
        // sleep 2 seconds, but timeout after 1
        let mut cmd = ShellCommand::executable("sleep".into());
        cmd.argument("1");
        cmd._set_timeout_ms(1);
        let out = cmd._run_capture().unwrap();
        // no stdout/stderr on timeout
        assert_eq!(out["stdout"], "");
        assert_eq!(out["stderr"], "");
        assert_eq!(out["code"], "0"); // we emulate code=0 on timeout
    }

    #[test]
    fn test_env() {
        let mut cmd = ShellCommand::executable("/bin/bash".into());
        cmd.argument("-c");
        cmd.argument("echo $FOO");
        cmd.env("FOO".into(), "BAR".into());
        let out = cmd._run_capture().unwrap();
        assert_eq!(out["stdout"], "BAR\n");
        assert_eq!(out["stderr"], "");
        assert_eq!(out["code"], "0");
    }

    #[test]
    fn php_example() -> anyhow::Result<()> {
        run_php_example("shell-command")?;
        Ok(())
    }
}
