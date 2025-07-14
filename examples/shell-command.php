<?php
use Hardened\ShellCommand;

// 1) Basic builder:
$cmd = new ShellCommand('ls');
$cmd->passArg('-la');
$cmd->setTimeout(5);                // seconds
$cmd->inheritEnvs(['PATH', 'HOME']);
$cmd->passEnv('FOO', 'bar');
$cmd->passthroughStdout();          // print live
$cmd->pipeCallbackStderr(function($chunk) { /* handle stderr chunks */ });

// 2) Run and capture both streams internally:
$code = $cmd->run($stdoutVar, $stderrVar);
// $stdoutVar and $stderrVar now contain full output, $code is exit code.

// 3) One-line helpers:
$result = Hardened\shell_exec('echo hello', ['echo']);
// Enforces top-level command 'echo' only, returns output or exit code.

$args = ['status', '--short'];
$result2 = Hardened\safe_exec('git', $args);
// Spawns `git status --short` without any shell interpretation.z
