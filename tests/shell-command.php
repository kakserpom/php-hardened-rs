<?php
// tests/shell-command.php

// Enable assertions
ini_set('assert.active',   '1');
ini_set('assert.warning',  '1');
ini_set('assert.bail',     '0');

echo "Running ShellCommand tests...\n";

// --- safeFromString basic ---
$cmd = \Hardened\ShellCommand::safeFromString('echo Hello');
assert($cmd instanceof \Hardened\ShellCommand, 'safeFromString returns instance');

$exit = $cmd->run($out, $err);
assert(is_int($exit), 'run() returns int');
assert($exit === 0, 'echo Hello exit code is 0');
assert(strpos($out, 'Hello') !== false, 'stdout contains "Hello"');
assert($err === null || $err === '', 'stderr is empty on success');

// --- safeFromString rejects NUL ---
try {
    \Hardened\ShellCommand::safeFromString("echo\x00oops");
    assert(false, 'safeFromString should throw on NUL');
} catch (\Exception $e) {
    // ext-php-rs rejects NUL bytes in strings before passing to Rust
    assert(strpos($e->getMessage(), 'NUL') !== false, 'NUL error message');
}

// --- shellFromString captures top-level commands ---
$unsafe = \Hardened\ShellCommand::shellFromString('ls -1; id');
assert($unsafe instanceof \Hardened\ShellCommand, 'shellFromString returns instance');
$cmds = $unsafe->topLevelCommands();
assert(is_array($cmds), 'top_level_commands is array');
assert(in_array('ls', $cmds), 'captures "ls"');
assert(in_array('id', $cmds), 'captures "id"');

try {
    Hardened\shell_exec('echo -n $WORD; rev', ['echo']);
    assert(false, 'shell_exec should throw');
} catch (\Exception $e) {
}


// Use a harmless unsafe command
$unsafe2 = \Hardened\ShellCommand::shellFromString('echo foo && echo bar');
$exit2 = $unsafe2->run($o2, $e2);
assert($exit2 === 0, 'unsafe echo exit code is 0');
assert(strpos($o2, 'foo') !== false && strpos($o2, 'bar') !== false, 'unsafe stdout contains both');

// --- pass_env ---
$cmdEnv = \Hardened\ShellCommand::safeFromString('php -r "echo getenv(\'FOO\');"');
$cmdEnv->passEnv('FOO', 'BAR');
$exit3 = $cmdEnv->run($o3, $e3);
assert($exit3 === 0, 'env echo exit code is 0');
assert(trim($o3) === 'BAR', 'environment variable passed correctly');

// --- timeout ---
$slow = \Hardened\ShellCommand::safeFromString('php -r "sleep(2); echo \'done\';"');
$slow->setTimeout(1);
$exit4 = $slow->run($o4, $e4);
assert($exit4 === -1, 'timeout returns -1 on sleep exceed');

// Summary
echo "All ShellCommand tests passed.\n";
