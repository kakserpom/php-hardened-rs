<?php
use Hardened\ShellCommand;

$command = ShellCommand::executable("cat");
$command->arguments([__FILE__]);
var_dump($command->runCapture()->stdout);
