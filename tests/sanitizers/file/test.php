<?php
use Hardened\Sanitizers\File\ArchiveSanitizer;

try {
    ArchiveSanitizer::defuse(__DIR__ . '/zbsm.zip');
} catch (\Throwable) {
    echo "DEFUSED!";
}
