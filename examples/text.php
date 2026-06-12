<?php
use Hardened\Text;

var_dump(Text::stripControls("foo\x00bar\x01baz"));
// string(9) "foobarbaz"
var_dump(Text::stripControls("line1\r\nline2", ""));
// string(10) "line1line2"
var_dump(Text::hasControls("innocent\x1b[31m"));
// bool(true)
var_dump(Text::hasControls("plain text"));
// bool(false)

var_dump(Text::sanitizeLogLine("user\r\n[CRITICAL] fake entry"));
// string(25) "user[CRITICAL] fake entry" — CR/LF stripped, no log forging

var_dump(Text::sanitizeHeaderValue("attachment; filename=report.pdf"));
// string(31) "attachment; filename=report.pdf"
try {
    Text::sanitizeHeaderValue("gotcha\r\nSet-Cookie: session=hijacked");
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(2101)
}

var_dump(Text::hasNullBytes("file.php\0.jpg"));
// bool(true)
try {
    Text::assertNoNullBytes("file.php\0.jpg");
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(2100)
}
