<?php
use Hardened\Filename;

var_dump(Filename::sanitize("../../etc/passwd"));
// string(6) "passwd"
var_dump(Filename::sanitize("invoice_\u{202E}cod.exe"));
// string(15) "invoice_cod.exe" — RLO bidi override removed, no visual spoof
var_dump(Filename::sanitize("CON.txt"));
// string(8) "_CON.txt" — reserved Windows device name neutralized
var_dump(Filename::sanitize("report.pdf..."));
// string(10) "report.pdf"
var_dump(Filename::sanitize("a<b>c:d.txt"));
// string(11) "a_b_c_d.txt"

var_dump(Filename::isSafe("report.pdf"));
// bool(true)
var_dump(Filename::isSafe("shell.php.jpg"));
// bool(false)
var_dump(Filename::hasDangerousExtension("invoice.pdf.php"));
// bool(true)
var_dump(Filename::hasDoubleExtension("invoice.pdf.exe"));
// bool(true)
var_dump(Filename::hasDangerousExtension("archive.tar.gz"));
// bool(false)

var_dump(Filename::contentDisposition("report.pdf"));
// string(35) "attachment; filename=\"report.pdf\""
var_dump(Filename::contentDisposition("отчёт.pdf"));
// attachment; filename="_____.pdf"; filename*=UTF-8''%D0%BE%D1%82%D1%87%D1%91%D1%82.pdf
