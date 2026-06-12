<?php
use Hardened\ConstantTime;

$expected = hash_hmac('sha256', 'payload', 'secret-key');
$received = hash_hmac('sha256', 'payload', 'secret-key');

var_dump(ConstantTime::equals($expected, $received));
// bool(true)
var_dump(ConstantTime::equals($expected, 'forged'));
// bool(false)

var_dump(ConstantTime::equalsHex('DEADBEEF', 'deadbeef'));
// bool(true) — compares decoded bytes, case-insensitive
var_dump(ConstantTime::equalsHex($expected, strtoupper($received)));
// bool(true)

var_dump(ConstantTime::equalsBase64(base64_encode('token'), base64_encode('token')));
// bool(true)
var_dump(ConstantTime::equalsBase64(base64_encode('token'), base64_encode('other')));
// bool(false)

try {
    ConstantTime::equalsHex('not-hex', 'deadbeef');
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(1900)
}
