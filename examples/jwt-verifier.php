<?php
use Hardened\JwtVerifier;

function b64url(string $s): string {
    return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
}
function makeJwt(array $header, array $payload, string $secret): string {
    $signingInput = b64url(json_encode($header)) . '.' . b64url(json_encode($payload));
    return $signingInput . '.' . b64url(hash_hmac('sha256', $signingInput, $secret, true));
}

$secret = "shared-secret-at-least-32-bytes!";
$jwt = makeJwt(
    ['alg' => 'HS256', 'typ' => 'JWT'],
    ['exp' => time() + 600, 'iss' => 'https://idp.example', 'aud' => 'api', 'sub' => 'user-1'],
    $secret,
);

$verifier = JwtVerifier::forHmac($secret);          // allowlist defaults to ["HS256"]
$verifier->requireIssuer(['https://idp.example']);
$verifier->requireAudience(['api']);

$claims = $verifier->verify($jwt);
var_dump($claims['sub']);
// string(6) "user-1"

// alg=none is always rejected
$none = makeJwt(['alg' => 'none', 'typ' => 'JWT'], ['exp' => time() + 600], '');
try {
    $verifier->verify($none);
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(2502)
}

// Tampered payload: signature no longer matches
[$h, , $s] = explode('.', $jwt);
try {
    $verifier->verify("$h." . b64url(json_encode(['exp' => time() + 600, 'sub' => 'admin'])) . ".$s");
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(2502)
}

// Expired tokens are rejected — exp is mandatory and validated
try {
    $verifier->verify(makeJwt(['alg' => 'HS256'], ['exp' => time() - 3600], $secret));
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(2502)
}

// HS/RS confusion is unrepresentable: an HMAC verifier refuses RSA algorithms
try {
    JwtVerifier::forHmac($secret, ['RS256']);
} catch (Exception $e) {
    var_dump($e->getCode());
    // int(2501)
}
