<?php
declare(strict_types=1);

use Hardened\CsrfProtection;

//
// 1) Initialization
//
$key = 'YOUR_BASE64URL_32_BYTE_KEY_HERE';  // must decode to 32 bytes
$ttl = 3600;                              // token lifetime in seconds

// If you have a previous token (for rotation), pass it as third argument:
// $previous = $_COOKIE['csrf'] ?? null;
// $csrf = new CsrfProtection($key, $ttl, $previous);

$csrf = new CsrfProtection($key, $ttl);

//
// 2) Send the cookie to the client
//
$csrf->setCookie(
    /* expires: */ time() + $ttl,
    /* path:    */ '/',
    /* domain:  */ '',      // default: current host
    /* secure:  */ true,    // only over HTTPS
    /* httponly:*/ true     // inaccessible to JavaScript
);

//
// 3) Embed the CSRF token in your form or AJAX request
//
$token = $csrf->token();  // Base64URL-encoded token string

?>
<!doctype html>
<html>
  <body>
    <form method="POST" action="submit.php">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($token, \ENT_QUOTES) ?>">
      <!-- other form fields… -->
      <button type="submit">Submit Securely</button>
    </form>
  </body>
</html>
<?php

//
// 4) On form submission (submit.php):
//
try {
    // Reconstruct with same key/ttl and pass previous cookie if rotating:
    $csrf = new CsrfProtection($key, $ttl, $_COOKIE['csrf'] ?? null);

    // Verify the token against the cookie
    $csrf->verifyToken(
        /* token value from form: */ $_POST['csrf_token'] ?? '',
        /* cookie value: */         $_COOKIE['csrf']     ?? null
    );

    // If we get here, CSRF check passed
    echo "CSRF validated — proceed with action.";
} catch (\Exception $e) {
    // Invalid or expired token
    http_response_code(403);
    echo "CSRF validation failed: " . htmlspecialchars($e->getMessage());
}
