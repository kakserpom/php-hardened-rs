<?php

use Hardened\Sanitizers\SvgSanitizer;

echo "=== SVG Sanitizer Examples (Ammonia-based) ===\n\n";

// Basic sanitization with default settings
echo "1. Basic sanitization:\n";
$sanitizer = new SvgSanitizer();
$dirty = '<svg><script>alert("XSS")</script><rect width="100" height="100" fill="red"/></svg>';
$clean = $sanitizer->clean($dirty);
echo "   Input:  $dirty\n";
echo "   Output: $clean\n\n";

// Removing event handlers
echo "2. Event handler removal:\n";
$dirty = '<svg><rect onclick="alert(1)" onmouseover="hack()" width="100" height="100"/></svg>';
$clean = $sanitizer->clean($dirty);
echo "   Input:  $dirty\n";
echo "   Output: $clean\n\n";

// foreignObject removal (can contain HTML)
echo "3. foreignObject removal:\n";
$dirty = '<svg><foreignObject><div xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></div></foreignObject><rect/></svg>';
$clean = $sanitizer->clean($dirty);
echo "   Input:  " . substr($dirty, 0, 60) . "...\n";
echo "   Output: $clean\n\n";

// SVG bomb detection
echo "4. SVG bomb detection:\n";
try {
    // This would throw if the dimensions are too large
    $largeSvg = '<svg viewBox="0 0 100000 100000"></svg>';
    $sanitizer->clean($largeSvg);
    echo "   ERROR: Should have thrown!\n";
} catch (Exception $e) {
    echo "   Caught: " . $e->getMessage() . "\n\n";
}

// Check if SVG is safe
echo "5. Safety check (isSafe):\n";
$safe = '<svg><rect width="100" height="100"/></svg>';
$unsafe = '<svg viewBox="0 0 100000 100000"></svg>';
echo "   Safe SVG: " . ($sanitizer->isSafe($safe) ? "true" : "false") . "\n";
echo "   Unsafe SVG: " . ($sanitizer->isSafe($unsafe) ? "true" : "false") . "\n\n";

// Builder pattern for custom configuration
echo "6. Custom configuration with builder:\n";
$customSanitizer = (new SvgSanitizer())
    ->setMaxDimension(5000)
    ->blockExternalReferences(true)
    ->stripComments(true);
$svg = '<svg><!-- comment --><rect width="100" height="100"/></svg>';
$clean = $customSanitizer->clean($svg);
echo "   Input:  $svg\n";
echo "   Output: $clean\n\n";

// Using presets
echo "7. Using presets:\n";
$strictSanitizer = SvgSanitizer::withPreset(SvgSanitizer::PRESET_STRICT);
$standardSanitizer = SvgSanitizer::withPreset(SvgSanitizer::PRESET_STANDARD);
echo "    Strict preset: allows minimal elements (svg, g, path, rect, etc.)\n";
echo "    Standard preset: allows common elements + gradients + filters\n";
echo "    Permissive preset: allows fonts and links too\n\n";

// Static defuse method
echo "8. Static defuse method:\n";
echo "    SvgSanitizer::defuse('/path/to/file.svg');\n";
echo "    Throws exception if SVG has dangerous dimensions\n\n";

// Allow relative URLs
echo "9. Allowing relative URLs:\n";
$permissiveSanitizer = (new SvgSanitizer())
    ->allowRelativeUrls(true)
    ->blockExternalReferences(false);
echo "    Use allowRelativeUrls(true) for internal SVGs\n\n";

echo "=== All examples completed ===\n";
