<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use FFIMe\FFIMe;

$header  = __DIR__ . '/../target/x86_64-unknown-linux-gnu/release/cidrscan.h';
$library = __DIR__ . '/../target/x86_64-unknown-linux-gnu/release/libcidrscan.so';
$outputDir = __DIR__ . '/php';

// Ensure output directory exists
if (!is_dir($outputDir)) {
    mkdir($outputDir, 0755, true);
}

// Generate the PHP wrapper class
$ffi = new FFIMe($library);
$ffi->include($header);
$ffi->codeGen('Citadel\\FFI\\Library', $outputDir . '/CidrScan.php');

echo "✅ Generated PHP FFI wrappers in {$outputDir}\n";
