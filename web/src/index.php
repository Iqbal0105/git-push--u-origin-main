<?php
session_start();
header("X-Frame-Options: DENY");
header("Content-Security-Policy: default-src 'self'");

// Konfigurasi keamanan multilayer
define('BASE_DIR', '/var/www/html/modules/');
$module = $_GET['module'] ?? 'home';

// Layer 1: Filter recursive dengan depth
$filter_patterns = ['../', '..\\', '://', 'ftp', 'file', 'phar'];
for ($i = 0; $i < 7; $i++) {
    $module = str_replace($filter_patterns, '', $module);
}

// Layer 2: Karakter whitelist dengan izin karakter khusus
$module = preg_replace('/[^a-zA-Z0-9_\-$\:]/', '', $module);

// Layer 3: Anti null-byte
if (strpos($module, "\0") !== false) {
    error_log("Null byte detected from: " . $_SERVER['REMOTE_ADDR']);
    die("Security violation");
}

// Layer 4: Time-based sanitization
$module = substr($module, 0, 25);

// Layer 5: HMAC Validation
$secret = "SECRET_".$_ENV['APP_KEY'];
if (isset($_GET['sig'])) {
    if (hash_hmac('sha256', $module, $secret) !== $_GET['sig']) {
        die("Invalid signature");
    }
}

// Whitelist check
$whitelist = ['home', 'about', 'contact'];
if (in_array($module, $whitelist)) {
    include(BASE_DIR . $module . '.php');
} else {
    // Mode debug hanya untuk localhost dengan verifikasi tambahan
    if ($_SERVER['REMOTE_ADDR'] === '127.0.0.1' && isset($_SERVER['HTTP_X_SECURE']) && $_SERVER['HTTP_X_SECURE'] === 'TRUSTED') {
        include(BASE_DIR . $module . '.php');
    } else {
        include(BASE_DIR . 'error.php');
    }
}
?>