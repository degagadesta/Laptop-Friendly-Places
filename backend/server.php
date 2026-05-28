<?php
// Simple router for PHP built-in server

// Get the requested URI first
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Always set CORS headers for every request
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Max-Age: 3600");

// Handle OPTIONS preflight - must exit immediately
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit(0);
}

// If it's a static file that exists, serve it
if ($uri !== '/' && file_exists(__DIR__ . $uri)) {
    return false; // Let PHP serve the file
}

// Otherwise, route through index.php
require __DIR__ . '/index.php';
