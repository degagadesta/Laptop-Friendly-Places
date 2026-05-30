<?php
require_once __DIR__ . '/../config/env.php';

$host = $_ENV['DB_HOST'] ?? 'localhost';
$db   = $_ENV['DB_NAME'] ?? 'lfp';
$user = $_ENV['DB_USER'] ?? 'root';
$pass = $_ENV['DB_PASS'] ?? '';

try {
    $conn = new PDO("mysql:host=$host;dbname=$db;charset=utf8mb4", $user, $pass);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    // Avoid privileged GLOBAL settings during app bootstrap.
    // This can fail on many local MySQL setups even when the DB connection itself is valid.
    try {
        $conn->exec("SET NAMES utf8mb4");
    } catch (Throwable $e) {
        error_log("Optional DB init warning: " . $e->getMessage());
    }
} catch (PDOException $e) {
    http_response_code(500);
    error_log("DB Connection failed: " . $e->getMessage());
    echo json_encode([
        "error" => "DB Connection failed",
        "details" => $e->getMessage()
    ]);
    exit;
}
?>
