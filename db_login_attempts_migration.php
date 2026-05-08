<?php
/**
 * Migration: create login_attempts table for rate limiting
 * Run once: php db_login_attempts_migration.php
 */
require_once "config/db.php";

$sql = "
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    email VARCHAR(255) NOT NULL,
    success TINYINT(1) NOT NULL DEFAULT 0,
    attempted_at DATETIME NOT NULL,
    INDEX idx_ip_attempted (ip_address, attempted_at),
    INDEX idx_email_attempted (email, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
";

try {
    $conn->exec($sql);
    echo "login_attempts table created successfully.\n";
} catch (PDOException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>
