<?php
/**
 * Migration: add email verification columns to users table
 * Run once: php db_email_verification_migration.php
 */
require_once "config/db.php";

$queries = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified TINYINT(1) NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token VARCHAR(64) NULL",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token_expiry DATETIME NULL",
];

foreach ($queries as $sql) {
    try {
        $conn->exec($sql);
        echo "OK: $sql\n";
    } catch (PDOException $e) {
        echo "Error: " . $e->getMessage() . "\n";
    }
}

echo "Migration complete.\n";
?>
