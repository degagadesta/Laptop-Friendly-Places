<?php
require_once 'config/db.php';

echo "Updating users table with missing columns...\n\n";

try {
    // Add missing columns for auth system
    $updates = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user' AFTER password",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_blocked TINYINT(1) DEFAULT 0 AFTER role",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(255) NULL AFTER is_blocked",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expiry DATETIME NULL AFTER reset_token",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified TINYINT(1) DEFAULT 0 AFTER reset_token_expiry",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_token VARCHAR(255) NULL AFTER email_verified",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP AFTER email_verification_token",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER created_at"
    ];
    
    foreach ($updates as $sql) {
        try {
            $conn->exec($sql);
            echo "✓ Executed: " . substr($sql, 0, 60) . "...\n";
        } catch (PDOException $e) {
            // Column might already exist, check if it's a duplicate column error
            if (strpos($e->getMessage(), 'Duplicate column') !== false) {
                echo "- Column already exists, skipping...\n";
            } else {
                echo "✗ Error: " . $e->getMessage() . "\n";
            }
        }
    }
    
    echo "\n✓ Users table updated successfully!\n\n";
    
    // Show updated structure
    echo "Updated users table structure:\n";
    $stmt = $conn->query("DESCRIBE users");
    $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    foreach ($columns as $column) {
        echo "  - {$column['Field']} ({$column['Type']}) {$column['Null']} {$column['Default']}\n";
    }
    
} catch (PDOException $e) {
    echo "✗ Error: " . $e->getMessage() . "\n";
}
?>
