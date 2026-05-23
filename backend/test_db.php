<?php
require_once 'config/db.php';

echo "Testing database connection...\n\n";

try {
    // Test connection
    echo "✓ Database connection successful!\n\n";
    
    // Check if users table exists
    $stmt = $conn->query("SHOW TABLES LIKE 'users'");
    $tableExists = $stmt->rowCount() > 0;
    
    if ($tableExists) {
        echo "✓ Users table exists\n\n";
        
        // Show table structure
        echo "Users table structure:\n";
        $stmt = $conn->query("DESCRIBE users");
        $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        foreach ($columns as $column) {
            echo "  - {$column['Field']} ({$column['Type']})\n";
        }
        
        // Count users
        $stmt = $conn->query("SELECT COUNT(*) as count FROM users");
        $count = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
        echo "\nTotal users: {$count}\n";
        
    } else {
        echo "✗ Users table does not exist\n";
        echo "\nWould you like to create it? Run: php create_users_table.php\n";
    }
    
    // Show all tables
    echo "\n\nAll tables in 'lfp' database:\n";
    $stmt = $conn->query("SHOW TABLES");
    $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
    
    if (empty($tables)) {
        echo "  No tables found\n";
    } else {
        foreach ($tables as $table) {
            echo "  - {$table}\n";
        }
    }
    
} catch (PDOException $e) {
    echo "✗ Error: " . $e->getMessage() . "\n";
}
?>
