<?php
header('Content-Type: application/json');

// Your database configuration (adjust as needed)
$host = 'localhost';
$dbname = 'your_database_name'; // Change this
$username = 'root'; // Change this
$password = ''; // Change this

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Check if tables exist
    $tables = ['favorites', 'places', 'users'];
    $results = [];
    
    foreach($tables as $table) {
        $stmt = $pdo->query("SHOW TABLES LIKE '$table'");
        $results[$table] = $stmt->rowCount() > 0;
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Database connected successfully',
        'tables' => $results
    ]);
    
} catch(PDOException $e) {
    echo json_encode([
        'success' => false,
        'message' => 'Connection failed: ' . $e->getMessage()
    ]);
}
?>