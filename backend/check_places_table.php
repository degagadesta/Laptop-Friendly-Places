<?php
require_once 'config/db.php';

echo "Places table structure:\n\n";

$stmt = $conn->query("DESCRIBE places");
$columns = $stmt->fetchAll(PDO::FETCH_ASSOC);

foreach ($columns as $column) {
    echo "- {$column['Field']} ({$column['Type']})\n";
}

echo "\n\nTotal places: ";
$stmt = $conn->query("SELECT COUNT(*) as count FROM places");
echo $stmt->fetch(PDO::FETCH_ASSOC)['count'];
echo "\n";
?>
