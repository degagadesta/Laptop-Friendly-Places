<?php
header("Content-Type: application/json");

require_once "../../config/db.php";
require_once "../auth/auth.middleware.php";

$user = authenticate();

try {
    // Debug: Show what user_id we're using
    error_log("Looking for user_id: " . $user['id']);
    
    $stmt = $conn->prepare("
        SELECT p.*, f.user_id as favorite_user_id
        FROM favorites f
        JOIN places p ON f.place_id = p.id
        WHERE f.user_id = ?
    ");
    
    $stmt->execute([$user['id']]);
    
    $places = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo json_encode([
        "success" => true,
        "count" => count($places),
        "debug_user_id" => $user['id'],
        "data" => $places
    ]);
    
} catch (PDOException $e) {
    echo json_encode([
        "success" => false,
        "message" => "Database error: " . $e->getMessage()
    ]);
}
?>
