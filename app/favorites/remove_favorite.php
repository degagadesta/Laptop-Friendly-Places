<?php
header("Content-Type: application/json");

require_once "../../config/db.php";
require_once "../auth/auth.middleware.php";

$user = authenticate(); // 🔐

$data = json_decode(file_get_contents("php://input"), true);
$place_id = $data['place_id'] ?? null;

if (!$place_id) {
    echo json_encode([
        "success" => false,
        "message" => "place_id is required"
    ]);
    exit;
}

try {
    $stmt = $conn->prepare("
        DELETE FROM favorites
        WHERE user_id = :user_id AND place_id = :place_id
    ");

    $stmt->execute([
        ':user_id' => $user['user_id'],
        ':place_id' => $place_id
    ]);

    echo json_encode([
        "success" => true,
        "message" => "Removed from favorites"
    ]);

} catch (PDOException $e) {
    echo json_encode([
        "success" => false,
        "message" => "Database error"
    ]);
}