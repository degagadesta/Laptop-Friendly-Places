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
    //  Check if place exists
    $stmt = $conn->prepare("SELECT id FROM places WHERE id = :id");
    $stmt->bindParam(':id', $place_id);
    $stmt->execute();

    if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
        echo json_encode([
            "success" => false,
            "message" => "Place not found"
        ]);
        exit;
    }

    //  Check duplicate
    $stmt = $conn->prepare("SELECT id FROM favorites WHERE user_id = :user_id AND place_id = :place_id");
    $stmt->execute([
        ':user_id' => $user['user_id'],
        ':place_id' => $place_id
    ]);

    if ($stmt->fetch()) {
        echo json_encode([
            "success" => false,
            "message" => "Already in favorites"
        ]);
        exit;
    }

    //  Insert
    $stmt = $conn->prepare("
        INSERT INTO favorites (user_id, place_id)
        VALUES (:user_id, :place_id)
    ");

    $stmt->execute([
        ':user_id' => $user['user_id'],
        ':place_id' => $place_id
    ]);

    echo json_encode([
        "success" => true,
        "message" => "Added to favorites"
    ]);

} catch (PDOException $e) {
    echo json_encode([
        "success" => false,
        "message" => "Database error"
    ]);
}