<?php
header("Content-Type: application/json");

require_once "../../config/db.php";
require_once "../auth/auth.middleware.php";

$user = authenticate(); // 🔐

$id = $_POST['id'] ?? null;

$name = $_POST['name'] ?? '';
$description = $_POST['description'] ?? '';
$location = $_POST['location'] ?? '';

if (!$id) {
    echo json_encode(["error" => "Place ID required"]);
    exit;
}

/* Optional: Check if user owns the place */
$stmt = $conn->prepare("SELECT created_by FROM places WHERE id = ?");
$stmt->execute([$id]);

$place = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$place) {
    echo json_encode(["error" => "Place not found"]);
    exit;
}

if ($place['created_by'] != $user['user_id']) {
    echo json_encode(["error" => "Unauthorized"]);
    exit;
}

/* Update */
$stmt = $conn->prepare("
    UPDATE places 
    SET name = ?, description = ?, location = ?
    WHERE id = ?
");

$stmt->execute([$name, $description, $location, $id]);

echo json_encode(["message" => "Place updated successfully"]);
?>