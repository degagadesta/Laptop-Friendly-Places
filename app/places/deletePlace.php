<?php
header("Content-Type: application/json");

require_once "../../config/db.php";
require_once "../auth/auth.middleware.php";

$user = authenticate(); // 🔐

$id = $_POST['id'] ?? null;

if (!$id) {
    echo json_encode(["error" => "Place ID required"]);
    exit;
}

/* Check ownership */
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

/* Delete */
$stmt = $conn->prepare("DELETE FROM places WHERE id = ?");
$stmt->execute([$id]);

echo json_encode(["message" => "Place deleted successfully"]);
?>