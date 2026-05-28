<?php
header("Content-Type: application/json");
require_once "../../config/db.php";
require_once "../auth/auth.middleware.php";

$user = authenticate();
$place_id = 14;

$stmt = $conn->prepare("SELECT * FROM favorites WHERE user_id = ? AND place_id = ?");
$stmt->execute([$user['id'], $place_id]);
$result = $stmt->fetch();

echo json_encode([
    "user_id" => $user['id'],
    "place_id" => $place_id,
    "found" => $result ? true : false,
    "data" => $result
]);
?>