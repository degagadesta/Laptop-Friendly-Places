<?php
header("Content-Type: application/json");

require_once "../../config/db.php";

$id = $_GET['id'] ?? null;

if (!$id) {
    echo json_encode(["error" => "Place ID required"]);
    exit;
}

$stmt = $conn->prepare("SELECT * FROM places WHERE id = ?");
$stmt->execute([$id]);

$place = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$place) {
    echo json_encode(["error" => "Place not found"]);
    exit;
}

echo json_encode($place);
?>