<?php
require_once "db.php";

$db = new Database();
$conn = $db->connect();

$data = json_decode(file_get_contents("php://input"), true);

$user_id = $data['user_id'] ?? null;
$item_id = $data['item_id'] ?? null;

if (!$user_id || !$item_id) {
    echo json_encode(["error" => "Missing data"]);
    exit;
}


$query = "DELETE FROM favorites WHERE user_id = :user_id AND item_id = :item_id";
$stmt = $conn->prepare($query);

$stmt->bindParam(":user_id", $user_id);
$stmt->bindParam(":item_id", $item_id);

if ($stmt->execute()) {
    echo json_encode(["message" => "Removed from favorites"]);
} else {
    echo json_encode(["error" => "Failed to remove"]);
}
?>