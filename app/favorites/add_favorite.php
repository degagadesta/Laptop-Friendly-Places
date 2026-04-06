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

try {
    $query = "INSERT INTO favorites (user_id, item_id) VALUES (:user_id, :item_id)";
    $stmt = $conn->prepare($query);

    $stmt->bindParam(":user_id", $user_id);
    $stmt->bindParam(":item_id", $item_id);

    $stmt->execute();

    echo json_encode(["message" => "Added to favorites"]);

} catch (PDOException $e) {
    echo json_encode(["error" => "Already exists or failed"]);
}
?>