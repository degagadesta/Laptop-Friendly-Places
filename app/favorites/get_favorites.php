<?php
require_once "db.php";

$db = new Database();
$conn = $db->connect();

$user_id = $_GET['user_id'] ?? null;

if (!$user_id) {
    echo json_encode(["error" => "User ID required"]);
    exit;
}

$query = "SELECT * FROM favorites WHERE user_id = :user_id";
$stmt = $conn->prepare($query);

$stmt->bindParam(":user_id", $user_id);
$stmt->execute();

$favorites = $stmt->fetchAll(PDO::FETCH_ASSOC);

echo json_encode($favorites);
?>