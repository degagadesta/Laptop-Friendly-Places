<?php
header("Content-Type: application/json");

require_once "../../config/db.php";

$stmt = $conn->prepare("SELECT * FROM places ORDER BY id DESC");
$stmt->execute();

$places = $stmt->fetchAll(PDO::FETCH_ASSOC);

echo json_encode($places);
?>