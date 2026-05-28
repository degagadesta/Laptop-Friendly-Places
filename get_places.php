<?php
header("Content-Type: application/json");

require_once "config/database.php";

$sql = "SELECT * FROM places";
$result = $conn->query($sql);

$places = [];

while ($row = $result->fetch_assoc()) {
    $places[] = $row;
}

echo json_encode([
    "success" => true,
    "count" => count($places),
    "data" => $places
]);