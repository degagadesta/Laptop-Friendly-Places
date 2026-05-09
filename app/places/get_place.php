<?php
require_once("../../config/database.php");

$sql = "SELECT * FROM places WHERE approved = 1";
$result = $conn->query($sql);

$places = [];

while ($row = $result->fetch_assoc()) {
    $places[] = $row;
}

echo json_encode($places);