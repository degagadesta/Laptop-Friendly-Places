<?php
require_once("../../config/database.php");
require_once("../auth/auth.middleware.php");

$user_id = $user["id"];

$sql = "SELECT p.* FROM places p
        JOIN favorites f ON p.id = f.place_id
        WHERE f.user_id = '$user_id'";

$result = $conn->query($sql);

$data = [];

while ($row = $result->fetch_assoc()) {
    $data[] = $row;
}

echo json_encode($data);