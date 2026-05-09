<?php
require_once("../../config/database.php");
require_once("../auth/auth.middleware.php");

$data = json_decode(file_get_contents("php://input"));

$name = $conn->real_escape_string($data->name);
$desc = $conn->real_escape_string($data->description);
$location = $conn->real_escape_string($data->location);

$user_id = $user["id"];

$sql = "INSERT INTO places (name, description, location, created_by)
        VALUES ('$name', '$desc', '$location', '$user_id')";

if ($conn->query($sql)) {
    echo json_encode(["message" => "Place submitted"]);
} else {
    echo json_encode(["error" => "Failed"]);
}