<?php
require_once("../../config/database.php");
require_once("../auth/auth.middleware.php");

$data = json_decode(file_get_contents("php://input"));

$user_id = $user["id"];
$place_id = $data->place_id;

$sql = "INSERT INTO favorites (user_id, place_id)
        VALUES ('$user_id', '$place_id')";

$conn->query($sql);

echo json_encode(["message" => "Added"]);