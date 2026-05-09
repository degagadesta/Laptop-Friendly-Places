<?php
require_once("../../config/database.php");

$data = json_decode(file_get_contents("php://input"));

$username = $conn->real_escape_string($data->username);
$email = $conn->real_escape_string($data->email);
$password = password_hash($data->password, PASSWORD_DEFAULT);

$sql = "INSERT INTO users (username, email, password)
        VALUES ('$username', '$email', '$password')";

if ($conn->query($sql)) {
    echo json_encode(["message" => "User registered"]);
} else {
    echo json_encode(["error" => "Registration failed"]);
}