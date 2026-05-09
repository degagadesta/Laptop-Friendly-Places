<?php
require_once("../../config/database.php");
require_once("jwt.php");

$data = json_decode(file_get_contents("php://input"));

$email = $conn->real_escape_string($data->email);
$password = $data->password;

$sql = "SELECT * FROM users WHERE email='$email'";
$result = $conn->query($sql);

if ($result->num_rows === 0) {
    echo json_encode(["error" => "User not found"]);
    exit;
}

$user = $result->fetch_assoc();

if (!password_verify($password, $user["password"])) {
    echo json_encode(["error" => "Wrong password"]);
    exit;
}

$token = generateJWT($user);

echo json_encode([
    "message" => "Login success",
    "token" => $token
]);