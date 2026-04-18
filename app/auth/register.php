<?php
header("Content-Type: application/json");

require_once "../../config/db.php";
require_once "jwt.php";

$data = json_decode(file_get_contents("php://input"), true);

$name = trim($data['name'] ?? '');
$email = trim($data['email'] ?? '');
$password = $data['password'] ?? '';

if (!$name || !$email || !$password) {
    echo json_encode(["error" => "All fields required"]);
    exit;
}

/* Check if user exists */
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->execute([$email]);

if ($stmt->fetch()) {
    echo json_encode(["error" => "User already exists"]);
    exit;
}

/* Hash password */
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

/* Insert user */
$stmt = $conn->prepare("
    INSERT INTO users (name, email, password)
    VALUES (?, ?, ?)
");

$stmt->execute([$name, $email, $hashedPassword]);

echo json_encode(["message" => "User registered successfully"])
?>