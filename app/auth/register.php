<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

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

$userId = $conn->lastInsertId();

/* Create JWT for auto-login */
$payload = [
    "id" => $userId,
    "email" => $email,
    "role" => 'user',
    "exp" => time() + (60 * 60) // 1 hour
];

$token = generateJWT($payload);

echo json_encode([
    "message" => "User registered successfully",
    "token" => $token,
    "user" => [
        "id" => $userId,
        "name" => $name,
        "email" => $email,
        "role" => 'user'
    ]
]);
?>