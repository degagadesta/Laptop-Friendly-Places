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

$name = trim(strip_tags($data['name'] ?? ''));
$email = trim(filter_var($data['email'] ?? '', FILTER_SANITIZE_EMAIL));
$password = $data['password'] ?? '';

// Validate required fields
if (!$name || !$email || !$password) {
    echo json_encode(["error" => "All fields required"]);
    exit;
}

// Validate name length
if (strlen($name) < 2 || strlen($name) > 100) {
    echo json_encode(["error" => "Name must be between 2 and 100 characters"]);
    exit;
}

// Validate email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(["error" => "Invalid email format"]);
    exit;
}

// Validate password strength: min 8 chars, at least one uppercase, one lowercase, one digit
if (strlen($password) < 8) {
    echo json_encode(["error" => "Password must be at least 8 characters"]);
    exit;
}
if (!preg_match('/[A-Z]/', $password)) {
    echo json_encode(["error" => "Password must contain at least one uppercase letter"]);
    exit;
}
if (!preg_match('/[a-z]/', $password)) {
    echo json_encode(["error" => "Password must contain at least one lowercase letter"]);
    exit;
}
if (!preg_match('/[0-9]/', $password)) {
    echo json_encode(["error" => "Password must contain at least one number"]);
    exit;
}

/* Check if user exists */
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->execute([$email]);

if ($stmt->fetch()) {
    echo json_encode(["error" => "User already exists"]);
    exit;
}

/* Hash password with bcrypt and high cost factor */
$hashedPassword = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

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