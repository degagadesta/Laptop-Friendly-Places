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

$email = trim($data['email'] ?? '');
$password = $data['password'] ?? '';

if (!$email || !$password) {
    echo json_encode(["error" => "Email and password required"]);
    exit;
}

/* Find user */
$stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
$stmt->execute([$email]);

$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user || !password_verify($password, $user['password'])) {
    http_response_code(401);
    echo json_encode(["error" => "Invalid credentials"]);
    exit;
}

if ($user['is_blocked']) {
    http_response_code(403);
    echo json_encode(["error" => "Account is blocked"]);
    exit;
}

/* Create JWT */
$payload = [
    "id" => $user['id'],
    "email" => $user['email'],
    "role" => $user['role'] ?? 'user',
    "exp" => time() + (60 * 60) // 1 hour
];

$token = generateJWT($payload);

echo json_encode([
    "message" => "Login successful",
    "token" => $token,
    "user" => [
        "id" => $user['id'],
        "name" => $user['name'],
        "email" => $user['email'],
        "role" => $user['role'] ?? 'user'
    ]
]);
?>