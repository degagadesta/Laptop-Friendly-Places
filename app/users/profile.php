<?php
header("Content-Type: application/json");

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
    echo json_encode(["error" => "Invalid credentials"]);
    exit;
}

$payload = [
    "user_id" => $user['id'],
    "email" => $user['email'],
];

$token = generateJWT($payload);

echo json_encode([
    "message" => "Login successful",
    "token" => $token
]);
?>
