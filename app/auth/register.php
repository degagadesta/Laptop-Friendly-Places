<?php
header("Content-Type: application/json");

require_once "../../config/db.php";

$data = json_decode(file_get_contents("php://input"), true);

$name = trim($data['name'] ?? '');
$email = trim($data['email'] ?? '');
$password = $data['password'] ?? '';

if (!$name || !$email || !$password) {
    echo json_encode(["error" => "All fields required"]);
    exit;
}

// Validate email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(["error" => "Invalid email format"]);
    exit;
}

// Validate password strength
if (strlen($password) < 6) {
    echo json_encode(["error" => "Password must be at least 6 characters"]);
    exit;
}

// check existing email
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
$stmt->execute([$email]);

if ($stmt->fetch()) {
    echo json_encode(["error" => "Email already exists"]);
    exit;
}

// hash password
$hashedPassword = password_hash($password, PASSWORD_BCRYPT);

// Generate email verification token
$verificationToken = bin2hex(random_bytes(32));

// insert user
$stmt = $conn->prepare("INSERT INTO users (name, email, password, email_verification_token, email_verified) VALUES (?, ?, ?, ?, 0)");
$stmt->execute([$name, $email, $hashedPassword, $verificationToken]);

// TODO: Send verification email
// For now, return token (in production, send via email)

echo json_encode([
    "message" => "User registered successfully. Please verify your email.",
    "verification_token" => $verificationToken // Remove this in production
]);
?>