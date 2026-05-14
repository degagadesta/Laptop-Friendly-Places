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
require_once "mailer.php";

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

/* Generate email verification token */
$verificationToken = bin2hex(random_bytes(32));
$tokenExpiry = date('Y-m-d H:i:s', strtotime('+24 hours'));

/* Insert user as unverified */
$stmt = $conn->prepare("
    INSERT INTO users (name, email, password, email_verified, verification_token, verification_token_expiry)
    VALUES (?, ?, ?, 0, ?, ?)
");
$stmt->execute([$name, $email, $hashedPassword, $verificationToken, $tokenExpiry]);

$userId = $conn->lastInsertId();

/* Send verification email */
$emailSent = sendVerificationEmail($email, $name, $verificationToken);

if (!$emailSent) {
    // Still registered but warn about email failure
    echo json_encode([
        "message" => "Account created but verification email could not be sent. Contact support.",
        "user" => ["id" => $userId, "name" => $name, "email" => $email]
    ]);
    exit;
}

echo json_encode([
    "message" => "Registration successful. Please check your email to verify your account before logging in.",
    "user" => ["id" => $userId, "name" => $name, "email" => $email]
]);
?>