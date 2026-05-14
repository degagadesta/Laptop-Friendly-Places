<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once "../../config/db.php";
require_once "mailer.php";

$data = json_decode(file_get_contents("php://input"), true);
$email = trim(filter_var($data['email'] ?? '', FILTER_SANITIZE_EMAIL));

if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(["error" => "Valid email required"]);
    exit;
}

$stmt = $conn->prepare("SELECT id, name, email_verified FROM users WHERE email = ?");
$stmt->execute([$email]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

// Always return same message to avoid email enumeration
if (!$user || $user['email_verified']) {
    echo json_encode(["message" => "If your email is registered and unverified, a new link has been sent."]);
    exit;
}

$verificationToken = bin2hex(random_bytes(32));
$tokenExpiry = date('Y-m-d H:i:s', strtotime('+24 hours'));

$stmt = $conn->prepare("
    UPDATE users SET verification_token = ?, verification_token_expiry = ? WHERE id = ?
");
$stmt->execute([$verificationToken, $tokenExpiry, $user['id']]);

sendVerificationEmail($email, $user['name'], $verificationToken);

echo json_encode(["message" => "If your email is registered and unverified, a new link has been sent."]);
?>
