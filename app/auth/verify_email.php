<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once "../../config/db.php";

$token = trim($_GET['token'] ?? '');

if (!$token) {
    http_response_code(400);
    echo json_encode(["error" => "Verification token required"]);
    exit;
}

// Find user with this token that hasn't expired
$stmt = $conn->prepare("
    SELECT id, email_verified
    FROM users
    WHERE verification_token = ? AND verification_token_expiry > NOW()
");
$stmt->execute([$token]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid or expired verification token"]);
    exit;
}

if ($user['email_verified']) {
    echo json_encode(["message" => "Email already verified. You can log in."]);
    exit;
}

// Mark as verified and clear token
$stmt = $conn->prepare("
    UPDATE users
    SET email_verified = 1, verification_token = NULL, verification_token_expiry = NULL
    WHERE id = ?
");
$stmt->execute([$user['id']]);

echo json_encode(["message" => "Email verified successfully. You can now log in."]);
?>
