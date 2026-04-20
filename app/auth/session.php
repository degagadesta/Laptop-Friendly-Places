<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once "../../config/db.php";
require_once "./jwt.php";
require_once "./auth.middleware.php";

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

// Refresh Token
if ($method === 'POST' && $action === 'refresh') {
    $data = json_decode(file_get_contents("php://input"), true);
    $token = $data['token'] ?? '';

    if (!$token) {
        echo json_encode(["error" => "Token required"]);
        exit;
    }

    $user = verifyJWT($token);

    if (!$user) {
        echo json_encode(["error" => "Invalid or expired token"]);
        exit;
    }

    $stmt = $conn->prepare("SELECT id, email, name, is_blocked, role FROM users WHERE id = ?");
    $stmt->execute([$user['id']]);
    $userData = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$userData || $userData['is_blocked']) {
        echo json_encode(["error" => "User not found or blocked"]);
        exit;
    }

    $newToken = generateJWT([
        "id" => $userData['id'],
        "email" => $userData['email'],
        "role" => $userData['role'] ?? 'user'
    ]);

    echo json_encode([
        "message" => "Token refreshed successfully",
        "token" => $newToken
    ]);
    exit;
}

// Logout
if ($method === 'POST' && $action === 'logout') {
    $user = authenticate();

    echo json_encode([
        "message" => "Logged out successfully"
    ]);
    exit;
}

// Verify Email
if ($method === 'POST' && $action === 'verify-email') {
    $data = json_decode(file_get_contents("php://input"), true);
    $token = $data['token'] ?? '';

    if (!$token) {
        echo json_encode(["error" => "Verification token required"]);
        exit;
    }

    $stmt = $conn->prepare("SELECT id FROM users WHERE email_verification_token = ?");
    $stmt->execute([$token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        echo json_encode(["error" => "Invalid verification token"]);
        exit;
    }

    $stmt = $conn->prepare("UPDATE users SET email_verified = 1, email_verification_token = NULL WHERE id = ?");
    $stmt->execute([$user['id']]);

    echo json_encode(["message" => "Email verified successfully"]);
    exit;
}

echo json_encode(["error" => "Invalid request"]);
?>
