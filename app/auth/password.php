<?php
header("Content-Type: application/json");

require_once "../../config/db.php";
require_once "./auth.middleware.php";

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

// Forgot Password - Request reset token
if ($method === 'POST' && $action === 'forgot') {
    $data = json_decode(file_get_contents("php://input"), true);
    $email = trim($data['email'] ?? '');

    if (!$email) {
        echo json_encode(["error" => "Email required"]);
        exit;
    }

    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        echo json_encode(["message" => "If email exists, reset link will be sent"]);
        exit;
    }

    $resetToken = bin2hex(random_bytes(32));
    $expiry = date('Y-m-d H:i:s', strtotime('+1 hour'));

    $stmt = $conn->prepare("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?");
    $stmt->execute([$resetToken, $expiry, $user['id']]);

    echo json_encode([
        "message" => "If email exists, reset link will be sent",
        "reset_token" => $resetToken // Remove in production
    ]);
    exit;
}

// Reset Password - Use token to set new password
if ($method === 'POST' && $action === 'reset') {
    $data = json_decode(file_get_contents("php://input"), true);
    $token = $data['token'] ?? '';
    $newPassword = $data['password'] ?? '';

    if (!$token || !$newPassword) {
        echo json_encode(["error" => "Token and new password required"]);
        exit;
    }

    if (strlen($newPassword) < 6) {
        echo json_encode(["error" => "Password must be at least 6 characters"]);
        exit;
    }

    $stmt = $conn->prepare("SELECT id FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()");
    $stmt->execute([$token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        echo json_encode(["error" => "Invalid or expired reset token"]);
        exit;
    }

    $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
    $stmt = $conn->prepare("UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?");
    $stmt->execute([$hashedPassword, $user['id']]);

    echo json_encode(["message" => "Password reset successfully"]);
    exit;
}

// Change Password - Authenticated user changes password
if ($method === 'POST' && $action === 'change') {
    $user = authenticate();

    $data = json_decode(file_get_contents("php://input"), true);
    $currentPassword = $data['current_password'] ?? '';
    $newPassword = $data['new_password'] ?? '';

    if (!$currentPassword || !$newPassword) {
        echo json_encode(["error" => "Current and new password required"]);
        exit;
    }

    if (strlen($newPassword) < 6) {
        echo json_encode(["error" => "New password must be at least 6 characters"]);
        exit;
    }

    $stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
    $stmt->execute([$user['id']]);
    $userData = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!password_verify($currentPassword, $userData['password'])) {
        echo json_encode(["error" => "Current password is incorrect"]);
        exit;
    }

    $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
    $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
    $stmt->execute([$hashedPassword, $user['id']]);

    echo json_encode(["message" => "Password changed successfully"]);
    exit;
}

echo json_encode(["error" => "Invalid request"]);
?>
