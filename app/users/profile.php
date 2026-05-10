<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, PUT, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once "../../config/db.php";
require_once "../auth/auth.middleware.php";

$method = $_SERVER['REQUEST_METHOD'];

// GET - Get user profile
if ($method === 'GET') {
    $user = authenticate();
    
    $stmt = $conn->prepare("SELECT id, name, email, role, created_at FROM users WHERE id = ?");
    $stmt->execute([$user['id']]);
    $userData = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$userData) {
        http_response_code(404);
        echo json_encode(["error" => "User not found"]);
        exit;
    }
    
    echo json_encode([
        "user" => $userData
    ]);
    exit;
}

// PUT - Update user profile
if ($method === 'PUT') {
    $user = authenticate();
    
    $data = json_decode(file_get_contents("php://input"), true);
    $name = trim($data['name'] ?? '');
    
    if (!$name) {
        http_response_code(400);
        echo json_encode(["error" => "Name is required"]);
        exit;
    }
    
    $stmt = $conn->prepare("UPDATE users SET name = ? WHERE id = ?");
    $stmt->execute([$name, $user['id']]);
    
    // Get updated user data
    $stmt = $conn->prepare("SELECT id, name, email, role, created_at FROM users WHERE id = ?");
    $stmt->execute([$user['id']]);
    $userData = $stmt->fetch(PDO::FETCH_ASSOC);
    
    echo json_encode([
        "message" => "Profile updated successfully",
        "user" => $userData
    ]);
    exit;
}

http_response_code(405);
echo json_encode(["error" => "Method not allowed"]);
?>
