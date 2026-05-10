<?php
require_once "jwt.php";

function authenticate() {
    $headers = getallheaders();

    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["error" => "Unauthorized"]);
        exit;
    }

    $token = str_replace("Bearer ", "", $headers['Authorization']);
    $secret = "my_secret_key";

    $decoded = verifyJWT($token, $secret);

    if (!$decoded) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid or expired token"]);
        exit;
    }

    return $decoded;
}

function requireRole($allowedRoles = []) {
    $user = authenticate();
    
    if (!empty($allowedRoles) && !in_array($user['role'] ?? 'user', $allowedRoles)) {
        http_response_code(403);
        echo json_encode(["error" => "Forbidden: Insufficient permissions"]);
        exit;
    }
    
    return $user;
}

function optionalAuth() {
    $headers = getallheaders();
    
    if (!isset($headers['Authorization'])) {
        return null;
    }
    
    $token = str_replace("Bearer ", "", $headers['Authorization']);
    return verifyJWT($token);
}
?>