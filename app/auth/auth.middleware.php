<?php
require_once "jwt.php";

function authenticate() {

    $headers = getallheaders();

    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["error" => "No token provided"]);
        exit;
    }

    $authHeader = $headers['Authorization'];

    if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid token format"]);
        exit;
    }

    $token = $matches[1];

    $secret = "my_secret_key";

    $decoded = verifyJWT($token, $secret);

    if (!$decoded) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid token"]);
        exit;
    }

    if ($decoded['exp'] < time()) {
        http_response_code(401);
        echo json_encode(["error" => "Token expired"]);
        exit;
    }

    return $decoded; // contains user_id
}
?>