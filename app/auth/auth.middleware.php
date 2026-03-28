<?php
require_once "./jwt.php";

function authenticate() {
    $headers = getallheaders();

    if (!isset($headers['Authorization'])) {
        echo json_encode(["error" => "Unauthorized"]);
        exit;
    }

    $token = str_replace("Bearer ", "", $headers['Authorization']);

    $user = verifyJWT($token);

    if (!$user) {
        echo json_encode(["error" => "Invalid or expired token"]);
        exit;
    }

    return $user;
}
?>