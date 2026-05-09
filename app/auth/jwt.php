<?php
$config = require __DIR__ . "/../../config/env.php";

function generateJWT($user) {
    global $config;

    $payload = [
        "id" => $user["id"],
        "email" => $user["email"],
        "exp" => time() + (60 * 60 * 24) // 1 day
    ];

    return base64_encode(json_encode($payload)) . "." . $config["JWT_SECRET"];
}

function verifyJWT($token) {
    global $config;

    $parts = explode(".", $token);
    if (count($parts) !== 2) return false;

    $payload = json_decode(base64_decode($parts[0]), true);

    if ($parts[1] !== $config["JWT_SECRET"]) return false;
    if ($payload["exp"] < time()) return false;

    return $payload;
}