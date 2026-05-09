<?php
require_once(__DIR__ . "/jwt.php");

$headers = getallheaders();

if (!isset($headers["Authorization"])) {
    echo json_encode(["error" => "Unauthorized"]);
    exit;
}

$user = verifyJWT($headers["Authorization"]);

if (!$user) {
    echo json_encode(["error" => "Invalid token"]);
    exit;
}