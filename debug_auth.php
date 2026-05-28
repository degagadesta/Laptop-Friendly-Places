<?php
header("Content-Type: application/json");
require_once "config/db.php";
require_once "app/auth/auth.middleware.php";

$user = authenticate();
echo json_encode([
    "user_array" => $user,
    "user_id_value" => $user['id'] ?? "NOT SET",
    "full_auth_result" => $user
]);
?>
