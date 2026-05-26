<?php
header("Content-Type: application/json");

require_once "config/database.php";

echo json_encode([
    "success" => true,
    "message" => "Database connected successfully",
    "database" => "lfp_db"
]);