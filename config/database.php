<?php
$config = require __DIR__ . "/env.php";

$conn = new mysqli(
    $config["DB_HOST"],
    $config["DB_USER"],
    $config["DB_PASS"],
    $config["DB_NAME"]
);

if ($conn->connect_error) {
    die(json_encode(["error" => "Database connection failed"]));
}

header("Content-Type: application/json");
?>