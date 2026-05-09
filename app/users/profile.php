<?php
require_once("../../config/database.php");
require_once("../auth/auth.middleware.php");

$user_id = $user["id"];

$sql = "SELECT id, username, email FROM users WHERE id='$user_id'";
$result = $conn->query($sql);

echo json_encode($result->fetch_assoc());