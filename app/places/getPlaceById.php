<?php

header("Content-Type: application/json");

require_once "../../config/db.php";

/* ===== GET PLACE ID ===== */
$id = $_GET['id'] ?? null;

/* ===== VALIDATION ===== */
if (!$id) {

    echo json_encode([
        "error" => "Place ID required"
    ]);

    exit;
}

/* ===== FETCH PLACE ===== */
$sql = "
    SELECT *
    FROM places
    WHERE id = ?
";

$stmt = $conn->prepare($sql);
$stmt->execute([$id]);

$place = $stmt->fetch(PDO::FETCH_ASSOC);

/* ===== CHECK IF PLACE EXISTS ===== */
if (!$place) {

    echo json_encode([
        "error" => "Place not found"
    ]);

    exit;
}

/* ===== RETURN JSON RESPONSE ===== */
echo json_encode($place);

?>