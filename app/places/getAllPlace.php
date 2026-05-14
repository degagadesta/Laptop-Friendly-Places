<?php

header("Content-Type: application/json");

require_once "../../config/db.php";

/* ===== FETCH ALL PLACES ===== */
$sql = "
    SELECT *
    FROM places
    ORDER BY id DESC
";

$stmt = $conn->prepare($sql);
$stmt->execute();

$places = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* ===== RETURN JSON RESPONSE ===== */
echo json_encode($places);

?>