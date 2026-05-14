<?php

header("Content-Type: application/json");
session_start();

require_once "../../config/db.php";

/* ===== GET SESSION USER ===== */
$user_id = $_SESSION['user_id'] ?? null;

/* ===== GET FORM DATA ===== */
$name = trim($_POST['name'] ?? '');
$description = trim($_POST['description'] ?? '');
$location = trim($_POST['location'] ?? '');

/* ===== VALIDATION ===== */
// Uncomment if validation is required
/*
if (!$name || !$location || !$user_id) {
    echo json_encode([
        "error" => "Missing required fields or not logged in"
    ]);
    exit;
}
*/

/* ===== HANDLE IMAGE UPLOAD ===== */
$imagePath = null;

if (
    isset($_FILES['image']) &&
    $_FILES['image']['error'] === 0
) {
    $imageUploadDir = "../../uploads/images/";

    if (!is_dir($imageUploadDir)) {
        mkdir($imageUploadDir, 0777, true);
    }

    $imageName = time() . "_" . basename($_FILES['image']['name']);
    $imageTarget = $imageUploadDir . $imageName;

    if (move_uploaded_file($_FILES['image']['tmp_name'], $imageTarget)) {
        $imagePath = "uploads/images/" . $imageName;
    }
}

/* ===== HANDLE VIDEO UPLOAD ===== */
$videoPath = null;

if (
    isset($_FILES['video']) &&
    $_FILES['video']['error'] === 0
) {
    $videoUploadDir = "../../uploads/videos/";

    if (!is_dir($videoUploadDir)) {
        mkdir($videoUploadDir, 0777, true);
    }

    $videoName = time() . "_" . basename($_FILES['video']['name']);
    $videoTarget = $videoUploadDir . $videoName;

    if (move_uploaded_file($_FILES['video']['tmp_name'], $videoTarget)) {
        $videoPath = "uploads/videos/" . $videoName;
    }
}

/* ===== INSERT INTO DATABASE ===== */
try {
    $sql = "
        INSERT INTO places (
            name,
            description,
            location,
            image,
            video,
            created_by
        )
        VALUES (?, ?, ?, ?, ?, ?)
    ";

    $stmt = $conn->prepare($sql);

    $stmt->execute([
        $name,
        $description,
        $location,
        $imagePath,
        $videoPath,
        $user_id
    ]);

    echo json_encode([
        "message" => "Place created successfully"
    ]);

} catch (PDOException $e) {

    echo json_encode([
        "error" => $e->getMessage()
    ]);
}
?>