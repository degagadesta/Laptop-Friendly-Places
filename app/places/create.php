<?php
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

require_once "../../config/db.php";
require_once "../auth/auth.middleware.php";

// Require authentication
$user = authenticate();
$user_id = $user['id'];

$name = trim($_POST['name'] ?? '');
$description = trim($_POST['description'] ?? '');
$location = trim($_POST['location'] ?? '');

/* ===== VALIDATION ===== */
if (!$name || !$location) {
    echo json_encode(["error" => "Name and location are required"]);
    exit;
}

/* ===== HANDLE IMAGE ===== */
$imagePath = null;

if (isset($_FILES['image']) && $_FILES['image']['error'] === 0) {

    $uploadDir = "../../uploads/images/";

    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    $imageName = time() . "_" . basename($_FILES['image']['name']);
    $target = $uploadDir . $imageName;

    if (move_uploaded_file($_FILES['image']['tmp_name'], $target)) {
        $imagePath = "uploads/images/" . $imageName;
    }
}

/* ===== HANDLE VIDEO ===== */
$videoPath = null;

if (isset($_FILES['video']) && $_FILES['video']['error'] === 0) {

    $uploadDir = "../../uploads/videos/";

    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    $videoName = time() . "_" . basename($_FILES['video']['name']);
    $target = $uploadDir . $videoName;

    if (move_uploaded_file($_FILES['video']['tmp_name'], $target)) {
        $videoPath = "uploads/videos/" . $videoName;
    }
}

/* ===== INSERT INTO DB ===== */
try {
    $stmt = $conn->prepare("
        INSERT INTO places (name, description, location, image, video, created_by)
        VALUES (?, ?, ?, ?, ?, ?)
    ");

    $stmt->execute([
        $name,
        $description,
        $location,
        $imagePath,
        $videoPath,
        $user_id
    ]);

    echo json_encode(["message" => "Place created successfully"]);

} catch (PDOException $e) {
    echo json_encode(["error" => $e->getMessage()]);
}
?>