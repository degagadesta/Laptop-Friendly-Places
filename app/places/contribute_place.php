<?php
include("../config/database.php");

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $name = $_POST['name'] ?? '';
    $category = $_POST['category'] ?? '';
    $description = $_POST['description'] ?? '';
    $lat = $_POST['latitude'] ?? 0;
    $lng = $_POST['longitude'] ?? 0;
    $rating = $_POST['rating'] ?? 0;
    $wifi = $_POST['wifi'] ?? '';
    $power = $_POST['power'] ?? '';
    $service = $_POST['service'] ?? '';

    // ---------- IMAGE UPLOAD ----------
    $imagePaths = [];

    if (!empty($_FILES['images']['name'][0])) {
        foreach ($_FILES['images']['tmp_name'] as $key => $tmpName) {
            $fileName = time() . "_" . $_FILES['images']['name'][$key];
            $target = "../uploads/images/" . $fileName;

            if (move_uploaded_file($tmpName, $target)) {
                $imagePaths[] = $target;
            }
        }
    }

    // ---------- VIDEO UPLOAD ----------
    $videoPath = null;

    if (!empty($_FILES['video']['name'])) {
        $fileName = time() . "_" . $_FILES['video']['name'];
        $target = "../uploads/videos/" . $fileName;

        if (move_uploaded_file($_FILES['video']['tmp_name'], $target)) {
            $videoPath = $target;
        }
    }

    $imagesJSON = json_encode($imagePaths);

    // ---------- INSERT ----------
    $stmt = $conn->prepare("INSERT INTO places 
        (name, category, description, latitude, longitude, rating, wifi_rating, power_rating, service_rating, images, video, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')");

    $stmt->bind_param(
        "sssddisssss",
        $name,
        $category,
        $description,
        $lat,
        $lng,
        $rating,
        $wifi,
        $power,
        $service,
        $imagesJSON,
        $videoPath
    );

    if ($stmt->execute()) {
        echo "Place submitted (waiting for admin approval)";
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
    $conn->close();
}
?>