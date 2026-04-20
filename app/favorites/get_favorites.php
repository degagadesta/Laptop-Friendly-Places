<?php
header("Content-Type: application/json");

require_once "../../config/db.php";
require_once "../auth/auth.middleware.php";

$user = authenticate(); // 🔐

try {
    $stmt = $conn->prepare("
        SELECT p.*
        FROM favorites f
        JOIN places p ON f.place_id = p.id
        WHERE f.user_id = :user_id
        ORDER BY f.created_at DESC
    ");

    $stmt->execute([
        ':user_id' => $user['user_id']
    ]);

    $places = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // 🔁 Transform SAME as get_place.php
    $transformed = array_map(function($place) {

        $place['media'] = [
            'images' => json_decode($place['media_images'], true) ?? [],
            'videos' => json_decode($place['media_videos'], true) ?? []
        ];

        $place['rating'] = [
            'customer_service' => $place['rating_customer_service'],
            'overall' => (float)$place['rating_overall'],
            'power' => $place['rating_power'],
            'wifi' => $place['rating_wifi']
        ];

        $place['location'] = [
            'lat' => (float)$place['location_lat'],
            'lng' => (float)$place['location_lng']
        ];

        unset(
            $place['media_images'],
            $place['media_videos'],
            $place['rating_customer_service'],
            $place['rating_overall'],
            $place['rating_power'],
            $place['rating_wifi'],
            $place['location_lat'],
            $place['location_lng']
        );

        return $place;

    }, $places);

    echo json_encode([
        "success" => true,
        "data" => $transformed
    ]);

} catch (PDOException $e) {
    echo json_encode([
        "success" => false,
        "message" => "Database error"
    ]);
}