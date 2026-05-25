<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

/** @var PDO $conn */
require_once '../../../config/db.php';
require_once '../../auth/admin.middleware.php';

// Require admin authentication
$admin = requireAdmin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);

    echo json_encode(['success' => false, 'message' => 'Only POST method allowed']);
    exit;
}

try {
    $input = json_decode(file_get_contents('php://input'), true);
    
    // Validate required fields
    if (!isset($input['name']) || empty(trim($input['name']))) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Name is required']);
        exit;
    }
    
    // Generate unique place ID
    $placeId = uniqid('place_', true);
    
    // Prepare data with defaults
    $category = $input['category'] ?? null;
    $description = $input['description'] ?? null;
    $locationLat = $input['location']['lat'] ?? null;
    $locationLng = $input['location']['lng'] ?? null;
    $mediaImages = isset($input['media']['images']) ? json_encode($input['media']['images']) : json_encode([]);
    $mediaVideos = isset($input['media']['videos']) ? json_encode($input['media']['videos']) : json_encode([]);
    $name = trim($input['name']);
    $ratingCustomerService = $input['rating']['customer_service'] ?? null;
    $ratingOverall = $input['rating']['overall'] ?? null;
    $ratingPower = $input['rating']['power'] ?? null;
    $ratingWifi = $input['rating']['wifi'] ?? null;
    $status = $input['status'] ?? 'pending';
    $tag = $input['tag'] ?? null;
    
    // Insert place
    $sql = "INSERT INTO places (
        id, category, description, location_lat, location_lng,
        media_images, media_videos, name, rating_customer_service,
        rating_overall, rating_power, rating_wifi, status, tag
    ) VALUES (
        :id, :category, :description, :location_lat, :location_lng,
        :media_images, :media_videos, :name, :rating_customer_service,
        :rating_overall, :rating_power, :rating_wifi, :status, :tag
    )";
    
    $stmt = $conn->prepare($sql);
    $stmt->execute([
        ':id' => $placeId,
        ':category' => $category,
        ':description' => $description,
        ':location_lat' => $locationLat,
        ':location_lng' => $locationLng,
        ':media_images' => $mediaImages,
        ':media_videos' => $mediaVideos,
        ':name' => $name,
        ':rating_customer_service' => $ratingCustomerService,
        ':rating_overall' => $ratingOverall,
        ':rating_power' => $ratingPower,
        ':rating_wifi' => $ratingWifi,
        ':status' => $status,
        ':tag' => $tag
    ]);
    
    http_response_code(201);
    echo json_encode([
        'success' => true,
        'message' => 'Place created successfully',
        'data' => ['id' => $placeId]
    ]);
    
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Database error occurred']);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'An error occurred']);
}
?>