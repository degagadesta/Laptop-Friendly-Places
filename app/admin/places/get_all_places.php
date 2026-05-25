<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

/** @var PDO $conn */
require_once '../../../config/db.php';
require_once '../../auth/admin.middleware.php';

// Require admin authentication
$admin = requireAdmin();

try {
    // Optional filters
    $status = $_GET['status'] ?? null;
    $category = $_GET['category'] ?? null;
    
    $whereConditions = [];
    $params = [];
    
    if ($status) {
        $whereConditions[] = "status = :status";
        $params[':status'] = $status;
    }
    
    if ($category) {
        $whereConditions[] = "category = :category";
        $params[':category'] = $category;
    }
    
    $whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';
    
    $sql = "SELECT * FROM places $whereClause ORDER BY created_at DESC";
    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
    $places = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Transform data structure
    $transformedPlaces = array_map(function($place) {
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
        
        unset($place['media_images'], $place['media_videos']);
        unset($place['rating_customer_service'], $place['rating_overall'], $place['rating_power'], $place['rating_wifi']);
        unset($place['location_lat'], $place['location_lng']);
        
        return $place;
    }, $places);

    http_response_code(200);
    echo json_encode([
        'success' => true,
        'data' => $transformedPlaces,
        'count' => count($transformedPlaces)
    ]);
    
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Database error occurred']);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'An error occurred']);
}
?>