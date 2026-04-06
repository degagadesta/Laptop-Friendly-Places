<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

require_once '../../config/db.php';

try {
    // Check if specific place ID is requested
    $placeId = $_GET['id'] ?? null;
    
    if ($placeId) {
        // Fetch single place by ID
        $stmt = $conn->prepare("SELECT * FROM places WHERE id = :id");
        $stmt->bindParam(':id', $placeId);
        $stmt->execute();
        
        $place = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($place) {
            // Convert JSON strings back to arrays
            $place['media'] = [
                'images' => json_decode($place['media_images'], true) ?? [],
                'videos' => json_decode($place['media_videos'], true) ?? []
            ];
            
            // Reconstruct rating object
            $place['rating'] = [
                'customer_service' => $place['rating_customer_service'],
                'overall' => (float)$place['rating_overall'],
                'power' => $place['rating_power'],
                'wifi' => $place['rating_wifi']
            ];
            
            // Reconstruct location object
            $place['location'] = [
                'lat' => (float)$place['location_lat'],
                'lng' => (float)$place['location_lng']
            ];
            
            // Remove flattened columns from response
            unset($place['media_images'], $place['media_videos']);
            unset($place['rating_customer_service'], $place['rating_overall'], $place['rating_power'], $place['rating_wifi']);
            unset($place['location_lat'], $place['location_lng']);
            
            echo json_encode([
                'success' => true,
                'data' => $place
            ]);
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Place not found'
            ]);
        }
    } else {
        // Fetch all places with optional filtering
        $category = $_GET['category'] ?? null;
        $status = $_GET['status'] ?? null;
        
        // Build query with optional filters
        $whereConditions = [];
        $params = [];
        
        if ($category) {
            $whereConditions[] = "category = :category";
            $params[':category'] = $category;
        }
        
        if ($status) {
            $whereConditions[] = "status = :status";
            $params[':status'] = $status;
        }
        
        $whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';
        
        // Get all places
        $sql = "SELECT * FROM places $whereClause ORDER BY created_at DESC";
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);
        $places = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Transform data structure for each place
        $transformedPlaces = array_map(function($place) {
            // Convert JSON strings back to arrays
            $place['media'] = [
                'images' => json_decode($place['media_images'], true) ?? [],
                'videos' => json_decode($place['media_videos'], true) ?? []
            ];
            
            // Reconstruct rating object
            $place['rating'] = [
                'customer_service' => $place['rating_customer_service'],
                'overall' => (float)$place['rating_overall'],
                'power' => $place['rating_power'],
                'wifi' => $place['rating_wifi']
            ];
            
            // Reconstruct location object
            $place['location'] = [
                'lat' => (float)$place['location_lat'],
                'lng' => (float)$place['location_lng']
            ];
            
            // Remove flattened columns from response
            unset($place['media_images'], $place['media_videos']);
            unset($place['rating_customer_service'], $place['rating_overall'], $place['rating_power'], $place['rating_wifi']);
            unset($place['location_lat'], $place['location_lng']);
            
            return $place;
        }, $places);
        
        echo json_encode([
            'success' => true,
            'data' => $transformedPlaces
        ]);
    }
    
} catch (PDOException $e) {
    echo json_encode([
        'success' => false,
        'message' => 'Database error occurred'
    ]);
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'message' => 'An error occurred'
    ]);
}
?>