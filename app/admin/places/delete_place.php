<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, DELETE');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

/** @var PDO $conn*/
require_once '../../../config/db.php';
require_once '../../auth/admin.middleware.php';

// Require admin authentication
$admin = requireAdmin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST' && $_SERVER['REQUEST_METHOD'] !== 'DELETE') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Only POST or DELETE method allowed']);
    exit;
}

try {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($input['place_id'])) {
        http_response_code(400);   
        echo json_encode(['success' => false, 'message' => 'place_id is required']);
        exit;
    }
    
    $placeId = $input['place_id'];
    
    // Check if place exists
    $checkSql = "SELECT id FROM places WHERE id = :id";
    $checkStmt = $conn->prepare($checkSql);
    $checkStmt->bindParam(':id', $placeId);
    $checkStmt->execute();
    
    if ($checkStmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Place not found']);
        exit;
    }
    
    // Delete place
    $sql = "DELETE FROM places WHERE id = :id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':id', $placeId);
    $stmt->execute();
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'message' => 'Place deleted successfully'
    ]);
    
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Database error occurred']);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'An error occurred']);
}
?>