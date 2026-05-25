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

if ($_SERVER['REQUEST_METHOD'] !== 'POST'){
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Only post method allowed']);
    exit; // terminate the running script.
}

try {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($input['place_id'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'place_id is required']);
        exit;
    }
    
    $placeId = $input['place_id'];
    $newStatus = $input['status'] ?? 'approved';
    
    // Validate status
    $validStatuses = ['pending', 'approved', 'rejected'];
    if (!in_array($newStatus, $validStatuses)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'message' => 'Invalid status. Valid statuses: ' . implode(', ', $validStatuses)
        ]);
        exit;
    }
    
    // Check if place exists
    $checkSql = "SELECT id, status FROM places WHERE id = :id";
    $checkStmt = $conn->prepare($checkSql);
    $checkStmt->bindParam(':id', $placeId);
    $checkStmt->execute();
    
    if ($checkStmt->rowCount() === 0) {
        http_response_code(404);

        echo json_encode(['success' => false, 'message' => 'Place not found']);
        exit;
    }
    
    // Update place status
    $sql = "UPDATE places SET status = :status WHERE id = :id";
    $stmt = $conn->prepare($sql);
    $stmt->execute([
        ':status' => $newStatus,
        ':id' => $placeId
    ]);
    
    http_response_code(200);

    echo json_encode([
        'success' => true,
        'message' => "Place status updated to {$newStatus}"
    ]);
    
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'message' => 'Database error occurred']);
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'An error occurred']);
}
?>