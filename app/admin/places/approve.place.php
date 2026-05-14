<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

require_once '../../../config/db.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Only POST method allowed']);
    exit;
}

try {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($input['place_id'])) {
        echo json_encode(['success' => false, 'message' => 'place_id is required']);
        exit;
    }
    
    $placeId = $input['place_id'];
    $newStatus = $input['status'] ?? 'approved';
    
    // Validate status
    $validStatuses = ['pending', 'approved', 'rejected'];
    if (!in_array($newStatus, $validStatuses)) {
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