<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

require_once '../../config/db.php';

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode([
        'success' => false,
        'message' => 'Only POST method allowed'
    ]);
    exit;
}

try {
    // Create reports table if it doesn't exist
    $createTableSql = "CREATE TABLE IF NOT EXISTS reports (
        id VARCHAR(255) PRIMARY KEY,
        message TEXT,
        place_id VARCHAR(255) NOT NULL,
        reason VARCHAR(100) NOT NULL,
        reported_by VARCHAR(255) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP NULL,
        INDEX idx_place_id (place_id),
        INDEX idx_reported_by (reported_by),
        INDEX idx_status (status)
    )";
    
    $conn->exec($createTableSql);
    
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    // Validate required fields
    $requiredFields = ['message', 'place_id', 'reason', 'reported_by'];
    $missingFields = [];
    
    foreach ($requiredFields as $field) {
        if (!isset($input[$field]) || empty(trim($input[$field]))) {
            $missingFields[] = $field;
        }
    }
    
    if (!empty($missingFields)) {
        echo json_encode([
            'success' => false,
            'message' => 'Missing required fields: ' . implode(', ', $missingFields)
        ]);
        exit;
    }
    
    // Validate reason (common report reasons)
    $validReasons = [
        'incorrect_info',
        'inappropriate_content',
        'spam',
        'fake_place',
        'duplicate',
        'closed_permanently',
        'other'
    ];
    
    if (!in_array($input['reason'], $validReasons)) {
        echo json_encode([
            'success' => false,
            'message' => 'Invalid reason. Valid reasons: ' . implode(', ', $validReasons)
        ]);
        exit;
    }
    
    // Check if place exists
    $placeCheckSql = "SELECT id FROM places WHERE id = :place_id";
    $placeStmt = $conn->prepare($placeCheckSql);
    $placeStmt->bindParam(':place_id', $input['place_id']);
    $placeStmt->execute();
    
    if ($placeStmt->rowCount() === 0) {
        echo json_encode([
            'success' => false,
            'message' => 'Place not found'
        ]);
        exit;
    }
    
    // Generate unique report ID
    $reportId = uniqid('report_', true);
    
    // Insert report
    $sql = "INSERT INTO reports (id, message, place_id, reason, reported_by, status, created_at) 
            VALUES (:id, :message, :place_id, :reason, :reported_by, 'pending', NOW())";
    
    $stmt = $conn->prepare($sql);
    $stmt->execute([
        ':id' => $reportId,
        ':message' => trim($input['message']),
        ':place_id' => $input['place_id'],
        ':reason' => $input['reason'],
        ':reported_by' => $input['reported_by']
    ]);
    
    // Get the created report
    $getReportSql = "SELECT * FROM reports WHERE id = :id";
    $getStmt = $conn->prepare($getReportSql);
    $getStmt->bindParam(':id', $reportId);
    $getStmt->execute();
    $report = $getStmt->fetch(PDO::FETCH_ASSOC);
    
    echo json_encode([
        'success' => true,
        'message' => 'Report created successfully',
        'data' => [
            'id' => $report['id'],
            'message' => $report['message'],
            'place_id' => $report['place_id'],
            'reason' => $report['reason'],
            'reported_by' => $report['reported_by'],
            'status' => $report['status'],
            'created_at' => $report['created_at'],
            'resolved_at' => $report['resolved_at']
        ]
    ]);
    
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