<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

/** @var PDO $conn */
require_once '../../../config/db.php';
require_once '../../auth/admin.middleware.php';

// Require admin authentication
$admin = requireAdmin();

try {
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        // Get all reports or filter by status
        $status = $_GET['status'] ?? null;
        $placeId = $_GET['place_id'] ?? null;
        
        $whereConditions = [];
        $params = [];
        
        if ($status) {
            $whereConditions[] = "status = :status";
            $params[':status'] = $status;
        }
        
        if ($placeId) {
            $whereConditions[] = "place_id = :place_id";
            $params[':place_id'] = $placeId;
        }
        
        $whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';
        
        $sql = "SELECT r.*, p.name as place_name 
                FROM reports r 
                LEFT JOIN places p ON r.place_id = p.id 
                $whereClause 
                ORDER BY r.created_at DESC";
        
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);
        $reports = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        http_response_code(200);

        echo json_encode([
            'success' => true,
            'data' => $reports
        ]);
        
    } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Update report status (resolve/reject)
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($input['report_id']) || !isset($input['status'])) {
            http_response_code(400);

            echo json_encode([
                'success' => false,
                'message' => 'Missing report_id or status'
            ]);
            exit;
        }
        
        $validStatuses = ['pending', 'resolved', 'rejected'];
        if (!in_array($input['status'], $validStatuses)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'Invalid status. Valid statuses: ' . implode(', ', $validStatuses)
            ]);
            exit;
        }
        
        // Update report status
        $sql = "UPDATE reports SET status = :status";
        $params = [':status' => $input['status'], ':report_id' => $input['report_id']];
        
        // Set resolved_at timestamp if status is resolved
        if ($input['status'] === 'resolved') {
            $sql .= ", resolved_at = NOW()";
        } elseif ($input['status'] === 'pending') {
            $sql .= ", resolved_at = NULL";
        }
        
        $sql .= " WHERE id = :report_id";
        
        $stmt = $conn->prepare($sql);
        $result = $stmt->execute($params);
        
        if ($stmt->rowCount() > 0) {
            http_response_code(200);
            echo json_encode([
                'success' => true,
                'message' => 'Report status updated successfully'
            ]);
        } else {
            http_response_code(404);
            echo json_encode([
                'success' => false,
                'message' => 'Report not found'
            ]);
        }
    }
    
} catch (PDOException $e) {
    http_response_code(500);
    
    echo json_encode([
        'success' => false,
        'message' => 'Database error occurred'
    ]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'An error occurred'
    ]);
}
?>