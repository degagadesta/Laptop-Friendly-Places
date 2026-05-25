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
    
    if (!isset($input['user_id'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'user_id is required']);
        exit;
    }
    
    $userId = $input['user_id'];
    $action = $input['action'] ?? 'block'; // 'block' or 'unblock'
    
    // Validate action
    if (!in_array($action, ['block', 'unblock'])) {
        http_response_code(400);

        echo json_encode(['success' => false, 'message' => 'Invalid action. Use "block" or "unblock"']);
        exit;
    }
    
    // Check if user exists
    $checkSql = "SELECT id, name, email, is_blocked FROM users WHERE id = :id";
    $checkStmt = $conn->prepare($checkSql);
    $checkStmt->bindParam(':id', $userId);
    $checkStmt->execute();
    
    $user = $checkStmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'User not found']);
        exit;
    }
    
    // Set block status
    $isBlocked = ($action === 'block') ? 1 : 0;
    
    // Check if already in desired state
    if ($user['is_blocked'] == $isBlocked) {
        $status = $action === 'block' ? 'blocked' : 'unblocked';
        http_response_code(200);
        echo json_encode([
            'success' => true,
            'message' => "User is already {$status}"
        ]);
        exit;
    }
    
    // Update user block status
    $sql = "UPDATE users SET is_blocked = :is_blocked WHERE id = :id";
    $stmt = $conn->prepare($sql);
    $stmt->execute([
        ':is_blocked' => $isBlocked,
        ':id' => $userId
    ]);
    
    $actionPast = $action === 'block' ? 'blocked' : 'unblocked';
    http_response_code(200);
    
    echo json_encode([
        'success' => true,
        'message' => "User {$actionPast} successfully",
        'data' => [
            'user_id' => $userId,
            'is_blocked' => (bool)$isBlocked
        ]
    ]);
    
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Database error occurred']);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'An error occurred']);
}
?>