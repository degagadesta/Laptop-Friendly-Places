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
    $isBlocked = $_GET['is_blocked'] ?? null;
    $role = $_GET['role'] ?? null;
    $emailVerified = $_GET['email_verified'] ?? null;
    
    $whereConditions = [];
    $params = [];
    
    if ($isBlocked !== null) {
        $whereConditions[] = "is_blocked = :is_blocked";
        $params[':is_blocked'] = (int)$isBlocked;
    }
    
    if ($role) {
        $whereConditions[] = "role = :role";
        $params[':role'] = $role;
    }
    
    if ($emailVerified !== null) {
        $whereConditions[] = "email_verified = :email_verified";
        $params[':email_verified'] = (int)$emailVerified;
    }
    
    $whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';
    
    // Get users without password field
    $sql = "SELECT id, name, email, role, is_blocked, email_verified, created_at, updated_at 
            FROM users $whereClause ORDER BY created_at DESC";
    
    $stmt = $conn->prepare($sql);
    $stmt->execute($params);
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Convert boolean fields to proper boolean
    $users = array_map(function($user) {
        $user['is_blocked'] = (bool)$user['is_blocked'];
        $user['email_verified'] = (bool)$user['email_verified'];
        return $user;
    }, $users);
    
    echo json_encode([
        'success' => true,
        'data' => $users,
        'count' => count($users)
    ]);
    
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'message' => 'Database error occurred']);
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'An error occurred']);
}
?>