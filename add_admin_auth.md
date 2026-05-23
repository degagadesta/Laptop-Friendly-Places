# Adding Admin Authentication to All Endpoints

I've created `app/auth/admin.middleware.php` with helper functions for admin authentication.

## What You Need to Do:

Add these 2 lines to the top of **EVERY** admin endpoint file:

### 1. Add to headers section:
```php
header('Access-Control-Allow-Headers: Content-Type, Authorization');
```

### 2. Add after requiring db.php:
```php
require_once '../../auth/admin.middleware.php';  // or adjust path based on file location
$admin = requireAdmin();  // This will block non-admins
```

## Files That Need Protection:

### Admin Places:
- ✅ `app/admin/places/delete_place.php` (DONE - example)
- ❌ `app/admin/places/create_place.php`
- ❌ `app/admin/places/approve.place.php`
- ❌ `app/admin/places/get_all_places.php`

### Admin Users:
- ❌ `app/admin/users/get_all_users.php`
- ❌ `app/admin/users/block_user.php`

### Admin Reports:
- ❌ `app/admin/report/get_reports.php`

## Example (delete_place.php - ALREADY DONE):

```php
<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, DELETE');
header('Access-Control-Allow-Headers: Content-Type, Authorization');  // ← Added Authorization

require_once '../../../config/db.php';
require_once '../../auth/admin.middleware.php';  // ← Added this
$admin = requireAdmin();  // ← Added this - blocks non-admins

// ... rest of your code
```

## How It Works:

1. Client sends request with header: `Authorization: Bearer <jwt_token>`
2. `requireAdmin()` validates the token
3. Checks if user has 'admin' role
4. If not admin → returns 403 Forbidden
5. If admin → continues with request

## Testing:

**Without token:**
```bash
curl http://localhost/app/admin/places/delete_place.php
# Response: {"error": "Unauthorized"}
```

**With user token (non-admin):**
```bash
curl -H "Authorization: Bearer <user_token>" http://localhost/app/admin/places/delete_place.php
# Response: {"error": "Forbidden: Insufficient permissions"}
```

**With admin token:**
```bash
curl -H "Authorization: Bearer <admin_token>" http://localhost/app/admin/places/delete_place.php
# Response: Success!
```

## Want me to update all files automatically?

Just say "yes, protect all admin endpoints" and I'll add authentication to all of them.