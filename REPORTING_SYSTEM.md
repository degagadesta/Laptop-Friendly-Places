# Reporting System - Complete Documentation

## Overview
Users can report problematic places. Admins review reports and take action (delete place, resolve, or reject).

---

## USER SIDE - How to Report a Place

### Step 1: Access Report Feature
1. Browse places on the Places page
2. Click on any place card to open details sheet
3. Click the "Report" button at the bottom

### Step 2: Fill Report Form
**Required Fields:**
- **Issue Type** (dropdown):
  - Incorrect Information
  - Inappropriate Content
  - Spam
  - Fake Place
  - Duplicate Entry
  - Closed Permanently
  - Other Issues
- **Description** (text area): Explain the problem in detail

### Step 3: Submit
- Click "Submit Report"
- Must be logged in (redirects to login if not)
- Success message appears
- Report is sent to admin dashboard

### Technical Details (User)
```javascript
// API: POST /reports
// Auth: Required (JWT token)
// Body:
{
  "place_id": 123,
  "reason": "incorrect_info",
  "message": "The WiFi rating is completely wrong...",
  "reported_by": 456
}
```

---

## ADMIN SIDE - Managing Reports

### Reports Dashboard
**Location:** Admin Dashboard → Reported Places

### Table Columns
1. **Place Name** - Name of reported place
2. **Issue Type** - Reason for report
3. **Reported By** - Username of reporter
4. **Message** - Preview of description (40 chars)
5. **Date** - When report was submitted
6. **Status** - Current state:
   - 🟡 Pending (yellow badge)
   - 🟢 Resolved (green badge)
   - 🔴 Rejected (red badge)
7. **Actions** - Admin buttons

### Filter Reports
Click filter buttons at top:
- **All** - Show everything
- **Pending** - Only unresolved
- **Resolved** - Completed reports
- **Rejected** - Dismissed reports

### Search Reports
- Use search bar to filter by any text
- Searches across all columns in real-time

---

## ADMIN ACTIONS

### 1. View Report Details
**Button:** Eye icon (👁️)

**Shows:**
- Full report information
- Complete message
- Reporter details
- Submission timestamp
- Current status

### 2. Delete Place (Removes Place Entirely)
**Button:** Red "Delete Place"

**When to use:**
- Place is fake/spam
- Inappropriate content
- Permanently closed
- Duplicate entry

**What happens:**
1. Confirmation dialog appears
2. Place is deleted from database
3. Report marked as "resolved"
4. Place removed from all user views
5. Success toast notification

**Code:**
```javascript
// Deletes place + resolves report
DELETE /admin/places/delete
Body: { place_id: 123 }

POST /admin/reports
Body: { report_id: 456, status: "resolved" }
```

### 3. Resolve (Keep Place, Mark Report Done)
**Button:** Green "Resolve"

**When to use:**
- Issue was fixed
- Report was valid but place should stay
- Problem resolved by editing place info

**What happens:**
1. Confirmation dialog
2. Report status → "resolved"
3. Place stays in database unchanged
4. Report moves to "Resolved" filter

**Code:**
```javascript
POST /admin/reports
Body: { report_id: 456, status: "resolved" }
```

### 4. Reject Report (Dismiss as Invalid)
**Button:** Gray "Reject Report"

**When to use:**
- Report is incorrect/false
- No issue found
- Spam report

**What happens:**
1. Confirmation dialog
2. Report status → "rejected"
3. Place stays unchanged
4. Report moves to "Rejected" filter

**Code:**
```javascript
POST /admin/reports
Body: { report_id: 456, status: "rejected" }
```

---

## WORKFLOW DIAGRAM

```
┌─────────────────────────────────────────────────────────────┐
│                        USER WORKFLOW                         │
└─────────────────────────────────────────────────────────────┘

1. User clicks place → Views details
2. Clicks "Report" button
3. Selects issue type from dropdown
4. Writes description
5. Submits form
6. Report saved with status: "pending"

                        ↓

┌─────────────────────────────────────────────────────────────┐
│                       ADMIN WORKFLOW                         │
└─────────────────────────────────────────────────────────────┘

1. Admin opens Reports dashboard
2. Sees all pending reports in table
3. Clicks eye icon to view details
4. Chooses one of three actions:

   ┌─────────────────────────────────────────────────────┐
   │ A. DELETE PLACE                                     │
   │    - Place removed from database                    │
   │    - Report marked "resolved"                       │
   │    - Use for: fake, spam, inappropriate             │
   └─────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────┐
   │ B. RESOLVE (Keep Place)                             │
   │    - Place stays in database                        │
   │    - Report marked "resolved"                       │
   │    - Use for: fixed issues, valid but keep place    │
   └─────────────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────┐
   │ C. REJECT REPORT                                    │
   │    - Place stays unchanged                          │
   │    - Report marked "rejected"                       │
   │    - Use for: false reports, no issue found         │
   └─────────────────────────────────────────────────────┘
```

---

## DATABASE SCHEMA

```sql
CREATE TABLE reports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    place_id INT NOT NULL,
    reason VARCHAR(50) NOT NULL,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Note: status and resolved_at columns may need to be added
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (place_id) REFERENCES places(id)
);
```

---

## API ENDPOINTS

### User Endpoints

**Create Report**
```
POST /reports
Authorization: Bearer <user_token>
Content-Type: application/json

Request:
{
  "place_id": 123,
  "reason": "incorrect_info",
  "message": "Description of the issue",
  "reported_by": 456
}

Response (201):
{
  "success": true,
  "message": "Report created successfully",
  "data": { ...report object... }
}
```

### Admin Endpoints

**Get All Reports**
```
GET /admin/reports
GET /admin/reports?status=pending
Authorization: Bearer <admin_token>

Response:
{
  "data": [
    {
      "id": 1,
      "place_id": 123,
      "place_name": "Coffee Shop",
      "reason": "incorrect_info",
      "message": "Wrong WiFi rating",
      "reported_by": "John Doe",
      "created_at": "2026-05-28 10:30:00",
      "status": "pending"
    }
  ]
}
```

**Update Report Status**
```
POST /admin/reports
Authorization: Bearer <admin_token>
Content-Type: application/json

Request:
{
  "report_id": 1,
  "status": "resolved"  // or "rejected"
}

Response:
{
  "success": true,
  "message": "Report updated"
}
```

**Delete Place**
```
DELETE /admin/places/delete
Authorization: Bearer <admin_token>
Content-Type: application/json

Request:
{
  "place_id": 123
}

Response:
{
  "success": true,
  "message": "Place deleted successfully"
}
```

---

## VALID REPORT REASONS

Backend validates these reason codes:
- `incorrect_info` - Incorrect Information
- `inappropriate_content` - Inappropriate Content
- `spam` - Spam
- `fake_place` - Fake Place
- `duplicate` - Duplicate Entry
- `closed_permanently` - Closed Permanently
- `other` - Other Issues

---

## FILES INVOLVED

### Frontend (User)
- `frontend/js/places.js` - Report modal and submission
- `frontend/pages/places.html` - Report button and modal HTML
- `frontend/css/style.css` - Report modal styling

### Frontend (Admin)
- `frontend/Admin-dashboard/js/reported.js` - Reports management
- `frontend/Admin-dashboard/html/reported.html` - Reports table
- `frontend/Admin-dashboard/css/reports.css` - Reports styling

### Backend
- `backend/controllers/ReportController.php` - User report creation
- `backend/controllers/AdminController.php` - Admin report management
- `backend/models/ReportModel.php` - Database operations
- `backend/index.php` - Route definitions

---

## SECURITY NOTES

1. **Authentication Required:**
   - Users must be logged in to submit reports
   - Admins must have admin token to manage reports

2. **Validation:**
   - All required fields checked
   - Reason must be from valid list
   - Place must exist before reporting

3. **Authorization:**
   - Only admins can view/manage reports
   - Users can only create reports, not view others'

---

## FUTURE ENHANCEMENTS

1. Add `status` and `resolved_at` columns to database
2. Email notifications to admins on new reports
3. Report history/audit log
4. Bulk actions (resolve multiple reports)
5. Report analytics dashboard
6. User notification when their report is handled
