# Scholar Tracker & Thesis Repository

A centralized Flask web application for managing academic research projects with role-based access, version control, and visual status tracking.

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the app
```bash
python app.py
```

The app initializes the SQLite database and seeds demo data on first run.

Open your browser at: **http://localhost:5000**

---

## Demo Credentials

| Role    | Email                  | Password    |
|---------|------------------------|-------------|
| Guide   | guide@scholar.edu      | guide123    |
| Student | arjun@scholar.edu      | student123  |
| Student | riya@scholar.edu       | student123  |

---

## Features

### Role-Based Access
- **Students** — Upload Dashboard: submit PDF drafts, view feedback, track milestones
- **Guides** — Review Dashboard: see all assigned student submissions, provide feedback

### Traffic Light Status System
| Status        | Colour  | Meaning                              |
|---------------|---------|--------------------------------------|
| Pending       | 🟡 Amber | Submitted, awaiting guide review     |
| Approved      | 🟢 Green | Guide has approved this version      |
| Needs Changes | 🔴 Red   | Guide has requested revisions        |

### Smart Version Control
Submitting a project with the same title auto-increments the version (v1 → v2 → v3…). Previous files are **never deleted**. Guides see the full version timeline with download links for every draft.

### Approved Repository
A searchable archive of all approved projects. Any logged-in user can search by title or keyword and download approved theses.

### Milestone Tracker
Guides can assign academic milestones (Proposal, Synopsis, Final Report, etc.) with due dates to individual students.

---

## Project Structure

```
scholar_tracker/
├── app.py               # Flask application (routes, models, logic)
├── requirements.txt     # Python dependencies
├── uploads/             # Stored submission files
└── templates/
    ├── base.html            # Shared layout with sidebar
    ├── login.html           # Authentication page
    ├── register.html        # Registration page
    ├── student_dashboard.html
    ├── guide_dashboard.html
    ├── upload.html          # File submission form
    ├── submission_detail.html  # Version timeline + review form
    ├── repository.html      # Searchable approved project archive
    ├── students.html        # Guide's student overview
    └── milestones.html      # Milestone management
```

---

## Database Schema

**users** — `id, name, email, password_hash, role (Student|Guide), guide_id (FK)`  
**submissions** — `id, student_id (FK), guide_id (FK), project_title, file_name, version_number, upload_date, teacher_feedback, status, description`  
**milestones** — `id, task_name, due_date, student_id (FK), completed`
