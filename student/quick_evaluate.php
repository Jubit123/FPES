<?php
require_once '../config.php';

// Quick evaluation entry point for QR codes
// Expected query params: faculty_id, subject_code (optional), subject_name (fallback)

$facultyId = isset($_GET['faculty_id']) ? (int)$_GET['faculty_id'] : 0;
$subjectCode = isset($_GET['subject_code']) ? trim($_GET['subject_code']) : '';
$subjectName = isset($_GET['subject_name']) ? trim($_GET['subject_name']) : '';

if ($facultyId <= 0 || ($subjectCode === '' && $subjectName === '')) {
    http_response_code(400);
    echo 'Invalid QR link. Required parameters are missing.';
    exit;
}

// If not logged in, remember target and send to login
if (!isLoggedIn()) {
    $_SESSION['quick_eval_target'] = [
        'faculty_id'   => $facultyId,
        'subject_code' => $subjectCode,
        'subject_name' => $subjectName,
    ];
    header('Location: ../index.php');
    exit;
}

// Must be a student to use this entry point
if (!hasRole('student')) {
    http_response_code(403);
    echo 'Only students can access this evaluation link.';
    exit;
}

// Check if evaluation period is open
list($evalOpen, $evalState, $evalReason, $evalSchedule) = isEvaluationOpenForStudents($pdo);
if (!$evalOpen) {
    echo 'Evaluations are currently closed. Please wait for the schedule to open.';
    exit;
}

$activePeriod = getActiveSemesterYear($pdo);

// Validate that this student is actually enrolled under this faculty and subject
try {
    $sql = "SELECT 
                sfs.subject_code,
                sfs.subject_name,
                fu.id AS faculty_user_id,
                f.id AS faculty_id
            FROM student_faculty_subjects sfs
            JOIN users fu ON fu.id = sfs.faculty_user_id AND fu.role = 'faculty'
            JOIN faculty f ON f.user_id = fu.id
            WHERE sfs.student_user_id = ?
              AND f.id = ?
              AND (
                    (sfs.subject_code IS NOT NULL AND sfs.subject_code <> '' AND sfs.subject_code = ?) 
                 OR (sfs.subject_code IS NULL OR sfs.subject_code = '') AND sfs.subject_name = ?
              )
            LIMIT 1";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([
        $_SESSION['user_id'],
        $facultyId,
        $subjectCode,
        $subjectName,
    ]);
    $row = $stmt->fetch();
} catch (PDOException $e) {
    $row = false;
}

if (!$row) {
    http_response_code(403);
    echo 'This evaluation link is not associated with your enrolled subjects.';
    exit;
}

// Store quick evaluation context in session for student dashboard
$_SESSION['quick_eval'] = [
    'faculty_id'   => (int)$row['faculty_id'],
    'subject_code' => (string)$row['subject_code'],
    'subject_name' => (string)$row['subject_name'],
    'semester'     => $activePeriod['semester'] ?? '',
    'academic_year'=> $activePeriod['academic_year'] ?? '',
];

// Clear original target (we now have a validated quick_eval)
unset($_SESSION['quick_eval_target']);

// Redirect to student dashboard; it will pre-select this evaluation
header('Location: student.php');
exit;
