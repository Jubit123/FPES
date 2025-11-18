<?php
require_once 'config.php';

$action = '';

// Check for both POST and GET logout requests
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $action = 'logout';
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
}

if ($action === 'login') {
    // For students, this field will contain the Student ID
    $username = sanitizeInput($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $role = sanitizeInput($_POST['role'] ?? '');
    
    // For admins, role selection is optional. Require role only for student/faculty/dean.
    if (empty($username) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Username and password are required']);
        exit();
    }
    
    try {
        // First try database authentication
        // Recognize Department Admin as a distinct login choice, but records remain role='admin' in DB
        $deptAdminList = ['Technology', 'Education', 'Business'];
        if ($role === 'student') {
            // Match by Student ID for students
            $stmt = $pdo->prepare("SELECT u.*, f.id as faculty_id, s.id as student_id 
                                   FROM users u 
                                   LEFT JOIN faculty f ON u.id = f.user_id 
                                   LEFT JOIN students s ON u.id = s.user_id 
                                   WHERE s.student_id = ? AND u.role = ?");
            $stmt->execute([$username, $role]);
        } elseif ($role === 'faculty') {
            // Employees (Faculty): match by Employee ID
            $stmt = $pdo->prepare("SELECT u.*, f.id as faculty_id, s.id as student_id 
                                   FROM users u 
                                   INNER JOIN faculty f ON u.id = f.user_id 
                                   LEFT JOIN students s ON u.id = s.user_id 
                                   WHERE f.employee_id = ? AND u.role = ?");
            $stmt->execute([$username, $role]);
        } elseif ($role === 'dean') {
            // Employees (Deans): match by Employee ID in deans table
            $stmt = $pdo->prepare("SELECT u.*, f.id as faculty_id, s.id as student_id 
                                   FROM users u 
                                   LEFT JOIN faculty f ON u.id = f.user_id 
                                   LEFT JOIN students s ON u.id = s.user_id 
                                   INNER JOIN deans d ON u.id = d.user_id 
                                   WHERE d.employee_id = ? AND u.role = ?");
            $stmt->execute([$username, $role]);
        } elseif ($role === 'department_admin') {
            // Department Admins are stored as role='admin' but must belong to an academic department
            $stmt = $pdo->prepare("SELECT u.*, f.id as faculty_id, s.id as student_id 
                                   FROM users u 
                                   LEFT JOIN faculty f ON u.id = f.user_id 
                                   LEFT JOIN students s ON u.id = s.user_id 
                                   WHERE u.username = ? AND u.role = 'admin' AND u.department IN ('Technology','Education','Business')");
            $stmt->execute([$username]);
        } else {
            // Admin path (role either 'admin' selected or omitted from form):
            // Allow both system admins and department admins to log in by username.
            $stmt = $pdo->prepare("SELECT u.*, f.id as faculty_id, s.id as student_id 
                                   FROM users u 
                                   LEFT JOIN faculty f ON u.id = f.user_id 
                                   LEFT JOIN students s ON u.id = s.user_id 
                                   WHERE u.username = ? AND u.role = 'admin'");
            $stmt->execute([$username]);
        }
        $user = $stmt->fetch();
        
        $authenticated = false;
        
        if ($user && password_verify($password, $user['password'])) {
            $authenticated = true;
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['department'] = $user['department'];
            
            // Store role-specific IDs
            if ($user['role'] === 'faculty') {
                $_SESSION['faculty_id'] = $user['faculty_id'];
            } elseif ($user['role'] === 'student') {
                $_SESSION['student_id'] = $user['student_id'];
            }
        }
        
        if ($authenticated) {
            // Track if user is required to change password
            $_SESSION['must_change_password'] = isset($user['must_change_password']) ? (int)$user['must_change_password'] : 0;
            $redirect = 'dashboard.php';
            // If a student scanned a quick evaluation QR before login, send them back into that flow
            if ($user['role'] === 'student' && !empty($_SESSION['quick_eval_target'])) {
                $redirect = 'student/quick_evaluate.php';
            }
            if (!empty($_SESSION['must_change_password'])) {
                $redirect = 'force_change_password.php';
            }
            // Normalize session role/flags for admins
            if ($user && $user['role'] === 'admin') {
                $_SESSION['role'] = 'admin';
                $deptAdminDepts = ['Technology','Education','Business'];
                if (!empty($user['department']) && in_array($user['department'], $deptAdminDepts)) {
                    $_SESSION['is_department_admin'] = 1;
                } else {
                    unset($_SESSION['is_department_admin']);
                }
            } else {
                // Non-admin users
                if ($role === 'department_admin') {
                    // Legacy path when the form explicitly posts department_admin
                    $_SESSION['role'] = 'admin';
                    $_SESSION['is_department_admin'] = 1;
                } elseif (empty($role)) {
                    // New path when role is empty (admin login by username)
                    $stmt = $pdo->prepare("SELECT u.* 
                                   FROM users u 
                                   WHERE u.username = ? AND u.role = 'admin'");
                    $stmt->execute([$username]);
                    $user = $stmt->fetch();
                    if ($user) {
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['username'] = $user['username'];
                        $_SESSION['role'] = $user['role'];
                        $_SESSION['full_name'] = $user['full_name'];
                        $_SESSION['department'] = $user['department'];
                        $_SESSION['must_change_password'] = isset($user['must_change_password']) ? (int)$user['must_change_password'] : 0;
                        $deptAdminDepts = ['Technology','Education','Business'];
                        if (!empty($user['department']) && in_array($user['department'], $deptAdminDepts)) {
                            $_SESSION['is_department_admin'] = 1;
                        } else {
                            unset($_SESSION['is_department_admin']);
                        }
                    }
                } else {
                    unset($_SESSION['is_department_admin']);
                }
            }
            echo json_encode([
                'success' => true, 
                'message' => 'Login successful',
                'redirect' => $redirect
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Invalid credentials']);
        }
    } catch (PDOException $e) {
        // Log the actual database error server-side for debugging (not shown to users)
        error_log('AUTH PDO ERROR: ' . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Database error']);
    }
    exit();
}

if ($action === 'logout') {
    // Fully clear session
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, 
            $params['path'], 
            $params['domain'], 
            $params['secure'], 
            $params['httponly']
        );
    }
    session_destroy();
    
    // Handle AJAX and non-AJAX requests
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        // AJAX request - send JSON response
        header('Content-Type: application/json');
        echo json_encode(['success' => true, 'redirect' => 'index.php']);
    } else {
        // Regular request - redirect directly
        header('Location: index.php');
    }
    exit();
}

// If not POST request, redirect to login
header('Location: index.php');
exit();
?>
