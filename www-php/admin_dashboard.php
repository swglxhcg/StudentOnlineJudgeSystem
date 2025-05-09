<?php
// 开启会话
session_start();

// 检查用户是否已登录
if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_role']) || $_SESSION['user_role'] !== 'admin') {
    header('Location: /index.php');
    exit();
}

// 获取用户信息
$user_id = $_SESSION['user_id'];
$user_role = $_SESSION['user_role'];
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理员面板</title>
    <!-- 引入Bootstrap CSS -->
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <!-- 引入jQuery -->
    <script src="script/jquery.min.js"></script>
    <style>
        body {
            font-family: 'Microsoft YaHei', sans-serif;
            margin: 0;
            padding: 0;
        }
        .sidebar {
            width: 250px;
            height: 100vh;
            background-color: #343a40;
            color: white;
            position: fixed;
            padding-top: 20px;
        }
        .main-content {
            margin-left: 250px;
            padding: 20px;
        }
        .sidebar-menu {
            list-style: none;
            padding: 0;
        }
        .sidebar-menu li a {
            display: block;
            color: white;
            padding: 10px 15px;
            text-decoration: none;
        }
        .sidebar-menu li a:hover {
            background-color: #495057;
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <h3 style="padding: 0 15px;">管理员面板</h3>
        <ul class="sidebar-menu">
            <li><a href="admin_pages/user_management.php">用户管理</a></li>
            <li><a href="admin_pages/system_settings.php">系统设置</a></li>
            <li><a href="admin_pages/log_view.php">日志查看</a></li>
            <li><a href="logout.php">退出登录</a></li>
        </ul>
    </div>

    <div class="main-content">
        <h1>欢迎使用管理员面板</h1>
        <p>当前登录用户ID: <?php echo htmlspecialchars($user_id); ?></p>
        <p>这里是管理员专用仪表盘，您可以管理整个系统。</p>
    </div>

    <!-- 引入Bootstrap JS和Popper.js -->
    <script src="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/3.4.1/js/bootstrap.min.js"></script>
</body>
</html>