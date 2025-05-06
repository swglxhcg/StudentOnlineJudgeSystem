<?php
// 开启会话
session_start();

// 检查用户是否已登录且是管理员
if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_role']) || $_SESSION['user_role'] !== 'admin') {
    header('Location: /index.php');
    exit();
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>日志查看</title>
</head>
<body>
    <h2>日志查看</h2>
    <p>当前登录用户ID: <?php echo htmlspecialchars($_SESSION['user_id']); ?></p>
    <p>这里是日志查看页面内容</p>
</body>
</html>