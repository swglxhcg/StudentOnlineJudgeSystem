<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>在线评测系统登录</title>
    <!-- 引入Bootstrap CSS -->
    <link href="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/3.4.1/css/bootstrap.min.css" rel="stylesheet">
    <!-- 引入jQuery -->
    <script src="https://apps.bdimg.com/libs/jquery/2.1.4/jquery.min.js"></script>
    <style>
        body {
            background-color: #f8f9fa;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            text-align: center;
            max-width: 400px;
            width: 100%;
        }
        .btn-login {
            width: 100%;
            padding: 12px;
            margin-bottom: 15px;
            font-size: 18px;
            border-radius: 5px;
            transition: all 0.3s;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <button id="teacher-login-btn" class="btn btn-primary btn-login" onclick="window.location.href='login.php'">教师登录</button>
            <button id="student-login-btn" class="btn btn-primary btn-login" onclick="window.location.href='student_login.html'">学生登录</button>
    </div>

    
</body>
</html>