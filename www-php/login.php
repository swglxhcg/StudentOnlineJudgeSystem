<?php
// 开启会话
session_start();

// 如果用户已登录，则重定向到对应页面
if (isset($_SESSION['user_id']) && isset($_SESSION['user_role'])) {
    if ($_SESSION['user_role'] === 'admin') {
        header('Location: /admin_dashboard.php');
    } else {
        header('Location: /teacher_dashboard.php');
    }
    exit();
}

// 处理登录请求

?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>教师登录</title>
    <!-- 引入Bootstrap CSS -->
    <link href="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/3.4.1/css/bootstrap.min.css" rel="stylesheet">
    <!-- 引入jQuery -->
    <script src="https://apps.bdimg.com/libs/jquery/2.1.4/jquery.min.js"></script>
    <!-- 引入MD5库 -->
    <script src="https://cdn.bootcdn.net/ajax/libs/blueimp-md5/2.19.0/js/md5.min.js"></script>
    <style>
        body {
            background-color: #f8f9fa;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-box {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        .form-control {
            margin-bottom: 20px;
            border-radius: 5px;
            transition: all 0.3s;
        }
        .form-control:focus {
            border-color: #66afe9;
            box-shadow: 0 0 8px rgba(102,175,233,0.6);
        }
        .btn-login {
            width: 100%;
            padding: 12px;
            font-size: 18px;
            border-radius: 5px;
        }
        .back-link {
            display: block;
            text-align: center;
            margin-top: 15px;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2 class="text-center mb-4">教师登录</h2>
        <form id="login-form">
            <?php if (isset($error)): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <div class="form-group">
                <input type="text" class="form-control" name="username" placeholder="账号" required>
            </div>
            <div class="form-group">
                <input type="password" class="form-control" name="password" placeholder="密码" required>
            </div>
            <button type="submit" class="btn btn-primary btn-login">登录</button>
            <a href="index.php" class="back-link">返回首页</a>
        </form>
    </div>

    <!-- 引入Bootstrap JS和Popper.js -->
    <script src="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/3.4.1/js/bootstrap.min.js"></script>
    <script>
        $(document).ready(function() {
            $('#login-form').submit(function(e) {
                e.preventDefault();
                
                const username = $('input[name="username"]').val();
                const password = $('input[name="password"]').val();
                const password_md5 = md5(password);
                
                $.ajax({
                    url: 'http://localhost:5000/login',
                    type: 'POST',
                    contentType: 'application/json',
                    data: JSON.stringify({
                        username: username,
                        password_md5: password_md5
                    }),
                    success: function(response) {
                        if (response.status === 200) {
                            $('.alert-danger').remove();
                            $('#login-form').prepend('<div class="alert alert-success">' + response.message + '</div>');
                            // 存储JWT token到localStorage
                            localStorage.setItem('jwt_token', response.token);
                            
                            // 根据用户角色跳转到不同页面
                            if (response.role === 'admin') {
                                window.location.href = '/admin_dashboard.php';
                            } else {
                                window.location.href = '/teacher_dashboard.php';
                            }
                        } else {
                            $('.alert-danger').remove();
                            $('#login-form').prepend('<div class="alert alert-danger">' + response.message + '</div>');
                        }
                    },
                    error: function() {
                        // 处理请求失败的情况
                        if (response.message!==null) {
                            $('.alert-danger').remove();
                            $('#login-form').prepend('<div class="alert alert-danger">' + response.message + '</div>');
                        }else{
                            $('.alert-danger').remove();
                            $('#login-form').prepend('<div class="alert alert-danger">登录请求失败，请稍后重试</div>');
                        }
                    }
                });
            });
        });
    </script>
</body>
</html>