-- 在线评测系统数据库结构
-- 创建数据库
CREATE DATABASE IF NOT EXISTS ojs_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE ojs_db;

-- 1. 用户表
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '用户ID',
    username VARCHAR(50) NOT NULL UNIQUE COMMENT '账号名称，只允许数字和字母',
    password VARCHAR(255) NOT NULL COMMENT '加盐哈希后的密码',
    user_type ENUM('admin', 'teacher') NOT NULL COMMENT '用户类型：admin-管理员，teacher-教师',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
) COMMENT '系统用户表';

-- 2. 小组表
CREATE TABLE IF NOT EXISTS student_groups (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '小组ID',
    group_name VARCHAR(100) NOT NULL COMMENT '小组名称',
    leader_name VARCHAR(50) NOT NULL COMMENT '组长姓名',
    members TEXT COMMENT '成员信息，存储为逗号分隔的字符串',
    created_at TIMESTAMP DEFAULT '2025-01-01 00:00:00' COMMENT '创建时间'
) COMMENT '学生小组表';

-- 3. 课程表
CREATE TABLE IF NOT EXISTS courses (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '课程ID',
    course_name VARCHAR(100) NOT NULL COMMENT '课程名称',
    created_at TIMESTAMP DEFAULT '2025-01-01 00:00:00' COMMENT '创建时间'
) COMMENT '课程表';

-- 4. 课程-任务点表
CREATE TABLE IF NOT EXISTS course_tasks (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '任务点ID',
    course_id INT NOT NULL COMMENT '所属课程ID',
    task_name LONGTEXT NOT NULL COMMENT '任务点名称',
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
) COMMENT '课程任务点表';

-- 5. 任务点-小组提交记录表
CREATE TABLE IF NOT EXISTS task_submissions (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '提交记录ID',
    task_id INT NOT NULL COMMENT '任务点ID',
    group_id INT NOT NULL COMMENT '提交小组ID',
    content LONGTEXT COMMENT '提交内容，包含文本和图片(格式:<|BASE:xxxxx|>)',
    submitted_at TIMESTAMP DEFAULT '2025-01-01 00:00:00' COMMENT '提交时间',
    FOREIGN KEY (task_id) REFERENCES course_tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES student_groups(id) ON DELETE CASCADE
) COMMENT '任务点提交表';

-- 6. 任务点-评分点表
CREATE TABLE IF NOT EXISTS task_criteria (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '评分点ID',
    task_id INT NOT NULL COMMENT '所属任务点ID',
    criteria_name VARCHAR(100) NOT NULL COMMENT '评分点名称',
    criteria_description TEXT COMMENT '评分标准说明',
    evaluated_at TIMESTAMP DEFAULT '2025-01-01 00:00:00' COMMENT '评分时间',
    FOREIGN KEY (task_id) REFERENCES course_tasks(id) ON DELETE CASCADE
) COMMENT '任务评分标准表';

-- 7. 小组评分记录表
CREATE TABLE IF NOT EXISTS peer_evaluations (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '评分记录ID',
    evaluator_group_id INT NOT NULL COMMENT '评分小组ID',
    evaluated_group_id INT NOT NULL COMMENT '被评分小组ID',
    criteria_id INT NOT NULL COMMENT '评分标准ID',
    score TINYINT NOT NULL CHECK (score BETWEEN 0 AND 5) COMMENT '评分分值(0-5)',
    evaluated_at TIMESTAMP DEFAULT '2025-01-01 00:00:00' COMMENT '评分时间',
    FOREIGN KEY (evaluator_group_id) REFERENCES student_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (evaluated_group_id) REFERENCES student_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (criteria_id) REFERENCES task_criteria(id) ON DELETE CASCADE
) COMMENT '小组互评记录表';

-- 8. 教师评分记录表
CREATE TABLE IF NOT EXISTS teacher_evaluations (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '评分记录ID',
    evaluated_group_id INT NOT NULL COMMENT '被评分小组ID',
    criteria_id INT NOT NULL COMMENT '评分标准ID',
    score TINYINT NOT NULL CHECK (score BETWEEN 0 AND 5) COMMENT '评分分值(0-5)',
    evaluated_at TIMESTAMP DEFAULT '2025-01-01 00:00:00' COMMENT '评分时间',
    FOREIGN KEY (evaluated_group_id) REFERENCES student_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (criteria_id) REFERENCES task_criteria(id) ON DELETE CASCADE
) COMMENT '教师评分记录表';

-- 9. 任务点描述表
CREATE TABLE IF NOT EXISTS task_descriptions (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '描述ID',
    task_id INT NOT NULL COMMENT '所属任务点ID',
    description LONGTEXT NOT NULL COMMENT '任务描述内容',
    FOREIGN KEY (task_id) REFERENCES course_tasks(id) ON DELETE CASCADE
) COMMENT '任务点描述表';

-- 10. 运行时变量表
CREATE TABLE IF NOT EXISTS runtime_variables (
    id INT AUTO_INCREMENT PRIMARY KEY COMMENT '变量ID',
    variable_name VARCHAR(50) NOT NULL UNIQUE COMMENT '变量名称',
    variable_value TEXT COMMENT '变量值',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
) COMMENT '运行时变量表';

-- 添加管理员用户
INSERT INTO users (username, password, user_type) VALUES ('admin', 'b80aff3d57efbee868148955a524951c1bc56956b3bbb6a83c66b57149055420', 'admin') ON DUPLICATE KEY UPDATE password = 'b80aff3d57efbee868148955a524951c1bc56956b3bbb6a83c66b57149055420';