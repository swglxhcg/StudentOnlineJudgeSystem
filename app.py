from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS, cross_origin
from datetime import timedelta
import pymysql
import hashlib
import json
import re
from ct_logger import CtLogger, RichCtLogger
from flask_jwt_extended import decode_token
import os
import uuid
from werkzeug.utils import secure_filename
from PIL import Image
import io

# 创建全局日志记录器
logger = RichCtLogger('ojs_app')

app = Flask(__name__, static_folder='www-html')
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

app.config['JWT_SECRET_KEY'] = 'chzt'  # 生产环境请使用更安全的密钥
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=5)
jwt = JWTManager(app)

# 数据库连接配置
db_config = {
    'host': 'localhost',
    'user': 'ojs_root',
    'password': '123456',
    'database': 'ojs_db',
    'charset': 'utf8mb4'
}

def get_db_connection():
    """获取数据库连接"""
    return pymysql.connect(**db_config)

def hash_password(password_md5, salt='random_salt'):
    """对MD5加密后的密码进行加盐哈希"""
    return hashlib.pbkdf2_hmac('sha256', password_md5.encode(), salt.encode(), 100000).hex()

#======================== 功能API 路由 ==============================

# 图片上传接口
@app.route('/image/upload', methods=['POST'])
@jwt_required()
def upload_image():
    """
    图片上传接口
    返回: {status: 状态码, message: 消息, path: 图片路径(成功时)}
    """
    if 'file' not in request.files:
        return jsonify({'status': 400, 'message': '没有上传文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 400, 'message': '没有选择文件'}), 400
    
    if file and allowed_file(file.filename):
        # 检查文件大小 (2MB = 2 * 1024 * 1024 bytes)
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > 2 * 1024 * 1024:
            logger.info(f"图片大小超过2MB: {file_size} bytes")
            try:
                
                # 读取图片
                img = Image.open(file.stream)
                # 计算压缩比例 (目标大小2MB)
                quality = int((2 * 1024 * 1024) / file_size * 100)
                quality = max(10, min(90, quality))  # 限制在10-90质量范围
                
                # 压缩图片
                output = io.BytesIO()
                if img.format == 'JPEG':
                    img.save(output, format='JPEG', quality=quality, optimize=True)
                else:
                    img.save(output, format=img.format, quality=quality)
                
                file.stream = output
                file.seek(0)
            except Exception as e:
                logger.error(f"图片压缩失败: {str(e)}")
                return jsonify({'status': 400, 'message': '图片压缩失败'}), 400
        
        # 生成唯一文件名
        filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex}_{filename}"
        
        # 如果没有扩展名，添加.jpg
        if not unique_name.endswith(('.png', '.jpg', '.jpeg', '.gif')):
            unique_name += '.png'
        
        logger.info(f"图片上传: {filename} -> {unique_name}")
        
        # 确保上传目录存在
        upload_folder = os.path.join(app.root_path, 'static', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)
        
        # 检查文件是否已存在
        while os.path.exists(os.path.join(upload_folder, unique_name)):
            unique_name = f"{uuid.uuid4().hex}_{filename}"
            logger.info(f"文件名冲突，生成新文件名: {unique_name}")
        
        # 保存文件
        file_path = os.path.join(upload_folder, unique_name)
        file.save(file_path)
        logger.info(f"图片保存成功: {file_path}")
        
        # 返回相对路径
        relative_path = f"/static/uploads/{unique_name}"
        return jsonify({
            'status': 200,
            'message': '上传成功',
            'path': relative_path
        }), 200
    
    return jsonify({'status': 400, 'message': '不支持的文件类型'}), 400

def allowed_file(filename):
    """检查文件扩展名是否允许"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 运行时变量设置接口
@app.route('/set_var', methods=['POST'])
def set_var():
    """
    设置运行时变量接口
    参数: {name: 变量名, value: 变量值}
    返回: {status: 状态码, message: 消息}
    """
    data = request.get_json()
    name = data.get('name')
    value = data.get('value')
    if not name or not value:
        return jsonify({'status': 400,'message': '缺少name或value参数'}), 400
    logger.info(f"设置运行时变量: {name} = {value}")
    # 操作数据库runtime_variables的variable_name和variable_value字段
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO runtime_variables (variable_name, variable_value) VALUES (%s, %s) ON DUPLICATE KEY UPDATE variable_value = %s', (name, value, value))
        conn.commit()
        return jsonify({'status': 200,'message': '变量设置成功'}), 200
    except Exception as e:
        logger.error(f"变量设置失败: {str(e)}")
        return jsonify({'status': 500,'message': '变量设置失败'}), 500
    finally:
        if conn:
            conn.close()

# 当前课程号设置接口
@app.route('/set_course_id', methods=['GET'])
def set_course_id():
    """
    设置当前课程号接口
    url参数: course_id
    返回: {status: 状态码, message: 消息}
    """
    course_id = request.args.get('course_id')
    if not course_id:
        return jsonify({'status': 400,'message': '缺少course_id参数'}), 400
    logger.info(f"设置当前课程号: {course_id}")
    # 操作数据库runtime_variables的variable_name和variable_value字段
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO runtime_variables (variable_name, variable_value) VALUES (%s, %s) ON DUPLICATE KEY UPDATE variable_value = %s', ('CURRENT_CLASS_ID', course_id, course_id))
        conn.commit()
        return jsonify({'status': 200,'message': '课程号设置成功'}), 200
    except Exception as e:
        logger.error(f"课程号设置失败: {str(e)}")
        return jsonify({'status': 500,'message': '课程号设置失败'}), 500
    finally:
        if conn:
            conn.close()

# JWT认证接口
@app.route('/jwt_auth', methods=['GET', 'OPTIONS'])
def jwt_auth():
    """
    JWT认证接口
    参数: {token: JWT令牌}
    返回: {status: 状态码, message: 消息, data: token数据(成功时)}
    """
    if request.method == 'OPTIONS':
        return jsonify({'status': 200,'message': 'OPTIONS请求成功'}), 200
    token = request.args.get('token') or (request.json and request.json.get('token'))
    if not token:
        return jsonify({'status': 401,'message': '缺少token参数'}), 401
    logger.info(f"收到JWT认证请求，token: {token}")
    # 刷新token
    try:
        decoded_token = decode_token(token)
        logger.info(f"解码后的token: {decoded_token}")
        return jsonify({'status': 200,'message': 'token有效','data': decoded_token}), 200
    except Exception as e:
        logger.error(f"token解码失败: {str(e)}")
        return jsonify({'status': 401,'message': 'token无效'}), 401

# 登录接口
@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    """
    用户登录接口
    参数: username, password_md5
    返回: {status: 状态码, message: 消息或用户信息}
    """
    if request.method == 'OPTIONS':
        return jsonify({'status': 200}), 200
    data = request.get_json()
    username = data.get('username')
    password_md5 = data.get('password_md5')
    
    logger.info(f"收到登录请求，用户名: {username}")

    # 验证参数完整性
    if not username or not password_md5:
        logger.warning("登录失败: 用户名或密码为空")
        return jsonify({'status': 400, 'message': '用户名和密码不能为空'}), 400
        
    # 验证用户名格式
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        logger.warning(f"登录失败: 用户名格式错误 - {username}")
        return jsonify({'status': 400, 'message': '用户名只能包含字母和数字'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()

        if not user:
            logger.warning(f"登录失败: 用户名不存在 - {username}")
            return jsonify({'status': 401, 'message': '用户名或密码错误'}), 401

        # 验证密码
        hashed_password = hash_password(password_md5)
        if hashed_password != user['password']:
            logger.warning(f"登录失败: 密码错误 - 用户名: {username}")
            return jsonify({'status': 401, 'message': '用户名或密码错误'}), 401
        
        logger.info(f"Database return : {user}")

        # 生成JWT令牌
        identity = {'id': user['id'], 'type': user['user_type']}
        identity_str = json.dumps(identity, separators=(',', ':'))
        access_token = create_access_token(identity=identity_str, expires_delta=timedelta(days=2))
        logger.info(f"登录成功:  \[{user['user_type']}\] 用户 {username} (ID: {user['id']}) 已登录")
        return jsonify({
            'status': 200,
            'message': {
                'token': access_token,
                'user_id': user['id'],
                'user_type': user['user_type']
            }
        }), 200

    except Exception as e:
        logger.error(f"登录过程中发生错误: {str(e)}")
        return jsonify({'status': 500, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

#=============================
# 用户管理接口
#=============================
@app.route('/users', methods=['POST', 'OPTIONS'])
@jwt_required()
def users():
    """
    用户管理接口
    参数: 
      - OPTIONS方法: 无参数
      - POST方法: {
          request_type: 请求类型(add/delete/update/search/get_all),
          request_data: 请求数据
        }
    返回: {status: 状态码, message: 消息, data: 数据(可选)}
    """
    current_user = get_jwt_identity()
    # logger.info(f"JWT身份: {current_user}")
    current_user = json.loads(current_user)
    if not isinstance(current_user, dict) or 'type' not in current_user:
        return jsonify({'status': 400, 'message': '无效的JWT主题格式'}), 400
    # 确保类型字段是字符串
    current_user['type'] = str(current_user['type'])
    if current_user['type'] != 'admin':
        return jsonify({'status': 403, 'message': '无权限操作'}), 403
    logger.info(f"收到用户管理请求: {request.method}")
    if request.method == 'OPTIONS':
        return jsonify({'status': 200}), 200

    # 解析请求数据
    data = request.get_json()
    if not data:
        return jsonify({'status': 400, 'message': '请求数据为空'}), 400
        
    # 验证请求数据格式
    request_type = data.get('request_type')
    request_data = data.get('request_data')
    
    if not request_type or not isinstance(request_type, str):
        return jsonify({'status': 422, 'message': '缺少或无效的request_type参数'}), 422
        
    if request_type != 'get_all' and (not request_data or not isinstance(request_data, dict)):
        return jsonify({'status': 422, 'message': '缺少或无效的request_data参数'}), 422
    
    if request_type == 'add':
        # 添加用户
        return add_user(request_data)
    elif request_type == 'delete':
        # 删除用户
        return delete_user(request_data)
    elif request_type == 'update':
        # 更新用户信息
        return update_user(request_data)
    elif request_type == 'search':
        # 获取用户信息
        return search_user(request_data)
    elif request_type == 'get_all':
        # 获取所有用户信息
        return get_all_users()
    elif request_type == 'update_type':
        # 更新用户类型
        return update_user_type(request_data)
    else:
        return jsonify({'status': 400,'message': '无效的请求类型'}), 400

def get_all_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()
        # 去除password字段
        for user in users:
            user.pop('password', None)
        return jsonify({'status': 200, 'message':"获取成功", 'data': users}), 200
    except Exception as e:
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def search_user(request_data):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        user_id = request_data.get('user_id')
        if user_id:
            cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
            user = cursor.fetchone()
            if user:
                return jsonify({'status': 200,'message':"获取成功", 'data': user}), 200
            else:
                return jsonify({'status': 404,'message': "用户不存在"}), 404
        else:
            return jsonify({'status': 400,'message': "缺少必要参数"}), 400
    except Exception as e:
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def add_user(request_data):
    # 解析请求体中的JSON数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400

    username = request_data.get('username')
    password_md5 = request_data.get('password_md5')
    user_type_num = request_data.get('user_type')

    # 验证参数
    if not all([username, password_md5, user_type_num]):
        return jsonify({'status': 400, 'message': '缺少必要参数'}), 400

    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return jsonify({'status': 400, 'message': '用户名只能包含字母和数字'}), 400

    user_type = 'teacher' if (user_type_num == 1 or user_type_num == '1' or user_type_num == 'teacher') else 'admin'
    hashed_password = hash_password(password_md5)

    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        
        # 检查用户名是否已存在
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({'status': 400, 'message': '用户名已存在'}), 400
            
        cursor.execute(
            'INSERT INTO users (username, password, user_type) VALUES (%s, %s, %s)',
            (username, hashed_password, user_type)
        )
        conn.commit()
        return jsonify({'status': 200, 'message': '用户添加成功'}), 200

    except pymysql.err.IntegrityError:
        return jsonify({'status': 400, 'message': '用户名已存在'}), 400
    except Exception as e:
        return jsonify({'status': 500, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def delete_user(request_data):
    # 解析请求体中的JSON数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400

    user_id = request_data.get('user_id')
    # 验证参数
    if not user_id:
        return jsonify({'status': 400,'message': '缺少必要参数'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        return jsonify({'status': 200,'message': '用户删除成功'}), 200

    except Exception as e:
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def update_user(request_data):
    # 解析请求体中的JSON数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400

    user_id = request_data.get('user_id')
    username = request_data.get('username')
    password_md5 = request_data.get('password_md5')
    user_type_num = request_data.get('user_type')

    # 验证参数
    if not all([user_id, password_md5, user_type_num]):
        return jsonify({'status': 400,'message': '缺少必要参数'}), 400

    # if not re.match(r'^[a-zA-Z0-9]+$', username):
    #     return jsonify({'status': 400,'message': '用户名只能包含字母和数字'}), 400

    user_type = 'teacher' if (user_type_num == 1 or user_type_num == '1' or user_type_num == 'teacher') else 'admin'
    hashed_password = hash_password(password_md5)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET password = %s, user_type = %s WHERE id = %s',
            (hashed_password, user_type, user_id)
        )
        conn.commit()
        return jsonify({'status': 200,'message': '用户信息更新成功'}), 200

    except Exception as e:
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def update_user_type(request_data):
    # 解析请求体中的JSON数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400

    user_id = request_data.get('user_id')
    user_type_num = request_data.get('user_type')

    # 验证参数
    if not all([user_id, user_type_num]):
        return jsonify({'status': 400,'message': '缺少必要参数'}), 400

    user_type = 'teacher' if (user_type_num == 1 or user_type_num == '1' or user_type_num == 'teacher') else 'admin'

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET user_type = %s WHERE id = %s',
            (user_type, user_id)
        )
        conn.commit()
        return jsonify({'status': 200,'message': '用户类型更新成功'}), 200

    except Exception as e:
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

#=============================
# 小组管理接口
#=============================
@app.route('/groups', methods=['POST', 'OPTIONS'])
@jwt_required()
def groups():
    """
    小组管理接口
    参数: {request_type: 请求类型(add/delete/update/search/get_all), request_data: 请求数据}
    返回: {status: 状态码, message: 消息, data: 数据(可选)}
    """
    current_user = get_jwt_identity()
    # logger.info(f"JWT身份: {current_user}")
    current_user = json.loads(current_user)
    logger.info(f"JWT身份: {current_user}")
    if not isinstance(current_user, dict) or 'type' not in current_user:
        return jsonify({'status': 400,'message': '无效的JWT主题格式'}), 400
    # 确保类型字段是字符串
    current_user['type'] = str(current_user['type'])
    logger.info(f"JWT身份: {current_user['type']}")
    if current_user['type']!= 'admin' and current_user['type']!= 'teacher':
        return jsonify({'status': 403,'message': '无权限操作'}), 403
    logger.info(f"收到小组管理请求: {request.method}")
    if request.method == 'OPTIONS':
        return jsonify({'status': 200}), 200

    # 解析请求数据
    data = request.get_json()
    if not data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400

    # 验证请求数据格式
    request_type = data.get('request_type')
    request_data = data.get('request_data')
    if not request_type or not isinstance(request_type, str):
        return jsonify({'status': 422,'message': '缺少或无效的request_type参数'}), 422

    if request_type != 'get_all' and (not request_data or not isinstance(request_data, dict)):
        return jsonify({'status': 422,'message': '缺少或无效的request_data参数'}), 422

    if request_type == 'add':
        # 添加小组
        return add_group(request_data)
    elif request_type == 'delete':
        # 删除小组
        return delete_group(request_data)
    elif request_type == 'update':
        # 更新小组信息
        return update_group(request_data)
    elif request_type =='get':
        # 获取小组信息
        return get_group_info(request_data)
    elif request_type == 'get_all':
        # 获取所有小组信息
        return get_all_groups()
    else:
        return jsonify({'status': 400,'message': '无效的请求类型'}), 400

def get_all_groups():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT * FROM student_groups')
        groups = cursor.fetchall()
        # 将groups中的members字段转换为列表
        for group in groups:
            if group['members']:
                group['members'] = group['members'].split(',')
            else:
                group['members'] = []
            # 添加小组人数字段
            group['members_count'] = len(group['members'])
        return jsonify({'status': 200,'message':"获取成功", 'data': groups}), 200
    except Exception as e:
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def add_group(request_data):
    # 解析请求体中的JSON数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400

    group_name = request_data.get('group_name')
    members = request_data.get('members')
    leader_name = request_data.get('leader_name')
    # 验证参数
    if not all([group_name, members, leader_name]):
        return jsonify({'status': 400,'message': '缺少必要参数'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 检查小组名是否已存在
        cursor.execute('SELECT * FROM student_groups WHERE group_name = %s', (group_name,))
        existing_group = cursor.fetchone()
        if existing_group:
            return jsonify({'status': 400,'message': '小组名已存在'}), 400
        # Add groups
        cursor.execute(
            'INSERT INTO `student_groups` (group_name, members, leader_name) VALUES (%s, %s, %s)',
            (group_name, ','.join(members), leader_name)
        )
        conn.commit()
        return jsonify({'status': 200,'message': '小组添加成功'}), 200

    except pymysql.err.IntegrityError:
        return jsonify({'status': 400,'message': '小组名已存在'}), 400
    except Exception as e:
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def get_group_info(request_data):
    """
    获取单个小组信息
    :param request_data: 包含group_id的字典
    :return: 小组信息
    """
    group_id = request_data.get('group_id')
    if not group_id:
        return jsonify({'status': 422, 'message': '缺少group_id参数'}), 422
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT * FROM student_groups WHERE id = %s', (group_id,))
        group = cursor.fetchone()
        
        if not group:
            return jsonify({'status': 404, 'message': '小组不存在'}), 404
            
        return jsonify({
            'status': 200,
            'message': '获取小组信息成功',
            'data': {
                'id': group['id'],
                'group_name': group['group_name'],
                'leader_name': group['leader_name'],
                'members': group['members'].split(',') if group['members'] else []
            }
        }), 200
        
    except Exception as e:
        logger.error(f"获取小组信息出错: {str(e)}")
        return jsonify({'status': 500, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def update_group(request_data):
    """
    更新小组信息
    参数: request_data 包含小组ID、名称和组长信息、成员信息的字典
    返回: JSON响应，包含状态码和消息
    """
    # 验证请求数据
    if not request_data:
        return jsonify({'status': 400, 'message': '请求数据为空'}), 400
    
    group_id = request_data.get('group_id')
    group_name = request_data.get('group_name')
    leader_name = request_data.get('leader_name')
    members = request_data.get('members')
    
    # 验证必要参数
    if not all([group_id, group_name, leader_name, members]):
        return jsonify({'status': 400,'message': '缺少必要参数'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 检查小组是否存在
        cursor.execute('SELECT id FROM student_groups WHERE id = %s', (group_id,))
        if not cursor.fetchone():
            return jsonify({'status': 404, 'message': '小组不存在'}), 404
            
        # 更新小组信息
        cursor.execute(
            'UPDATE student_groups SET group_name = %s, leader_name = %s, members = %s WHERE id = %s',
            (group_name, leader_name, ','.join(members), group_id)
        )
        conn.commit()
        return jsonify({'status': 200, 'message': '小组更新成功'}), 200
        
    except Exception as e:
        logger.error(f"更新小组出错: {str(e)}")
        return jsonify({'status': 500, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def delete_group(request_data):
    """
    删除小组
    参数: request_data 包含小组ID的字典
    返回: JSON响应，包含状态码和消息
    """
    # 验证请求数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400

    group_id = request_data.get('group_id')
    if not group_id:
        return jsonify({'status': 422,'message': '缺少group_id参数'}), 422

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 检查小组是否存在
        cursor.execute('SELECT id FROM student_groups WHERE id = %s', (group_id,))
        if not cursor.fetchone():
            return jsonify({'status': 404,'message': '小组不存在'}), 404
        # 删除小组
        cursor.execute('DELETE FROM student_groups WHERE id = %s', (group_id,))
        conn.commit()
        return jsonify({'status': 200,'message': '小组删除成功'}), 200
    except Exception as e:
        logger.error(f"删除小组出错: {str(e)}")
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

#=============================
# 课程管理接口
#=============================
@app.route('/courses', methods=['POST', 'OPTIONS'])
@jwt_required()
def courses():
    """
    课程管理接口
    参数: {request_type: 请求类型(add/delete/update/get/get_all), request_data: 请求数据}
    返回: {status: 状态码, message: 消息, data: 数据(可选)}
    """
    current_user = get_jwt_identity()
    # logger.info(f"JWT身份: {current_user}")
    current_user = json.loads(current_user)
    logger.info(f"JWT身份: {current_user}")
    if not isinstance(current_user, dict) or 'type' not in current_user:
        return jsonify({'status': 400,'message': '无效的JWT主题格式'}), 400
    # 确保类型字段是字符串
    current_user['type'] = str(current_user['type'])
    logger.info(f"JWT身份: {current_user['type']}")
    if current_user['type']!= 'admin' and current_user['type']!= 'teacher':
        return jsonify({'status': 403,'message': '无权限操作'}), 403
    logger.info(f"收到课程管理请求: {request.method}")
    if request.method == 'OPTIONS':
        return jsonify({'status': 200}), 200
    # 解析请求数据
    data = request.get_json()
    if not data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400

    # 验证请求数据格式
    request_type = data.get('request_type')
    request_data = data.get('request_data')
    if not request_type or not isinstance(request_type, str):
        return jsonify({'status': 422,'message': '缺少或无效的request_type参数'}), 422

    if request_type!= 'get_all' and (not request_data or not isinstance(request_data, dict)):
        return jsonify({'status': 422,'message': '缺少或无效的request_data参数'}), 422

    if request_type == 'add':
        # 添加课程
        return add_course(request_data)
    elif request_type == 'delete':
        # 删除课程
        return delete_course(request_data)
    elif request_type == 'update':
        # 更新课程信息
        return update_course(request_data)
    elif request_type =='get':
        # 获取课程信息
        return get_course_info(request_data)
    elif request_type == 'get_all':
        # 获取所有课程信息
        return get_all_courses()
    else:
        return jsonify({'status': 400,'message': '无效的请求类型'}), 400

def get_all_courses():
    """
    获取所有课程信息
    对于每一条课程信息，获取其对应的课程名字、测试点个数
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT * FROM courses')
        courses = cursor.fetchall()
        # 对于每一条课程信息，获取其对应的课程名字courses.course_name、测试点个数（匹配course_tasks.course_id）
        for course in courses:
            cursor.execute('SELECT COUNT(*) AS tmp_test_points FROM course_tasks WHERE course_id = %s', (course['id'],))
            test_points = cursor.fetchone()['tmp_test_points']
            course['tasks_count'] = test_points
        return jsonify({'status': 200,'message':"获取成功", 'data': courses}), 200
    except Exception as e:
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def add_course(request_data):
    """
    添加课程
    参数: request_data 包含课程名称的字典
    返回: JSON响应，包含状态码和消息
    """
    # 验证请求数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400
    course_name = request_data.get('course_name')
    if not course_name:
        return jsonify({'status': 422,'message': '缺少course_name参数'}), 422
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 检查课程是否已存在
        cursor.execute('SELECT id FROM courses WHERE course_name = %s', (course_name,))
        if cursor.fetchone():
            return jsonify({'status': 400,'message': '课程已存在'}), 400
        # 添加课程
        cursor.execute('INSERT INTO courses (course_name) VALUES (%s)', (course_name,))
        conn.commit()
        return jsonify({'status': 200,'message': '课程添加成功'}), 200
    except Exception as e:
        logger.error(f"添加课程出错: {str(e)}")
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def get_course_info(request_data):
    """
    获取课程信息
    参数: request_data 包含课程ID的字典
    返回: JSON响应，包含状态码和消息
    """
    # 验证请求数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400
    course_id = request_data.get('course_id')
    if not course_id:
        return jsonify({'status': 422,'message': '缺少course_id参数'}), 422
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        # 获取课程信息
        cursor.execute('SELECT * FROM courses WHERE id = %s', (course_id,))
        course = cursor.fetchone()
        if not course:
            return jsonify({'status': 404,'message': '课程不存在'}), 404
        # 获取课程对应的测试点信息
        cursor.execute('SELECT * FROM course_tasks WHERE course_id = %s', (course_id,))
        tasks = cursor.fetchall()
        return jsonify({
            'status': 200,
            'message': '获取课程信息成功',
            'data': {
                'course': course,
                'tasks': tasks
            }
        }), 200
    except Exception as e:
        logger.error(f"获取课程信息出错: {str(e)}")

def update_course(request_data):
    """
    更新课程信息
    参数: request_data 包含课程ID、名称的字典
    返回: JSON响应，包含状态码和消息
    """
    # 验证请求数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400
    course_id = request_data.get('course_id')
    course_name = request_data.get('course_name')
    if not all([course_id, course_name]):
        return jsonify({'status': 422,'message': '缺少必要参数'}), 422
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 检查课程是否存在
        cursor.execute('SELECT id FROM courses WHERE id = %s', (course_id,))
        if not cursor.fetchone():
            return jsonify({'status': 404,'message': '课程不存在'}), 404
        # 更新课程信息
        cursor.execute('UPDATE courses SET course_name = %s WHERE id = %s', (course_name, course_id))
        conn.commit()
        return jsonify({'status': 200,'message': '课程更新成功'}), 200
    except Exception as e:
        logger.error(f"更新课程出错: {str(e)}")
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def delete_course(request_data):
    """
    删除课程
    参数: request_data 包含课程ID的字典
    返回: JSON响应，包含状态码和消息
    """
    # 验证请求数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400
    course_id = request_data.get('course_id')
    if not course_id:
        return jsonify({'status': 422,'message': '缺少course_id参数'}), 422
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 检查课程是否存在
        cursor.execute('SELECT id FROM courses WHERE id = %s', (course_id,))
        if not cursor.fetchone():
            return jsonify({'status': 404,'message': '课程不存在'}), 404
        # 删除课程
        cursor.execute('DELETE FROM courses WHERE id = %s', (course_id,))
        conn.commit()
        return jsonify({'status': 200,'message': '课程删除成功'}), 200
    except Exception as e:
        logger.error(f"删除课程出错: {str(e)}")
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


#=============================
# 测试点管理接口
#=============================
@app.route('/course_tasks', methods=['POST', 'OPTIONS'])
@jwt_required()
def course_tasks():
    """
    测试点管理接口
    参数: {request_type: 请求类型(add/delete/update/get/get_all), request_data: 请求数据}
    返回: {status: 状态码, message: 消息, data: 数据(可选)}
    """
    current_user = get_jwt_identity()
    # logger.info(f"JWT身份: {current_user}")
    current_user = json.loads(current_user)
    logger.info(f"JWT身份: {current_user}")
    if not isinstance(current_user, dict) or 'type' not in current_user:
        return jsonify({'status': 400,'message': '无效的JWT主题格式'}), 400
    # 确保类型字段是字符串
    current_user['type'] = str(current_user['type'])
    logger.info(f"JWT身份: {current_user['type']}")
    if current_user['type']!= 'admin' and current_user['type']!= 'teacher':
        return jsonify({'status': 403,'message': '无权限操作'}), 403
    logger.info(f"收到测试点管理请求: {request.method}")
    if request.method == 'OPTIONS':
        return jsonify({'status': 200}), 200
    # 解析请求数据
    data = request.get_json()
    if not data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400

    # 验证请求数据格式
    request_type = data.get('request_type')
    request_data = data.get('request_data')
    if not request_type or not isinstance(request_type, str):
        return jsonify({'status': 422,'message': '缺少或无效的request_type参数'}), 422

    if request_type!= 'get_all' and (not request_data or not isinstance(request_data, dict)):
        return jsonify({'status': 422,'message': '缺少或无效的request_data参数'}), 422
    if request_type == 'add':
        # 添加测试点
        return add_course_task(request_data)
    elif request_type == 'delete':
        # 删除测试点
        return delete_course_task(request_data)
    elif request_type == 'update':
        # 更新测试点信息
        return update_course_task(request_data)
    elif request_type =='get':
        # 获取测试点信息
        return get_course_task_info(request_data)
    elif request_type == 'get_all':
        # 获取所有测试点信息
        return get_all_course_tasks()
    else:
        return jsonify({'status': 400,'message': '无效的请求类型'}), 400

def get_all_course_tasks():
    """
    获取所有测试点信息
    对于每一条测试点信息，获取其对应的课程名字、测试点名字
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT * FROM course_tasks')
        tasks = cursor.fetchall()
        # 对于每一条测试点信息，获取其对应的课程名字courses.course_name、测试点名字course_tasks.task_name
        for task in tasks:
            cursor.execute('SELECT course_name FROM courses WHERE id = %s', (task['course_id'],))
            course_name = cursor.fetchone()['course_name']
            task['course_name'] = course_name
        return jsonify({'status': 200,'message':"获取成功", 'data': {'tasks':tasks}}), 200
    except Exception as e:
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def add_course_task(request_data):
    """
    添加测试点
    参数: request_data 包含课程ID、测试点名称的字典
    返回: JSON响应，包含状态码和消息
    """
    # 验证请求数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400
    course_id = request_data.get('course_id')
    task_name = request_data.get('task_name')
    if not all([course_id, task_name]):
        return jsonify({'status': 422,'message': '缺少必要参数'}), 422
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 检查课程是否存在
        cursor.execute('SELECT id FROM courses WHERE id = %s', (course_id,))
        if not cursor.fetchone():
            return jsonify({'status': 404,'message': '课程不存在'}), 404
        # 检查测试点是否已存在
        cursor.execute('SELECT id FROM course_tasks WHERE course_id = %s AND task_name = %s', (course_id, task_name))
        if cursor.fetchone():
            return jsonify({'status': 400,'message': '测试点已存在'}), 400
        # 添加测试点 
        cursor.execute('INSERT INTO course_tasks (course_id, task_name) VALUES (%s, %s)', (course_id, task_name))
        conn.commit()
        return jsonify({'status': 200,'message': '测试点添加成功'}), 200
    except Exception as e:
        logger.error(f"添加测试点出错: {str(e)}")
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def delete_course_task(request_data):
    """
    删除测试点
    参数: request_data 包含测试点ID的字典
    返回: JSON响应，包含状态码和消息
    """
    # 验证请求数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400
    task_id = request_data.get('task_id')
    if not task_id:
        return jsonify({'status': 422,'message': '缺少task_id参数'}), 422
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 检查测试点是否存在
        cursor.execute('SELECT id FROM course_tasks WHERE id = %s', (task_id,))
        if not cursor.fetchone():
            return jsonify({'status': 404,'message': '测试点不存在'}), 404
        # 删除测试点
        cursor.execute('DELETE FROM course_tasks WHERE id = %s', (task_id,))
        conn.commit()
        return jsonify({'status': 200,'message': '测试点删除成功'}), 200
    except Exception as e:
        logger.error(f"删除测试点出错: {str(e)}")
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def get_course_task_info(request_data):
    """
    获取测试点信息
    参数: request_data 包含测试点ID的字典
    返回: JSON响应，包含状态码和消息
    """
    # 验证请求数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400
    task_id = request_data.get('task_id')
    if not task_id:
        return jsonify({'status': 422,'message': '缺少task_id参数'}), 422
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        # 获取测试点信息
        cursor.execute('SELECT * FROM course_tasks WHERE id = %s', (task_id,))
        task = cursor.fetchone()
        if not task:
            return jsonify({'status': 404,'message': '测试点不存在'}), 404
        # 获取测试点对应的课程名字
        cursor.execute('SELECT course_name FROM courses WHERE id = %s', (task['course_id'],))
        course_name = cursor.fetchone()['course_name']
        task['course_name'] = course_name
        # 获取测试点的评分点信息task_criteria.criteria_name、task_criteria.criteria_description通过task_criteria.task_id
        cursor.execute('SELECT criteria_name, criteria_description FROM task_criteria WHERE task_id = %s', (task_id,))
        criteria = cursor.fetchall()
        task['criterias'] = criteria
        
        ### 获取测试点的内容信息task_descriptions.description通过task_descriptions.task_id
        cursor.execute('SELECT description FROM task_descriptions WHERE task_id = %s', (task_id,))
        description = cursor.fetchone()
        task['description'] = description['description'] if description else ''
        return jsonify({
           'status': 200,
           'message': '获取测试点信息成功',
            'data': {
                'task': task
            }
        })
    except Exception as e:
        logger.error(f"获取测试点信息出错: {str(e)}")
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def update_course_task(request_data):
    """
    更新测试点信息
    参数: request_data 包含测试点ID、名称的字典
    返回: JSON响应，包含状态码和消息
    """
    # 验证请求数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400
    task_id = request_data.get('task_id')
    task_name = request_data.get('task_name')   # 测试点名称
    task_description = request_data.get('content')   # 测试点内容
    task_criterias = request_data.get('criterias')   # 测试点评分点信息
    
    if not all([task_id, task_name]):
        return jsonify({'status': 422,'message': '缺少必要参数'}), 422
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        ##### 更新测试点信息 #####
        # 检查测试点是否存在
        cursor.execute('SELECT id FROM course_tasks WHERE id = %s', (task_id,))
        if not cursor.fetchone():
            return jsonify({'status': 404,'message': '测试点不存在'}), 404
        # 更新测试点信息
        cursor.execute('UPDATE course_tasks SET task_name = %s WHERE id = %s', (task_name, task_id))
        conn.commit()
        
        ##### 更新测试点内容 #####
        # 检查测试点内容是否存在task_descriptions.task_id = task_id
        cursor.execute('SELECT id FROM task_descriptions WHERE task_id = %s', (task_id,))
        if cursor.fetchone():
            # 更新测试点内容
            cursor.execute('UPDATE task_descriptions SET description = %s WHERE task_id = %s', (task_description, task_id))
            conn.commit()
        else:
            # 添加测试点内容
            cursor.execute('INSERT INTO task_descriptions (task_id, description) VALUES (%s, %s)', (task_id, task_description))
            
        ##### 更新测试点评分点信息 #####
        # 检查测试点评分点信息是否存在task_criteria.task_id = task_id
        cursor.execute('SELECT id FROM task_criteria WHERE task_id = %s', (task_id,))
        if cursor.fetchone():
            # 更新测试点评分点信息
            for criteria in task_criterias:
                criteria_name = criteria.get('criteria_name')
                criteria_description = criteria.get('criteria_description')
                if not all([criteria_name,]):
                    return jsonify({'status': 422,'message': '缺少必要参数'}), 422
                # 检查测试点评分点信息是否存在
                cursor.execute('SELECT id FROM task_criteria WHERE task_id = %s AND criteria_name = %s', (task_id, criteria_name))
                if cursor.fetchone():
                    # 更新测试点评分点信息
                    cursor.execute('UPDATE task_criteria SET criteria_description = %s WHERE task_id = %s AND criteria_name = %s', (criteria_description, task_id, criteria_name))
                else:
                    # 添加测试点评分点信息
                    cursor.execute('INSERT INTO task_criteria (task_id, criteria_name, criteria_description) VALUES (%s, %s, %s)', (task_id, criteria_name, criteria_description))
            conn.commit()
        else:
            # 添加测试点评分点信息
            for criteria in task_criterias:
                criteria_name = criteria.get('criteria_name')
                criteria_description = criteria.get('criteria_description')
                if not all([criteria_name,]):
                    return jsonify({'status': 422,'message': '缺少必要参数'}), 422
                # 添加测试点评分点信息
                cursor.execute('INSERT INTO task_criteria (task_id, criteria_name, criteria_description) VALUES (%s, %s, %s)', (task_id, criteria_name, criteria_description))
            conn.commit()
        # 提交事务
        conn.commit()
        # 返回成功响应
        return jsonify({'status': 200,'message': '测试点更新成功'}), 200
    except Exception as e:
        logger.error(f"更新测试点出错: {str(e)}")
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

#=============================
# 评分接口
#=============================
@app.route('/score', methods=['POST', 'OPTIONS'])
def score():
    """
    评分接口
    参数: {request_type: 请求类型(teacher/student), request_data: 请求数据}
    返回: {status: 状态码, message: 消息, data: 数据(可选)}
    """
    logger.info(f"收到评分请求: {request.method}")
    if request.method == 'OPTIONS':
        return jsonify({'status': 200}), 200
    # 解析请求数据
    data = request.get_json()
    if not data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400
    # 验证请求数据格式
    request_type = data.get('request_type')
    request_data = data.get('request_data')
    if not request_type or not isinstance(request_type, str):
        return jsonify({'status': 422,'message': '缺少或无效的request_type参数'}), 422
    if request_type!= 'update' and (not request_data or not isinstance(request_data, dict)):
        return jsonify({'status': 422,'message': '缺少或无效的request_data参数'}), 422
    if request_type == 'student':
        # 更新评分
        return update_student_score(request_data)
    elif request_type == 'teacher':
        # 获取评分
        return update_teacher_score(request_data)
    else:
        return jsonify({'status': 400,'message': '无效的请求类型'}), 400

def update_student_score(request_data):
    """
    更新评分
    参数: request_data 包含评分组id、被评分组id、评分点id、分数的字典
    返回: JSON响应，包含状态码和消息
    """
    # 验证请求数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400
    score_group_id = request_data.get('score_group_id')
    scored_group_id = request_data.get('scored_group_id')
    score_point_id = request_data.get('score_point_id')
    score = request_data.get('score')
    if not all([score_group_id, scored_group_id, score_point_id, score]):
        return jsonify({'status': 422,'message': '缺少必要参数'}), 422
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 检查评分组是否存在
        cursor.execute('SELECT id FROM student_groups WHERE id = %s', (score_group_id,))
        if not cursor.fetchone():
            return jsonify({'status': 404,'message': '评分组不存在'}), 404
        # 检查被评分组是否存在
        cursor.execute('SELECT id FROM student_groups WHERE id = %s', (scored_group_id,))
        if not cursor.fetchone():
            return jsonify({'status': 404,'message': '被评分组不存在'}), 404
        # 检查评分点是否存在
        cursor.execute('SELECT id FROM task_criteria WHERE id = %s', (score_point_id,))
        if not cursor.fetchone():
            return jsonify({'status': 404,'message': '评分点不存在'}), 404
        # 检查评分是否存在
        cursor.execute('SELECT id FROM peer_evaluations WHERE evaluator_group_id = %s AND evaluated_group_id = %s AND criteria_id = %s', (score_group_id, scored_group_id, score_point_id))
        if not cursor.fetchone():
            logger.info(f"评分不存在，添加评分")
            # 添加评分
            cursor.execute('INSERT INTO peer_evaluations (evaluator_group_id, evaluated_group_id, criteria_id, score) VALUES (%s, %s, %s, %s)', (score_group_id, scored_group_id, score_point_id, score))
        else:
            logger.info(f"评分存在，更新评分")
            # 更新评分
            cursor.execute('UPDATE peer_evaluations SET score = %s WHERE evaluator_group_id = %s AND evaluated_group_id = %s AND criteria_id = %s', (score, score_group_id, scored_group_id, score_point_id))
        conn.commit()
        return jsonify({'status': 200,'message': '评分更新成功'}), 200
    except Exception as e:
        logger.error(f"更新评分出错: {str(e)}")
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

def update_teacher_score(request_data):
    """
    获取评分
    参数: request_data 包含评分组id、被评分组id、评分点id的字典
    返回: JSON响应，包含状态码和消息
    """
    # 验证请求数据
    if not request_data:
        return jsonify({'status': 400,'message': '请求数据为空'}), 400
    scored_group_id = request_data.get('scored_group_id')
    score_point_id = request_data.get('score_point_id')
    score = request_data.get('score')
    if not all([scored_group_id, score_point_id]):
        return jsonify({'status': 422,'message': '缺少必要参数'}), 422
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 检查被评分组是否存在
        cursor.execute('SELECT id FROM student_groups WHERE id = %s', (scored_group_id,))
        if not cursor.fetchone():
            return jsonify({'status': 404,'message': '被评分组不存在'}), 404
        # 检查评分点是否存在
        cursor.execute('SELECT id FROM task_criteria WHERE id = %s', (score_point_id,))
        if not cursor.fetchone():
            return jsonify({'status': 404,'message': '评分点不存在'}), 404
        # 获取评分
        cursor.execute('SELECT criteria_id, score FROM teacher_evaluations WHERE criteria_id = %s', (score_point_id, ))
        scores = cursor.fetchone()
        if not scores:
            # 添加评分
            cursor.execute('INSERT INTO teacher_evaluations (evaluated_group_id, criteria_id, score) VALUES (%s, %s, %s)', (scored_group_id, score_point_id, score))
            conn.commit()
            return jsonify({'status': 200,'message': '评分成功', 'data': {'score': 0}}), 200
        else:
            # 更新评分
            cursor.execute('UPDATE teacher_evaluations SET score = %s WHERE criteria_id = %s', (score, score_point_id))
            conn.commit()
            return jsonify({'status': 200,'message': '评分成功', 'data': {'score': scores['score']}}), 200
    except Exception as e:
        logger.error(f"获取评分出错: {str(e)}")
        return jsonify({'status': 500,'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


#======================== 页面返回 路由 ==============================

@app.route('/', methods=['GET'])
def index():
    """
    首页接口
    返回: www目录下的index.html文件
    """
    return app.send_static_file('index.html')

@app.route('/teacher_login', methods=['GET'])
def teacher_login():
    """
    教师登录页面返回
    返回: www目录下的teacher_login.html文件
    """
    return app.send_static_file('teacher_login.html') 

@app.route('/class_login', methods=['GET'])
def class_login():
    """
    课堂登录页面
    返回: 动态生成的课堂选择页面
    """
    # 加载文件class_login.html
    with open(os.path.join(app.root_path,'www-html', 'class_login.html'), 'r', encoding='utf-8') as f:
        html_content = f.read()
    # 读取数据库的所有小组信息
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT id, group_name, leader_name FROM student_groups")
    groups = cursor.fetchall()
    cursor.close()
    conn.close()
    # 生成动态的小组选择选项
    options = ""
    for group in groups:
        options += f"""
        <div class="col-md-3 col-sm-6">
            <a href="/class?stuid={group['id']}">
                <div class="class-btn btn btn-light btn-block">
                    <h4>{group['group_name']}</h4>
                    <p class="leader">组长: {group['leader_name']}</p>
                </div>
            </a>
        </div>
        """
    options += """
    <div class="col-md-3 col-sm-6">
        <a href="/teacher_login?nextpage=classing">
            <div class="class-btn btn btn-light btn-block">
                <h4>教师登录</h4>
                <p class="leader">将会跳转到教师登录界面</p>
            </div>
        </a>
    </div>
    """
    # 将动态选项插入到HTML模板中
    html_content = html_content.replace("<!--<|CHZT_REF_CLASS_BUTTONS|>-->", options)
    html_content = html_content.replace("<!--<|CHZT_REF_CLASS_TITLE|>-->", "请选择小组登录")
    return html_content

@app.route('/edit_task', methods=['GET'])
def edit_task():
    """
    编辑任务页面返回
    返回: www目录下的edit_task.html文件
    """
    token = request.args.get('token')
    if not token:
        return jsonify({'status': 401,'message': '缺少token参数'}), 401
    decoded_token = decode_token(token)
    current_user = decoded_token['sub']
    current_user = json.loads(current_user)
    if current_user.get('type') != 'admin' and current_user.get('type')!= 'teacher':
        return jsonify({'status': 401,'message': '权限不足'}), 401
    else:
        return app.send_static_file('edit_task.html')

@app.route('/<path:filename>', methods=['GET'])
def static_html(filename):
    """
    静态HTML文件处理接口
    参数: filename(URL路径)
    返回: www目录下对应的静态文件(仅处理.html文件)
    """
    logger.info(f"收到静态文件请求: {filename}")
    if not filename.endswith('.html'):
        logger.info(f"静态文件请求: {filename} 不是HTML文件，正常返回")
        return app.send_static_file(filename)
    logger.warning(f"静态文件请求: {filename} 是HTML文件，返回404")
    return "Not Found", 404

@app.route('/static/uploads/<path:filename>', methods=['GET'])
def get_image_static_uploads(filename):
    """
    静态文件处理接口(图片)
    参数: filename(URL路径)
    返回: www目录下对应的静态文件(仅处理图片文件)
    """
    logger.info(f"收到静态文件请求: {filename}")
    file_path = os.path.join(app.root_path, 'static', 'uploads', filename)
    if not os.path.exists(file_path):
        logger.warning(f"文件不存在: {file_path}")
        return "Not Found", 404
    
    if not filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
        logger.warning(f"不支持的文件类型: {filename}")
        return "Not Found, only get images", 404
    
    logger.info(f"返回图片文件: {filename}")
    return send_from_directory(os.path.join(app.root_path, 'static', 'uploads'), filename)

@app.route('/dashboard', methods=['GET', 'OPTIONS'])
def dashboard():
    """
    教师仪表盘接口
    参数: {request_type: 请求类型(add/delete/update/search/get_all), request_data: 请求数据}
    返回: {status: 状态码, message: 消息或数据}
    """
    if request.method == 'OPTIONS':
        return jsonify({'status': 200}), 200
    
    # 从URL参数获取token
    token = request.args.get('token')
    if not token:
        return jsonify({'status': 401, 'message': '缺少token参数'}), 401
    logger.info(f"收到仪表盘请求，token: {token}")
    
    decoded_token = decode_token(token)
    logger.info(f"解码后的token: {decoded_token}")
    # decoded_token = json.loads(decoded_token)
    
    # logger.info(f"解码后的token: {decoded_token}")
    current_user = decoded_token['sub']
    current_user = json.loads(current_user)
    if current_user.get('type') == 'admin':
        admin_dashboard_html_path = 'www-html/admin_dashboard.html'
        # 获取url中的参数，判断仪表盘的页面
        response_html_code = ""
        # 判断url是否有参数page
        page = ""
        if not request.args.get('page'):
            logger.warning("仪表盘请求: 缺少page参数")
            page = 'users'
            # from flask import redirect, url_for
            # return redirect(url_for('dashboard', page='users', token=token))
        else:
            page = request.args.get('page')
        
        # 定义模板映射字典
        template_mapping = {
            'users': {
                'template_file': 'www-html/templates/users-container.template',
                'placeholder': '<!--<|CHZT_REF_CONTENT|>-->'
            },
            'systemsettings': {
                'template_file': 'www-html/templates/system-settings-container.template',
                'placeholder': '<!--<|CHZT_REF_CONTENT|>-->'
            },
            'logview': {
                'template_file': 'www-html/templates/log-view-container.template',
                'placeholder': '<!--<|CHZT_REF_CONTENT|>-->'
            }
        }
        
        # 检查page参数是否有效
        if page not in template_mapping:
            logger.warning(f"仪表盘请求失败: 未知的page参数 - {page}")
            return jsonify({'status': 400,'message': '未知的page参数'}), 400

        # 读取模板和主页面内容
        try:
            with open(template_mapping[page]['template_file'], 'r', encoding='utf-8') as f:
                template = f.read()
            with open(admin_dashboard_html_path, 'r', encoding='utf-8') as f:
                response_html_code = f.read()
            
            # 替换占位符
            response_html_code = response_html_code.replace(
                template_mapping[page]['placeholder'], 
                template
            )
            return response_html_code, 200
        except Exception as e:
            logger.error(f"加载模板失败: {str(e)}")
            return jsonify({'status': 500,'message': '加载模板失败'}), 500

    elif current_user.get('type') == 'teacher':
        template_mapping = {
            'groups_manage': {
                'show': True,
                'show_text': '群组管理',
                'template_file': 'www-html/templates/groups-manage-container.template',
                'placeholder': '<!--<|CHZT_REF_CONTENT|>-->'
            },
            'courses_manage': {
                'show': True,
                'show_text': '课程管理',
                'template_file': 'www-html/templates/courses-manage-container.template',
                'placeholder': '<!--<|CHZT_REF_CONTENT|>-->'
            },
            'submissions_manage': {
                'show': False,
                'show_text': '',
                'template_file': 'www-html/templates/submissions-manage-container.template',
                'placeholder': '<!--<|CHZT_REF_CONTENT|>-->'
            },
        }
        teacher_dashboard_html_path = 'www-html/teacher_dashboard.html'
        html_code_menu_items = ""
        for i in template_mapping:
            if not template_mapping[i]['show']:
                continue
            html_code_menu_items += f"""<li><a href="#" data-page="{i}">{template_mapping[i]['show_text']}</a></li>"""
        # 获取url中的参数，判断仪表盘的页面
        response_html_code = ""
        # 判断url是否有参数page
        page = ""
        if not request.args.get('page'):
            logger.warning("仪表盘请求: 缺少page参数")
            page = list(template_mapping.keys())[0]
            # from flask import redirect, url_for
            # return redirect(url_for('dashboard', page='users', token=token))
        else:
            page = request.args.get('page')
        # 检查page参数是否有效
        if page not in template_mapping:
            logger.warning(f"仪表盘请求失败: 未知的page参数 - {page}")
            return jsonify({'status': 400,'message': '未知的page参数'}), 400
        # 读取模板和主页面内容
        try:
            with open(template_mapping[page]['template_file'], 'r', encoding='utf-8') as f:
                template = f.read()
            with open(teacher_dashboard_html_path, 'r', encoding='utf-8') as f:
                response_html_code = f.read()
            # 替换占位符
            response_html_code = response_html_code.replace(
                template_mapping[page]['placeholder'],
                template
            )
            response_html_code = response_html_code.replace(
                '<!--<|CHZT_REF_MENU_ITEM|>-->',
                html_code_menu_items
            )
            return response_html_code, 200
        except Exception as e:
            logger.error(f"加载模板失败: {str(e)}")
            return jsonify({'status': 500,'message': '加载模板失败'}), 500
    else:
        return jsonify({'status': 403,'message': '权限不足'}), 403

@app.route('/class', methods=['GET'])
def class_page():
    """
    课堂页面返回，如存在token参数则进行验证，并构建教师课堂页面；否则检查是否存在stuid参数，并构建学生课堂页面。
    参数: token(可选)
    返回: www目录下的class.html文件
    """
    token = request.args.get('token')
    stuid = request.args.get('stuid')
    page_html = ""
    if token and stuid:
        return jsonify({'status': 400,'message': '参数错误'}), 400
    if token:
        # 验证token
        decoded_token = decode_token(token)
        current_user = decoded_token['sub']
        current_user = json.loads(current_user)
        
        if current_user.get('type') == 'teacher':
            # 构建教师课堂页面
            page_html = generate_teacher_class_page(current_user)
        else:
            return jsonify({'status': 403,'message': '权限不足'}), 403
    elif stuid:
        # 构建学生课堂页面
        page_html = generate_student_class_page(stuid)
    else:
        return jsonify({'status': 400,'message': '缺少参数'}), 400
    return page_html

def generate_teacher_class_page(current_user):
    """
    构建教师课堂页面
    参数: current_user(当前用户信息)
    返回: 教师课堂页面HTML代码
    """
    html_content = ""
    optinons = ""
    script_content = """
    <script>
    $(document).ready(function() {
        // 为课程按钮绑定点击事件
        $('.course-btn').click(function(e) {
            e.preventDefault();
            var courseId = $(this).data('course-id');
            
            // 发送AJAX请求
            $.ajax({
                url: '/set_course_id?course_id=' + courseId,
                type: 'GET',
                success: function(response) {
                    if(response.status === 200) {
                        // 使用Bootstrap提示框显示成功消息
                        $('body').append(`
                            <div class="alert alert-success alert-dismissible fade show" role="alert" style="position: fixed; top: 20px; right: 20px; z-index: 9999;">
                                ${response.message}
                                <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                                    <span aria-hidden="true">&times;</span>
                                </button>
                            </div>
                        `);
                        
                        // 3秒后自动关闭提示框
                        setTimeout(function() {
                            $('.alert').alert('close');
                        }, 3000);
                    } else {
                        // 显示错误消息
                        $('body').append(`
                            <div class="alert alert-danger alert-dismissible fade show" role="alert" style="position: fixed; top: 20px; right: 20px; z-index: 9999;">
                                ${response.message}
                                <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                                    <span aria-hidden="true">&times;</span>
                                </button>
                            </div>
                        `);
                    }
                },
                error: function(xhr) {
                    // 处理请求失败的情况
                    $('body').append(`
                        <div class="alert alert-danger alert-dismissible fade show" role="alert" style="position: fixed; top: 20px; right: 20px; z-index: 9999;">
                            请求失败: ${xhr.status} ${xhr.statusText}
                            <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                            </button>
                        </div>
                    `);
                }
            });
        });
    });
    </script>
    """
    with open(os.path.join(app.root_path,'www-html', 'class_login.html'), 'r', encoding='utf-8') as f:
        html_content = f.read()
    # 查询运行时变量表，是否存在variable_name=”CURRENT_CLASS_ID“，如果存在则查询返回variable_value，否则创建该条目
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT variable_value FROM runtime_variables WHERE variable_name = 'CURRENT_CLASS_ID'")
    current_class_id = cursor.fetchone()
    if not current_class_id:
        # 创建该条目
        cursor.execute("INSERT INTO runtime_variables (variable_name, variable_value) VALUES ('CURRENT_CLASS_ID', '1')")
        conn.commit()
        current_class_id = 0
    else:
        current_class_id = current_class_id['variable_value']
    cursor.close()
    conn.close()
    # 读取所有courses的信息
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT id, course_name FROM courses")
    courses = cursor.fetchall()
    for course in courses:
        optinons += f"""
                <div class="col-md-3 col-sm-6">
            <a href="#" class="course-btn" data-course-id="{course['id']}">
                <div class="class-btn btn btn-light btn-block">
                    <h4>{course['course_name']}</h4>
                </div>
            </a>
        </div>
        """
    cursor.close()
    conn.close()
    html_content = html_content.replace("<!--<|CHZT_REF_CLASS_BUTTONS|>-->", optinons)
    html_content = html_content.replace("<!--<|CHZT_REF_CLASS_TITLE|>-->", "请选择课程")
    html_content = html_content.replace("<!--<|CHZT_REF_SCRIPT|>-->", script_content)
    return html_content

def generate_student_class_page(stuid):
    """
    构建学生课堂页面
    参数: stuid(学生学号)
    返回: 学生课堂页面HTML代码
    """
    return f"<h1>学生课堂页面 - {stuid}</h1>"

if __name__ == '__main__':
    app.run(debug=True,port=5010)