from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS, cross_origin
from datetime import timedelta
import pymysql
import hashlib
import json
import re
from ct_logger import CtLogger, RichCtLogger
from flask_jwt_extended import decode_token

# 创建全局日志记录器
logger = RichCtLogger('ojs_app')

app = Flask(__name__, static_folder='www-html')
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

app.config['JWT_SECRET_KEY'] = 'chzt'  # 生产环境请使用更安全的密钥
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=2)
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

@app.route('/<path:filename>', methods=['GET'])
def static_html(filename):
    """
    静态HTML文件处理接口
    参数: filename(URL路径)
    返回: www目录下对应的静态文件(仅处理.html文件)
    """
    if filename.endswith('.html'):
        return app.send_static_file(filename)
    return "Not Found", 404

@app.route('/dashboard', methods=['GET', 'OPTIONS'])
# @cross_origin()
# @jwt_required(locations=['query_string'])
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
                'template_file': 'www-html/users-container.template',
                'placeholder': '<!--<|CHZT_REF_CONTENT|>-->'
            },
            'systemsettings': {
                'template_file': 'www-html/system-settings-container.template',
                'placeholder': '<!--<|CHZT_REF_CONTENT|>-->'
            },
            'logview': {
                'template_file': 'www-html/log-view-container.template',
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

###################################
# 用户管理接口
###################################
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

###################################
# 小组管理接口
###################################
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

###################################
# 课程管理接口
###################################
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


if __name__ == '__main__':
    app.run(debug=True,port=5010)