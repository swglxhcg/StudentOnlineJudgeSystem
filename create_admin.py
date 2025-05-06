import requests
import hashlib

# 生成MD5加密的密码
def get_md5_password(password):
    """
    对密码进行MD5加密
    :param password: 原始密码
    :return: MD5加密后的字符串
    """
    return hashlib.md5(password.encode()).hexdigest()

# 创建管理员用户
def create_admin_user(username, password, api_url='http://localhost:5000/users'):
    """
    通过Flask API创建管理员用户
    :param username: 用户名
    :param password: 原始密码
    :param api_url: API接口地址
    :return: API响应结果
    """
    # 获取MD5加密后的密码
    password_md5 = get_md5_password(password)
    
    # 准备请求数据
    data = {
        'username': username,
        'password_md5': password_md5,
        'user_type': 2  # 2表示管理员
    }
    
    # 输出信息
    print(f'准备创建管理员用户: {username}, MD5密码: {password_md5}')
    
    try:
        # 输出请求数据
        print(f'构建请求数据: {data}')
        # 发送POST请求
        response = requests.post(api_url, json=data)
        return response.json()
    except Exception as e:
        return {'status': 500, 'message': f'请求失败: {str(e)}'}

if __name__ == '__main__':
    # 创建管理员用户
    result = create_admin_user('admin', '123456')
    print(result)