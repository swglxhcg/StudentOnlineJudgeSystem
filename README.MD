### 部署步骤记录
---
1. 创建MySQL用户，创建数据库，导入数据库、数据表文件`ojs_db_schema.sql`。
   1. 进入MySQL命令行，输入` create user 'ojs_root' @'localhost' identified by '123456';`，创建用户。
   2. 输入`revoke all on *.* from 'ojs_root'@'localhost';`，撤销用户所有权限。
   3. 输入`flush privileges;`，刷新权限。
   4. 输入`create database ojs_db;`，创建数据库。
   5. 输入`use ojs_db;`，选择数据库。
   6. 输入`source ojs_db_schema.sql;`，导入数据库。
   7. 输入`grant all privileges on ojs_db.* to 'ojs_root'@'localhost';`，赋予用户对于ojs_db数据库的所有权限。
   8. 输入`flush privileges;`，刷新权限。
   9.  输入`exit;`，退出MySQL命令行。