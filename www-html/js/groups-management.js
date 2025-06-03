// 显示添加小组表单
function showAddGroupForm() {
    document.getElementById('groupManagementSection').style.display = 'none';
    document.getElementById('addGroupSection').style.display = 'block';
    document.getElementById('editGroupSection').style.display = 'none';
    document.getElementById('groupName').value = '';
}

// 隐藏添加小组表单
function hideAddGroupForm() {
    document.getElementById('groupManagementSection').style.display = 'block';
    document.getElementById('addGroupSection').style.display = 'none';
}

// 添加新小组
function addGroup() {
    const groupName = document.getElementById('groupName').value.trim();
    if (!groupName) {
        alert('请输入小组名称');
        return;
    }
    
    // TODO: 调用API添加小组
    console.log('添加小组:', groupName);
    hideAddGroupForm();
    // TODO: 刷新小组列表
}

// 显示编辑小组表单
function showEditGroupForm(groupId, groupName) {
    document.getElementById('groupManagementSection').style.display = 'none';
    document.getElementById('addGroupSection').style.display = 'none';
    document.getElementById('editGroupSection').style.display = 'block';
    document.getElementById('editGroupName').value = groupName;
    // TODO: 存储当前编辑的groupId
}

// 隐藏编辑小组表单
function hideEditGroupForm() {
    document.getElementById('groupManagementSection').style.display = 'block';
    document.getElementById('editGroupSection').style.display = 'none';
}

// 更新小组信息
function updateGroup() {
    const groupName = document.getElementById('editGroupName').value.trim();
    if (!groupName) {
        alert('请输入小组名称');
        return;
    }
    
    // TODO: 调用API更新小组
    console.log('更新小组:', groupName);
    hideEditGroupForm();
    // TODO: 刷新小组列表
}

// 删除小组
function deleteGroup(groupId) {
    if (confirm('确定要删除这个小组吗？')) {
        // TODO: 调用API删除小组
        console.log('删除小组:', groupId);
        // TODO: 刷新小组列表
    }
}