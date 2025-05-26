// 显示添加群组表单
function showAddGroupForm() {
    document.getElementById('groupManagementSection').style.display = 'none';
    document.getElementById('addGroupSection').style.display = 'block';
    document.getElementById('editGroupSection').style.display = 'none';
    document.getElementById('groupName').value = '';
}

// 隐藏添加群组表单
function hideAddGroupForm() {
    document.getElementById('groupManagementSection').style.display = 'block';
    document.getElementById('addGroupSection').style.display = 'none';
}

// 添加新群组
function addGroup() {
    const groupName = document.getElementById('groupName').value.trim();
    if (!groupName) {
        alert('请输入群组名称');
        return;
    }
    
    // TODO: 调用API添加群组
    console.log('添加群组:', groupName);
    hideAddGroupForm();
    // TODO: 刷新群组列表
}

// 显示编辑群组表单
function showEditGroupForm(groupId, groupName) {
    document.getElementById('groupManagementSection').style.display = 'none';
    document.getElementById('addGroupSection').style.display = 'none';
    document.getElementById('editGroupSection').style.display = 'block';
    document.getElementById('editGroupName').value = groupName;
    // TODO: 存储当前编辑的groupId
}

// 隐藏编辑群组表单
function hideEditGroupForm() {
    document.getElementById('groupManagementSection').style.display = 'block';
    document.getElementById('editGroupSection').style.display = 'none';
}

// 更新群组信息
function updateGroup() {
    const groupName = document.getElementById('editGroupName').value.trim();
    if (!groupName) {
        alert('请输入群组名称');
        return;
    }
    
    // TODO: 调用API更新群组
    console.log('更新群组:', groupName);
    hideEditGroupForm();
    // TODO: 刷新群组列表
}

// 删除群组
function deleteGroup(groupId) {
    if (confirm('确定要删除这个群组吗？')) {
        // TODO: 调用API删除群组
        console.log('删除群组:', groupId);
        // TODO: 刷新群组列表
    }
}