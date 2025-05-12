#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <trace/events/sched.h>
#include <linux/seq_file.h> // 添加 seq_file 头文件

int global_groupid = 0;
struct proc_t{
    struct list_head head;
    pid_t pid;
    struct proc_t* father;
    struct list_head child;
    int groupid;
};
static struct proc_t procs_root;
static spinlock_t proc_lock;

static struct proc_t* lookup_proc_nolock(struct proc_t* proc, pid_t pid)
{
    struct proc_t* cur, *next;
    list_for_each_entry_safe(cur, next, &proc->child, head){
        if(cur->pid == pid){
            return cur;
        }
        if(!list_empty(&cur->child)){
            struct proc_t* child_proc = lookup_proc_nolock(cur, pid);
            if(child_proc){
                return child_proc;
            }
        }
    }
    return NULL;
}

static struct proc_t* lookup_proc(pid_t pid)
{
    struct proc_t* proc;

    spin_lock(&proc_lock);
    proc = lookup_proc_nolock(&procs_root, pid);
    spin_unlock(&proc_lock);
    return proc;
}

static struct proc_t* insert_proc(pid_t pid)
{
    struct proc_t* proc;

    spin_lock(&proc_lock);
    proc = lookup_proc_nolock(&procs_root, pid);
    if (proc)
        return proc;
    while(!(proc = kmalloc(sizeof(struct proc_t), GFP_KERNEL))){}
    memset(proc, 0, sizeof(struct proc_t));
    INIT_LIST_HEAD(&proc->head);
    proc->pid = pid;
    proc->father = NULL;
    INIT_LIST_HEAD(&proc->child);

    list_add(&(proc->head), &(procs_root.child));
    
    spin_unlock(&proc_lock);
    return proc;
}

static void set_proc_family(struct proc_t* parent, struct proc_t* child)
{
    spin_lock(&proc_lock);
    list_del(&child->head);
    INIT_LIST_HEAD(&child->head);
    list_add(&(child->head), &(parent->child));
    child->father = parent;
    spin_unlock(&proc_lock);
}

static void remove_proc_nolock(struct proc_t* proc)
{
    struct proc_t* cur, *next;
    list_for_each_entry_safe(cur, next, &proc->child, head){
        remove_proc_nolock(cur);
    }
        
    if(proc->father){
        list_del(&proc->head);
    }
    kfree(proc);
}

static void remove_proc(struct proc_t* proc)
{
    spin_lock(&proc_lock);
    remove_proc_nolock(proc);
    spin_unlock(&proc_lock);
}

static void process_fork_callback(void *ignore, struct task_struct *parent, struct task_struct *child)
{
    struct proc_t *parent_proc, *child_proc;
    parent_proc = lookup_proc(parent->pid);
    if(!parent_proc){
        parent_proc = insert_proc(parent->pid);
    }
    child_proc = lookup_proc(child->pid);
    if(!child_proc){
        child_proc = insert_proc(child->pid);
    }
    set_proc_family(parent_proc, child_proc);
}

static void process_exit_callback(void *ignore, struct task_struct *task)
{
    struct proc_t *proc;
    proc = lookup_proc(task->pid);
    if(proc)
        remove_proc(proc);
}

static int scan_and_build(void* data){
    struct task_struct *task;
    for_each_process(task) {
        struct proc_t *proc;
        proc = lookup_proc(task->pid);
        if(!proc){
            proc = insert_proc(task->pid);
        }
        if(task->parent){
            struct proc_t *parent_proc;
            parent_proc = lookup_proc(task->parent->pid);
            if(!parent_proc){
                parent_proc = insert_proc(task->parent->pid);
            }
            set_proc_family(parent_proc, proc);
        }
    }
    return 0;
}

struct dentry* dir;

// 递归打印 proc 树
static void print_proc_tree(struct seq_file *m, struct proc_t *proc, int depth)
{
    struct proc_t *child;

    // 打印当前节点
    seq_printf(m, "%*s- %d\n", depth * 2, "", proc->pid);

    // 遍历子节点
    list_for_each_entry(child, &proc->child, head) {
        print_proc_tree(m, child, depth + 1);
    }
}

static pid_t root_pid = 0; // 新增全局变量，指定打印的根节点 PID

// seq_file 的显示回调函数
static int proc_tree_show(struct seq_file *m, void *v)
{
    struct proc_t *start_proc;

    spin_lock(&proc_lock);

    if (root_pid <= 0) {
        start_proc = &procs_root; // 从根节点开始打印
    } else {
        start_proc = lookup_proc_nolock(&procs_root, root_pid); // 查找指定 PID 的节点
        if (!start_proc) {
            seq_printf(m, "PID %d not found\n", root_pid);
            spin_unlock(&proc_lock);
            return 0;
        }
    }

    print_proc_tree(m, start_proc, 0); // 打印从指定节点开始的树形结构

    spin_unlock(&proc_lock);
    return 0;
}

// debugfs 文件操作接口
static int proc_tree_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_tree_show, NULL);
}

static const struct file_operations proc_tree_fops = {
    .owner = THIS_MODULE,
    .open = proc_tree_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

void set_groupid(struct proc_t* proc, int groupid)
{
    struct proc_t *cur, *next;
    proc->groupid = groupid;
    list_for_each_entry_safe(cur, next, &proc->child, head){
        set_groupid(cur, groupid);
    }
}

void create_group(pid_t pid)
{
    struct proc_t *proc;
    proc = lookup_proc(pid);
    if(!proc){
        printk(KERN_ERR "Failed to find process %d\n", pid);
        return;
    }
    spin_lock(&proc_lock);
    set_groupid(proc, ++global_groupid);
    spin_unlock(&proc_lock);
}

static ssize_t create_group_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char pid_str[16];
    pid_t new_pid;

    if (count >= sizeof(pid_str))
        return -EINVAL;

    if (copy_from_user(pid_str, buf, count))
        return -EFAULT;

    pid_str[count] = '\0';
    if (kstrtoint(pid_str, 10, &new_pid))
        return -EINVAL;

    create_group(new_pid);
    printk(KERN_INFO "create group at pid %d\n", new_pid);

    return count;
}

// 定义 root_pid 文件的 file_operations
static const struct file_operations create_group_fops = {
    .owner = THIS_MODULE,
    .write = create_group_write,
};

// 打印分组结构的辅助函数
static void print_group_structure(struct seq_file *m, struct proc_t *proc)
{
    struct proc_t *child;

    // 如果当前节点有分组 ID，打印分组信息
    if (proc->groupid > 0) {
        seq_printf(m, "Group %d: PID %d\n", proc->groupid, proc->pid);
    }

    // 遍历子节点
    list_for_each_entry(child, &proc->child, head) {
        print_group_structure(m, child);
    }
}

// seq_file 的显示回调函数
static int group_structure_show(struct seq_file *m, void *v)
{
    spin_lock(&proc_lock);
    print_group_structure(m, &procs_root); // 从根节点开始打印
    spin_unlock(&proc_lock);
    return 0;
}

// debugfs 文件操作接口
static int group_structure_open(struct inode *inode, struct file *file)
{
    return single_open(file, group_structure_show, NULL);
}

static const struct file_operations group_structure_fops = {
    .owner = THIS_MODULE,
    .open = group_structure_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

// Function to recursively remove groupid from processes
static void clear_groupid(struct proc_t *proc, int groupid)
{
    struct proc_t *cur, *next;

    if (proc->groupid == groupid) {
        proc->groupid = 0; // Clear the group ID
    }

    list_for_each_entry_safe(cur, next, &proc->child, head) {
        clear_groupid(cur, groupid);
    }
}

// Function to delete a group by groupid
void delete_group(int groupid)
{
    struct proc_t *cur, *next;

    spin_lock(&proc_lock);
    list_for_each_entry_safe(cur, next, &procs_root.child, head) {
        clear_groupid(cur, groupid);
    }
    spin_unlock(&proc_lock);

    printk(KERN_INFO "Group %d deleted\n", groupid);
}

// Write callback for delete_group debugfs file
static ssize_t delete_group_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char groupid_str[16];
    int groupid;

    if (count >= sizeof(groupid_str))
        return -EINVAL;

    if (copy_from_user(groupid_str, buf, count))
        return -EFAULT;

    groupid_str[count] = '\0';
    if (kstrtoint(groupid_str, 10, &groupid))
        return -EINVAL;

    delete_group(groupid);
    return count;
}

// Define file_operations for delete_group
static const struct file_operations delete_group_fops = {
    .owner = THIS_MODULE,
    .write = delete_group_write,
};


// 新增写入 root_pid 的回调函数
static ssize_t set_root_pid_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char pid_str[16];
    pid_t new_root_pid;

    if (count >= sizeof(pid_str))
        return -EINVAL;

    if (copy_from_user(pid_str, buf, count))
        return -EFAULT;

    pid_str[count] = '\0';
    if (kstrtoint(pid_str, 10, &new_root_pid))
        return -EINVAL;

    root_pid = new_root_pid; // 更新全局变量 root_pid
    printk(KERN_INFO "Set root_pid to %d\n", root_pid);

    return count;
}

// 定义 set_root_pid 文件的 file_operations
static const struct file_operations set_root_pid_fops = {
    .owner = THIS_MODULE,
    .write = set_root_pid_write,
};

// 修改 debugfs_init 函数
static void debugfs_init(void)
{
    dir = debugfs_create_dir("process_grouping", NULL);
    if (!dir) {
        printk(KERN_ERR "Failed to create debugfs directory\n");
        return;
    }

    // 创建用于输出 proc 树的文件
    if (!debugfs_create_file("proc_tree", 0444, dir, NULL, &proc_tree_fops)) {
        printk(KERN_ERR "Failed to create proc_tree file\n");
    }

    if (!debugfs_create_file("set_root_pid", 0644, dir, NULL, &set_root_pid_fops)) {
        printk(KERN_ERR "Failed to create set_root_pid file\n");
    }

    // 创建 create_group 文件
    if (!debugfs_create_file("create_group", 0644, dir, NULL, &create_group_fops)) {
        printk(KERN_ERR "Failed to create group file\n");
    }

    // 创建 group_structure 文件
    if (!debugfs_create_file("group_structure", 0444, dir, NULL, &group_structure_fops)) {
        printk(KERN_ERR "Failed to create group_structure file\n");
    }

    if (!debugfs_create_file("delete_group", 0644, dir, NULL, &delete_group_fops)) {
        printk(KERN_ERR "Failed to create delete_group file\n");
    }
}

static int __init process_grouping_init(void)
{
    struct task_struct *scan_thread;

    INIT_LIST_HEAD(&procs_root.head);
    procs_root.pid = 0;
    procs_root.father = NULL;
    INIT_LIST_HEAD(&procs_root.child);

    spin_lock_init(&proc_lock);

    debugfs_init();
    register_trace_sched_process_fork(process_fork_callback, NULL);
    register_trace_sched_process_exit(process_exit_callback, NULL);

    // 创建并启动线程
    scan_thread = kthread_run(scan_and_build, NULL, "scan_thread");
    if (IS_ERR(scan_thread)) {
        printk(KERN_ERR "Failed to create scan thread\n");
        scan_thread = NULL;
        return PTR_ERR(scan_thread);
    }
    return 0;
}
static void __exit process_grouping_exit(void)
{
    struct proc_t* cur, *next;
    if (dir) {
        debugfs_remove_recursive(dir);
        dir = NULL;
    }
    list_for_each_entry_safe(cur, next, &procs_root.child, head){
        remove_proc(cur);
    }
    unregister_trace_sched_process_fork(process_fork_callback, NULL);
    unregister_trace_sched_process_exit(process_exit_callback, NULL);
}
module_init(process_grouping_init);
module_exit(process_grouping_exit);
MODULE_LICENSE("GPL");