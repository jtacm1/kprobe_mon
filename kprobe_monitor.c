// SPDX-License-Identifier: GPL-2.0-only
/*
 * Here's a sample kernel module showing the use of kprobes to dump a
 * stack trace and selected registers when kernel_clone() is called.
 *
 * For more information on theory of operation of kprobes, see
 * Documentation/trace/kprobes.rst
 *
 * You will see the trace data in /var/log/messages and on the console
 * whenever kernel_clone() is invoked to create a new process.
 */

#define pr_fmt(fmt) "%s: " fmt, __func__
#include <linux/string.h>
#include "./util.h"
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>



// #define MONITOR_PATH "/home/jt/"  // 默认指定需要监控的目录
#define CREATE_OP "EVENT_CREATE"
#define OPEN_OP "EVENT_OPEN"
#define WRITE_OP "EVENT_WRITE"
#define READ_OP "EVENT_READ"
#define RENAME_OP "EVENT_RENAME"
#define CLOSE_OP "EVENT_CLOSE"
#define DELETE_OP "EVENT_DELETE"
#define EXECVE_OP "EVENT_EXECVE"
#define FORK_OP "EVENT_FORK"
#define EXIT_OP "EVENT_EXIT"
#define	KILL_OP "EVENT_KILL"
#define CRED_UP_OP "EVENT_UPCRED"
#define CONNECT_OP "EVENT_CONNECT"
#define RECV_OP "EVENT_RECV"
#define SEND_OP "EVENT_SEND"

// #define NAME_TOO_LONG "-2"
// #define DEFAULT_RET_STR "-1"

#define DEFAULT_INO -1
#define DEFAULT_SIZE 0
#define MAX_RECORDS 16384
#define	RESULT_LEN	256
// #define HASH_BITS 11
#define MAX_PATHS 64 //max monitor path counts
// static char target_dir[PATH_MAX] = MONITOR_PATH;
// module_param_string(dir, target_dir, PATH_MAX, 0644);
// MODULE_PARM_DESC(dir, "target directory to monitor");
static char *target_paths[MAX_PATHS] = {};
static int path_count = 0;
static char pre_s[RESULT_LEN]; //用于判断需要记录的事件是否已经发生过
static char *exclude_paths[MAX_PATHS] = { };
static int exclude_count = 0;
module_param_array_named(exclude, exclude_paths, charp, &exclude_count, 0644);
MODULE_PARM_DESC(exclude, "Comma-separated list of paths to exclude");
module_param_array_named(dir, target_paths, charp, &path_count, 0644);
MODULE_PARM_DESC(dir, "Comma-separated list of target paths to monitor");
DEFINE_HASHTABLE(inode_hash_table, 11); //定义inode哈系表
LIST_HEAD(inode_list); //定义inode双向链表头

rwlock_t inode_hash_lock; //定义inode哈系表读写锁
static DEFINE_SPINLOCK(event_lock);
static LIST_HEAD(event_list);
static struct kmem_cache *event_cache;
static struct proc_dir_entry *proc_entry;
static atomic_t event_count = ATOMIC_INIT(0);

//定义表中inode节点的结构体
struct inode_info {
	unsigned long ino; //inode号，文件唯一标识
	char *file_name; //文件名
	char *file_path; //文件路径
	struct list_head i_list; //双向链表节点
	struct hlist_node i_hash; //哈系表节点
};

struct path_info {
    const char *path;
    size_t len;    // 预计算路径长度
};
static struct path_info sorted_paths[MAX_PATHS];
static struct path_info sorted_exclude[MAX_PATHS];

struct kevent {
    char result[RESULT_LEN];
    struct list_head list;
};

struct update_cred_data {
		kuid_t old_uid;
};

struct net_data {
    struct sock *sk;
    int sa_family;
};

/* 路径比较函数（按长度降序） */
static int compare_path(const void *a, const void *b)
{
    const struct path_info *pa = a;
    const struct path_info *pb = b;
    return pb->len - pa->len;  // 降序排列
}

// 路径匹配检查函数
static bool is_target_path(const char *filepath)
{
    int i;

	// 先检查排除路径
    for (i = 0; i < exclude_count; i++) {
        const struct path_info *pi = &sorted_exclude[i];
        
        if (unlikely(!pi->path)) continue;
        if (strlen(filepath) < pi->len) continue;

        if (strncmp(filepath, pi->path, pi->len) == 0) {
            const char end_char = filepath[pi->len];
            if (end_char == '/' || end_char == '\0') {
                return false; // 匹配排除路径
            }
        }
    }

    for (i = 0; i < path_count; i++) {
        const struct path_info *pi = &sorted_paths[i];
        if (i == 0 && path_count == 1 && pi->len == 1 && pi->path[0] == '/'){
			return true;
		}
        /* 快速失败检查 */
        if (unlikely(!pi->path)) continue;
        if (strlen(filepath) < pi->len) continue;

        /* 精确前缀匹配 */
        if (strncmp(filepath, pi->path, pi->len) == 0) {
            /* 检查路径分隔符或字符串结尾 */
            const char end_char = filepath[pi->len];
            if (end_char == '/' || end_char == '\0') {
                return true;
            }
        }
    }
    return false;
}

//获取task的进程执行文件路径
static char *get_exe_path(struct task_struct *task, char *buf, int size){
	char *exe_path = "-1";

	if (unlikely(!buf))
		return exe_path;

	if (likely(task->mm)){
		if(likely(task->mm->exe_file)){
			exe_path = d_path(&(task->mm->exe_file->f_path), buf, size);
		}
	}

	if (unlikely(IS_ERR(exe_path)))
		exe_path = "-1";

	return exe_path;

}

//获取当前进程的父进程的文件执行路径
// static char *get_parent_exe_path(struct task_struct *task, char *buf, int size){
// 	char *exe_path = "-1";
// 	struct task_struct *p = NULL;

// 	if (task->real_parent){
// 		p = task->real_parent;
// 		exe_path = get_exe_path(p, buf, size);
// 	}

// 	return exe_path;
// }

////添加某个inode项及对应的文件信息
static int add_inode(unsigned long ino, char *file_name, char *file_path){
	struct inode_info *i = NULL;
	//写入写锁
	write_lock(&inode_hash_lock);
	//分配内存空间
	i = kzalloc(sizeof(struct inode_info), GFP_KERNEL);
	if (!i){
		pr_alert("fail to alloc memory for inode_info.\n");
		write_unlock(&inode_hash_lock);
		return 0;
	}	
	//添加inode项
	i->ino = ino;
	i->file_name = kstrdup(file_name, GFP_KERNEL);
	i->file_path = kstrdup(file_path, GFP_KERNEL);
	if (!i->file_name || !i->file_path) {
		kfree(i->file_name);
		kfree(i->file_path);
		pr_alert("fail to alloc memory for file name or path.\n");
		kfree(i);
		write_unlock(&inode_hash_lock);
		return 0;
	}
	//添加到哈系表中
	hash_add(inode_hash_table, &(i->i_hash), ino);
	//添加到链表中
	list_add(&(i->i_list), &inode_list);
	//释放写锁
	write_unlock(&inode_hash_lock);
	// pr_info("added inode: %lu, path: %s, file: %s\n", i->ino, i->file_path, i->file_name);
	return  1;
}

//查找某个inode项，获取对应的文件信息
static struct inode_info *find_inode(unsigned long ino)
{
	struct inode_info *i;

	//获取读锁
	read_lock(&inode_hash_lock);
	hash_for_each_possible(inode_hash_table, i, i_hash, ino)
	{
		if (i->ino == ino) {
			//释放读锁
			read_unlock(&inode_hash_lock);
			return i;
		}
	}
	// pr_info("inode: %lu not found.\n", ino);
	//没有找到匹配项，释放读锁
	read_unlock(&inode_hash_lock);
	return NULL;
}

static void delete_inode (unsigned long ino) {
	struct inode_info *i;
	//获取写锁
	write_lock(&inode_hash_lock);
	hash_for_each_possible(inode_hash_table, i, i_hash, ino)
	{
		if (i->ino == ino) {
			//从哈系表中删除
			hash_del(&i->i_hash);
			//从链表中删除
			list_del(&i->i_list);
			// pr_info("deleted inode: %lu, path: %s. file: %s\n", i->ino, i->file_path, i->file_name);

			//释放内存
			kfree(i->file_name);
			kfree(i->file_path);
			kfree(i);
			//释放写锁
			write_unlock(&inode_hash_lock);
			return;
		}
	}
	// pr_info("inode: %lu not found for deletion.\n", ino);
	//未找到匹配项，释放写锁
	write_unlock(&inode_hash_lock);
	return;
}

/* kprobe pre_handler: called just before the probed instruction is executed */
static int write_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_arg1(regs);//因为x86的参数传递规则是di，si，dx，cx，r8，r9，所以di就是vfs_write的第一个参数。arm默认是r0，r1，r2，r3，相应的取r0
	// char *result_str = NULL;
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	char *f_name = NULL;
	unsigned long ino;
	char *exe_buf = NULL;

	char *exe_path = NULL;

	struct inode_info *inode_info;
	struct inode *inode;
    // 写锁保护
    // write_lock(&write_lock);

    // 只处理有效的文件写操作
    if (unlikely(!S_ISREG(file_inode(file)->i_mode))) {
        // write_unlock(&write_lock);
        return 0;
    }

    // 分配路径缓冲区
    pname_buf = f_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (unlikely(!pname_buf)) {
        // write_unlock(&write_lock);
        return 0;
    }

	inode = file_inode((const struct file *)file);
	if (unlikely(!inode))
	{
		kfree(pname_buf);
		return 0;
	}
	inode_info = find_inode(inode->i_ino);
	if (unlikely(!inode_info)){
		filepath = dentry_path_raw(file->f_path.dentry, pname_buf, PATH_MAX);
		if (unlikely(IS_ERR(filepath))) {
			kfree(pname_buf);
			return 0;
		}
		// 只监控特定目录的文件操作
		if (!is_target_path(filepath)) {
			kfree(pname_buf);
			return 0;  // 如果文件路径不匹配，则直接返回
		}
		//记录文件名和inode号
		f_name = (char *)file->f_path.dentry->d_name.name;
		ino = file->f_path.dentry->d_inode->i_ino;
		} else {
				filepath = inode_info->file_path;
				f_name = inode_info->file_name;
				ino = inode_info->ino;
		}	

	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}

	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	// if (likely(result_str)){
	// 	snprintf(result_str, RESULT_LEN, "File|%s|%s|%s|%s|%s|%lu|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, f_name, filepath, ino, WRITE_OP, ktime_get_real_seconds());
	// }
	// pr_info("%s",result_str);

	struct kevent* file_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
	if (likely(file_event)){
		snprintf(file_event->result, RESULT_LEN, "File|%s|%s|%s|%s|%s|%lu|%s",
				current->comm, exe_path, current->real_parent->comm, f_name, filepath, ino, WRITE_OP);
        spin_lock(&event_lock);
        if (atomic_read(&event_count) >= MAX_RECORDS) {
            struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
            list_del(&old->list);
            atomic_dec(&event_count);
            kmem_cache_free(event_cache, old);
        }
        list_add_tail(&file_event->list, &event_list);
        atomic_inc(&event_count);
        spin_unlock(&event_lock);
    }

    // 释放资源
    kfree(pname_buf);
	// if (likely(result_str))
	// 	kfree(result_str);
    // write_unlock(&write_lock);
	kfree(exe_buf);
    return 0;
}

static int read_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_arg1(regs);//因为x86的参数传递规则是di，si，dx，cx，r8，r9，所以di就是vfs_write的第一个参数。arm默认是r0，r1，r2，r3，相应的取r0
	// char *result_str = NULL;
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	char *f_name = NULL;
	unsigned long ino;
	char *exe_buf = NULL;
	char *exe_path = NULL;
	struct inode_info *inode_info;
	struct inode *inode;

    // 写锁保护
    // write_lock(&write_lock);

    // 只处理有效的文件写操作
    if (unlikely(!S_ISREG(file_inode(file)->i_mode))) {
        // write_unlock(&write_lock);
        return 0;
    }

    // 分配路径缓冲区
    pname_buf = f_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (unlikely(!pname_buf)) {
        // write_unlock(&write_lock);
        return 0;
    }

	inode = file_inode((const struct file *)file);
	if (unlikely(!inode))
	{
		kfree(pname_buf);
		return 0;
	}
	inode_info = find_inode(inode->i_ino);
	if (unlikely(!inode_info)){
		filepath = dentry_path_raw(file->f_path.dentry, pname_buf, PATH_MAX);
		if (unlikely(IS_ERR(filepath))) {
			kfree(pname_buf);
			return 0;
		}
		// 只监控特定目录的文件操作
		if (!is_target_path(filepath)) {
			kfree(pname_buf);
			return 0;  // 如果文件路径不匹配，则直接返回
		}
		//记录文件名和inode号
		f_name = (char *)file->f_path.dentry->d_name.name;
		ino = file->f_path.dentry->d_inode->i_ino;
		} else {
				filepath = inode_info->file_path;
				f_name = inode_info->file_name;
				ino = inode_info->ino;
			}	

	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}
	
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);


	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	// if (likely(result_str)){
	// 	snprintf(result_str, RESULT_LEN, "File|%s|%s|%s|%s|%s|%lu|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, f_name, filepath, ino, READ_OP, ktime_get_real_seconds());
	// }
	// pr_info("%s",result_str);

	struct kevent* file_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
	if (likely(file_event)){
		snprintf(file_event->result, RESULT_LEN, "File|%s|%s|%s|%s|%s|%lu|%s",
				current->comm, exe_path, current->real_parent->comm, f_name, filepath, ino, READ_OP);
        spin_lock(&event_lock);
        if (atomic_read(&event_count) >= MAX_RECORDS) {
            struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
            list_del(&old->list);
            atomic_dec(&event_count);
            kmem_cache_free(event_cache, old);
        }
        list_add_tail(&file_event->list, &event_list);
        atomic_inc(&event_count);
        spin_unlock(&event_lock);
    }
    // 释放资源
    kfree(pname_buf);
	// if (likely(result_str))
	// 	kfree(result_str);
    kfree(exe_buf);

    return 0;
}

static int rename_handler_pre(struct kprobe *p, struct pt_regs *regs){
	struct dentry *old_dentry = (struct dentry *)regs_get_arg2(regs);
	struct inode *old_inode;
	struct dentry *new_dentry = (struct dentry *)regs_get_arg4(regs);
	char *old_name = NULL;
	char *new_name = NULL;
	// char *result_str = NULL;
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	unsigned long ino;
	char *exe_buf = NULL;
	char *exe_path = NULL;
	struct inode_info *inode_info;

	if (unlikely(!old_dentry || !(old_dentry->d_inode) || !S_ISREG(old_dentry->d_inode->i_mode)))
		return 0;
	else 
		old_inode = old_dentry->d_inode;
	//分配路径缓冲区
	pname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!pname_buf)) {
		return 0;
	}

	//从哈希表中获取对应的文件信息
	inode_info = find_inode(old_inode->i_ino);
	if (unlikely(!inode_info)){
		filepath = dentry_path_raw(old_dentry, pname_buf, PATH_MAX);
		if (unlikely(IS_ERR(filepath))) {
			kfree(pname_buf);
			return 0;
		}

		// 只监控特定目录的文件操作
		if (!is_target_path(filepath)) {
			kfree(pname_buf);
			return 0;  // 如果文件路径不匹配，则直接返回
		}
		//记录原文件名和inode号
		old_name = (char *)old_dentry->d_name.name;
		ino = old_dentry->d_inode->i_ino;
		} else {
				filepath = inode_info->file_path;
				old_name = inode_info->file_name;
				ino = inode_info->ino;
			}	

	//获取新文件名
	if (unlikely(!new_dentry || !(new_dentry->d_inode) || !S_ISREG(new_dentry->d_inode->i_mode)))
	{
		kfree(pname_buf);
		return 0;
	}
	new_name = (char *)new_dentry->d_name.name;

	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	// if (likely(result_str)){
	// 	snprintf(result_str, RESULT_LEN, "File|%s|%s|%s|%s|%s|%s|%lu|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, old_name, filepath, new_name, ino, RENAME_OP, ktime_get_real_seconds());
	// }

	// pr_info("%s",result_str);

	struct kevent* file_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
	if (likely(file_event)){
		snprintf(file_event->result, RESULT_LEN, "File|%s|%s|%s|%s|%s|%s|%lu|%s",
				current->comm, exe_path, current->real_parent->comm, old_name, filepath, new_name, ino, RENAME_OP);
        spin_lock(&event_lock);
        if (atomic_read(&event_count) >= MAX_RECORDS) {
            struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
            list_del(&old->list);
            atomic_dec(&event_count);
            kmem_cache_free(event_cache, old);
        }
        list_add_tail(&file_event->list, &event_list);
        atomic_inc(&event_count);
        spin_unlock(&event_lock);
    }

    // 释放资源
    kfree(pname_buf);
	// if (likely(result_str))
	// 	kfree(result_str);
    // write_unlock(&write_lock);
	kfree(exe_buf);
    return 0;

}

static int close_handler_pre(struct kprobe *p, struct pt_regs *regs){
	struct file *file = (struct file *)regs_get_arg1(regs);
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	// char *result_str = NULL;
	char *f_name = NULL;
	unsigned long ino;
	struct inode *inode;
	char *exe_buf = NULL;
	char *exe_path = NULL;
	struct inode_info *inode_info;
	//只处理有效文件的关闭操作
	if (unlikely(!S_ISREG(file_inode(file)->i_mode))) {
		return 0;	
	}
	
	// 分配路径缓冲区
    pname_buf = f_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (unlikely(!pname_buf)) {
        // write_unlock(&write_lock);
        return 0;
    }

	//从哈希表中获取对应的文件信息
	inode = file_inode((const struct file *)file);
	if (unlikely(!inode))
	{
		kfree(pname_buf);
		return 0;
	}
	inode_info = find_inode(inode->i_ino);
	if (unlikely(!inode_info)){
		filepath = dentry_path_raw(file->f_path.dentry, pname_buf, PATH_MAX);
		if (unlikely(IS_ERR(filepath))) {
			kfree(pname_buf);
			return 0;
		}
		// 只监控特定目录的文件操作
		if (!is_target_path(filepath)) {
			kfree(pname_buf);
			return 0;  // 如果文件路径不匹配，则直接返回
		}

		//记录文件名和inode号
		f_name = (char *)file->f_path.dentry->d_name.name;
		ino = file->f_path.dentry->d_inode->i_ino;
		} else {
				filepath = inode_info->file_path;
				f_name = inode_info->file_name;
				ino = inode_info->ino;
			}	
	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	// if (likely(result_str)){
	// 	snprintf(result_str, RESULT_LEN, "File|%s|%s|%s|%s|%s|%lu|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, f_name, filepath, ino, CLOSE_OP, ktime_get_real_seconds());
	// }
	// pr_info("%s", result_str);

	struct kevent* file_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
	if (likely(file_event)){
		snprintf(file_event->result, RESULT_LEN, "File|%s|%s|%s|%s|%s|%lu|%s",
				current->comm, exe_path, current->real_parent->comm, f_name, filepath, ino, CLOSE_OP);
        spin_lock(&event_lock);
        if (atomic_read(&event_count) >= MAX_RECORDS) {
            struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
            list_del(&old->list);
            atomic_dec(&event_count);
            kmem_cache_free(event_cache, old);
        }
        list_add_tail(&file_event->list, &event_list);
        atomic_inc(&event_count);
        spin_unlock(&event_lock);
    }

	delete_inode(ino);
	kfree(pname_buf);
	// if (likely(result_str))
	// 	kfree(result_str);
	kfree(exe_buf);
	return 0;
}

static void create_handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	
	struct dentry *dentry = (struct dentry *)regs_get_arg2(regs);
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	// char *result_str = NULL;
	char *f_name = NULL;
	char *exe_buf = NULL;
	char *exe_path = NULL;
	// long long size;
	// long ino = DEFAULT_INO; 

	//分配内存给文件路径缓冲区
	pname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!pname_buf)) {
		return ;
	}

		//只处理有效的文件创建操作
	if (unlikely(IS_ERR_OR_NULL(dentry))){
		kfree(pname_buf);
		return ;	
	}
	//获取文件路径
	filepath = dentry_path_raw(dentry, pname_buf, PATH_MAX);
	if (unlikely(IS_ERR(filepath))) {
		kfree(pname_buf);
		return ;
	}
	// pr_info("%s\n", filepath);
	// 只监控特定目录的文件操作
	if (!is_target_path(filepath)) {
		kfree(pname_buf);
		return ;  // 如果文件路径不匹配，则直接返回
	}
	//记录文件名
	f_name = (char *)dentry->d_name.name;
	
	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return;
	}

	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);
	
	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	// if (likely(result_str)){
	// 	snprintf(result_str, RESULT_LEN, "File|%s|%s|%s|%s|%s|%d|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, f_name, filepath, DEFAULT_INO, CREATE_OP, ktime_get_real_seconds());
	// }
	// pr_info("%s", result_str);
	
	struct kevent* file_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
	if (likely(file_event)){
		snprintf(file_event->result, RESULT_LEN, "File|%s|%s|%s|%s|%s|%d|%s",
				current->comm, exe_path, current->real_parent->comm, f_name, filepath, DEFAULT_INO, CREATE_OP);
        spin_lock(&event_lock);
        if (atomic_read(&event_count) >= MAX_RECORDS) {
            struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
            list_del(&old->list);
            atomic_dec(&event_count);
            kmem_cache_free(event_cache, old);
        }
        list_add_tail(&file_event->list, &event_list);
        atomic_inc(&event_count);
        spin_unlock(&event_lock);
    }
	
	//释放内存资源
	kfree(pname_buf);
	// if (likely(result_str))
	// 	kfree(result_str);
	kfree(exe_buf);
	return;
}

static int delete_handler_pre(struct kprobe *p, struct pt_regs *regs){
	struct dentry *dentry = (struct dentry *)regs_get_arg2(regs);
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	// char *result_str = NULL;
	char *f_name = NULL;
	unsigned long ino;
	char *exe_buf = NULL;
	char *exe_path = NULL;
	struct inode_info *inode_info = NULL;

	//分配内存给文件路径缓冲区
	pname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!pname_buf)) {
		return 0;
	}

	//只处理有效的文件删除操作
	//|| !S_ISREG(dentry->d_inode->i_mode)
	if (unlikely(IS_ERR_OR_NULL(dentry) || !(dentry->d_inode))){
		kfree(pname_buf);
		return 0;	
	}

	//从哈希表中获取对应的文件信息
	inode_info = find_inode(dentry->d_inode->i_ino);
	if (unlikely(!inode_info)){
		filepath = dentry_path_raw(dentry, pname_buf, PATH_MAX);
		if (unlikely(IS_ERR(filepath))) {
			kfree(pname_buf);
			return 0;
		}

		// 只监控特定目录的文件操作
		if (!is_target_path(filepath)) {
			kfree(pname_buf);
			return 0;  // 如果文件路径不匹配，则直接返回
		}
		//记录文件名和inode号
		f_name = (char *)dentry->d_name.name;
		ino = dentry->d_inode->i_ino;
		} else {
				filepath = inode_info->file_path;
				f_name = inode_info->file_name;
				ino = inode_info->ino;
	}	
	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	// if (likely(result_str)){
	// 	snprintf(result_str, RESULT_LEN, "File|%s|%s|%s|%s|%s|%lu|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, f_name, filepath, ino, DELETE_OP, ktime_get_real_seconds());
	// }

	// pr_info("%s", result_str);

	struct kevent* file_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
	if (likely(file_event)){
		snprintf(file_event->result, RESULT_LEN, "File|%s|%s|%s|%s|%s|%lu|%s",
				current->comm, exe_path, current->real_parent->comm, f_name, filepath, ino, DELETE_OP);
        spin_lock(&event_lock);
        if (atomic_read(&event_count) >= MAX_RECORDS) {
            struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
            list_del(&old->list);
            atomic_dec(&event_count);
            kmem_cache_free(event_cache, old);
        }
        list_add_tail(&file_event->list, &event_list);
        atomic_inc(&event_count);
        spin_unlock(&event_lock);
    }
	//删除掉哈系表对应的文件信息
	delete_inode(ino);

	//释放内存资源
	kfree(pname_buf);
	// if (likely(result_str))
	// 	kfree(result_str);
	kfree(exe_buf);
	return 0;
}

static int open_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_arg1(regs);
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	// char *result_str = NULL;
	char *f_name = NULL;
	unsigned long ino;
	char *exe_buf = NULL;
	char *exe_path = NULL;
	int retval;

	//只处理有效的文件打开操作
	if (unlikely(IS_ERR_OR_NULL(file) || !(file->f_inode) || !S_ISREG(file->f_inode->i_mode))){
		return 0;	
	}

	//分配内存给文件路径缓冲区
	pname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!pname_buf)) {
		return 0;
	}

	//获取文件路径
	filepath = dentry_path_raw(file->f_path.dentry, pname_buf, PATH_MAX);
	if (unlikely(IS_ERR(filepath))){
		kfree(pname_buf);
		return 0;
	}

	// 只监控特定目录的文件操作
	if (!is_target_path(filepath)){
		kfree(pname_buf);
		return 0;
	}


	//记录文件名和inode号
	f_name = (char *)file->f_path.dentry->d_name.name;
	ino = file->f_inode->i_ino;

	//分配并将文件信息填充到inode_info中
	retval = add_inode(ino, f_name, filepath);
	if (!retval)
	{
		pr_info("add inode info failed\n");
		kfree(pname_buf);
		return 0;
	}

	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	// if (likely(result_str)){
	// 	snprintf(result_str, RESULT_LEN, "File|%s|%s|%s|%s|%s|%lu|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, f_name, filepath, ino, OPEN_OP, ktime_get_real_seconds());
	// }
	// pr_info("%s", result_str);

	struct kevent* file_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
	if (likely(file_event)){
		snprintf(file_event->result, RESULT_LEN, "File|%s|%s|%s|%s|%s|%lu|%s",
				current->comm, exe_path, current->real_parent->comm, f_name, filepath, ino, OPEN_OP);
        spin_lock(&event_lock);
        if (atomic_read(&event_count) >= MAX_RECORDS) {
            struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
            list_del(&old->list);
            atomic_dec(&event_count);
            kmem_cache_free(event_cache, old);
        }
        list_add_tail(&file_event->list, &event_list);
        atomic_inc(&event_count);
        spin_unlock(&event_lock);
    }

	//释放内存资源
	kfree(pname_buf);
	// if (likely(result_str))
	// 	kfree(result_str);
	kfree(exe_buf);
	return 0;
}

static int fork_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long child_pid = regs_return_value(regs); // 获取子进程PID
    char *p_exe_buf = NULL;
    char *c_exe_buf = NULL;
	// char *result_str = NULL;
    struct task_struct *parent = current;
    struct pid *cpid_struct = find_vpid(child_pid);
	struct task_struct *child = pid_task(cpid_struct, PIDTYPE_PID);
	// struct pt_regs *regs1 = task_pt_regs(current);
	// int syscall_no = regs1->orig_ax;  // x86架构系统调用号存储位置
    // 获取父进程信息
	p_exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!p_exe_buf)) {
		// kfree(pname_buf);
		return 0;
	}
    char *p_exe_path = get_exe_path(parent, p_exe_buf, PATH_MAX);
    
    // 获取子进程信息
    char *c_exe_path = DEFAULT_RET_STR;
	c_exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!c_exe_buf)) {
		// kfree(pname_buf);
		kfree(p_exe_buf);
		return 0;
	}
    if (child) {
        c_exe_path = get_exe_path(child, c_exe_buf, PATH_MAX);
        get_task_struct(child);
    }

	//filter tgid
	if (parent->pid == child->tgid){
		put_task_struct(child);
		kfree(p_exe_buf);
		kfree(c_exe_buf);
		return 0;
	}
	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	// if (likely(result_str)){
	// 	snprintf(result_str, RESULT_LEN, "Process|%s|%s|%s|%s|%lx|%s|%lld\n",
	// 		parent->comm, p_exe_path, child->comm, c_exe_path, regs_get_arg1(regs), FORK_OP, ktime_get_real_seconds());
	// }
    // 记录关键信息
    // pr_info("%s", result_str);
    
	struct kevent* process_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
	if (likely(process_event)){
		snprintf(process_event->result, RESULT_LEN, "Process|%s|%s|%s|%s|%lx|%s",
			parent->comm, p_exe_path, child->comm, c_exe_path, regs_get_arg1(regs), FORK_OP);
        spin_lock(&event_lock);
        if (atomic_read(&event_count) >= MAX_RECORDS) {
            struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
            list_del(&old->list);
            atomic_dec(&event_count);
            kmem_cache_free(event_cache, old);
        }
        list_add_tail(&process_event->list, &event_list);
        atomic_inc(&event_count);
        spin_unlock(&event_lock);
    }

    put_task_struct(child);

	// if (unlikely(!result_str)){
	// 	kfree(result_str);
	// }
	
	kfree(p_exe_buf);
	kfree(c_exe_buf);
    return 0;
}

static void execve_handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	char *exe_buf = NULL;
	// char *exe_parent_buf = NULL;
	char *exe_path = NULL;
	// char *exe_parent_path = NULL;
	char *pname_buf = NULL;
	// char * f_name = NULL;
	// char *result_str = NULL;
	struct linux_binprm *bprm = (struct linux_binprm *)regs_get_arg1(regs);
	struct file *file = bprm->file;
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = file_inode(file);
	//分配内存给进程执行路径缓冲区和父进程执行路径缓冲区
	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		return;
	}
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);
	// exe_parent_path = get_parent_exe_path(current, exe_parent_buf, PATH_MAX);
	// int ret;
	// ret = kern_path(filepath, LOOKUP_FOLLOW, &path);
	// if (ret == 0){
	// 	f_name = (char *)path.dentry->d_name.name;
	// 	path_put(&path);
	// }
	const char *filename = dentry->d_name.name;
	pname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!pname_buf)){
		kfree(exe_buf);
		return;
	}
	char *filepath = dentry_path_raw(dentry, pname_buf, PATH_MAX);
	unsigned long ino = inode->i_ino;
	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	// if (likely(result_str)){
	// 	snprintf(result_str, RESULT_LEN, "Process|%s|%s|%s|%s|%s|%ld|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, filepath, filename, ino, EXECVE_OP, ktime_get_real_seconds());
	// }
	// pr_info("%s", result_str);

	struct kevent* process_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
	if (likely(process_event)){
		snprintf(process_event->result, RESULT_LEN, "Process|%s|%s|%s|%s|%s|%ld|%s",
				current->comm, exe_path, current->real_parent->comm, filepath, filename, ino, EXECVE_OP);
        spin_lock(&event_lock);
        if (atomic_read(&event_count) >= MAX_RECORDS) {
            struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
            list_del(&old->list);
            atomic_dec(&event_count);
            kmem_cache_free(event_cache, old);
        }
        list_add_tail(&process_event->list, &event_list);
        atomic_inc(&event_count);
        spin_unlock(&event_lock);
    }

	//释放内存资源
	// if(unlikely(!result_str)){
	// 	kfree(result_str);
	// }
	kfree(exe_buf);
	kfree(pname_buf);
	return;
}

static void exit_handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	char *exe_buf = NULL;
	char *exe_path = NULL;
	// char *result_str = NULL;
	long exit_code = regs_get_arg1(regs);
	//分配内存给进程执行路径缓冲区和父进程执行路径缓冲区
	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		return;
	}

	//获取进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	// if (likely(result_str)){
	// 	snprintf(result_str, RESULT_LEN, "Process|%s|%s|%s|%ld|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, exit_code, EXIT_OP, ktime_get_real_seconds());
	// }
	// pr_info("%s", result_str);

	struct kevent* process_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
	if (likely(process_event)){
		snprintf(process_event->result, RESULT_LEN, "Process|%s|%s|%s|%ld|%s",
				current->comm, exe_path, current->real_parent->comm, exit_code, EXIT_OP);
        spin_lock(&event_lock);
        if (atomic_read(&event_count) >= MAX_RECORDS) {
            struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
            list_del(&old->list);
            atomic_dec(&event_count);
            kmem_cache_free(event_cache, old);
        }
        list_add_tail(&process_event->list, &event_list);
        atomic_inc(&event_count);
        spin_unlock(&event_lock);
    }

	//释放内存资源
	// if(unlikely(!result_str)){
	// 	kfree(result_str);
	// }
	kfree(exe_buf);


	return;
}

static void kill_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    pid_t pid = (pid_t)regs_get_arg3(regs);
    int sig = (int)regs_get_arg1(regs);
    // char *result_str = NULL;
	char *p_exe_buf = NULL;
    char *t_exe_buf = NULL;
    // struct task_struct *cur = current;
    struct pid *tpid_struct = find_vpid(pid);
	struct task_struct *target = pid_task(tpid_struct, PIDTYPE_PID);

	// struct pt_regs *regs1 = task_pt_regs(current);
	// int syscall_no = regs1->orig_ax;  // x86架构系统调用号存储位置
    // 获取父进程信息
	p_exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!p_exe_buf)) {
		// kfree(pname_buf);
		return;
	}
    char *p_exe_path = get_exe_path(current, p_exe_buf, PATH_MAX);
    
    // 获取子进程信息
    char *t_exe_path = DEFAULT_RET_STR;
	t_exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!t_exe_buf)) {
		// kfree(pname_buf);
		kfree(p_exe_buf);
		return;
	}
    if (target) {
        t_exe_path = get_exe_path(target, t_exe_buf, PATH_MAX);
        // get_task_struct(child);
    }

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	// if (likely(result_str)){
	// 	snprintf(result_str, RESULT_LEN, "Process|%s|%s|%s|%s|%s|%d|%s|%lld\n",
	// 		current->comm, p_exe_path, current->real_parent->comm, target->comm, t_exe_buf, sig, KILL_OP, ktime_get_real_seconds());
	// }
    // // 记录关键信息
    // pr_info("%s", result_str);

	struct kevent* process_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
	if (likely(process_event)){
		snprintf(process_event->result, RESULT_LEN, "Process|%s|%s|%s|%s|%s|%d|%s",
			current->comm, p_exe_path, current->real_parent->comm, target->comm, t_exe_path, sig, KILL_OP);
        spin_lock(&event_lock);
        if (atomic_read(&event_count) >= MAX_RECORDS) {
            struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
            list_del(&old->list);
            atomic_dec(&event_count);
            kmem_cache_free(event_cache, old);
        }
        list_add_tail(&process_event->list, &event_list);
        atomic_inc(&event_count);
        spin_unlock(&event_lock);
    }

	// if (unlikely(!result_str)){
	// 	kfree(result_str);
	// }

	kfree(p_exe_buf);
	kfree(t_exe_buf);

    return;
}

static int update_cred_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct update_cred_data *data;
	data = (struct update_cred_data *)ri->data;
	data->old_uid = current_uid();
	return 0;
}

static int update_cred_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	char *exe_buf = NULL;
	char *exe_path = NULL;
	// char *result_str = NULL;
	int now_uid = __kuid_val(current_uid());
    int retval = regs_return_value(regs);
	struct update_cred_data *data;
    //only get old uid ≠0 && new uid == 0
    if (now_uid != 0){
        return 0;
	}

    data = (struct update_cred_data *)ri->data;
    if (__kuid_val(data->old_uid) == 0) {
		return 0;
	}

	//分配内存给进程执行路径缓冲区和父进程执行路径缓冲区
	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		return 0;
	}

	//获取进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	// if (likely(result_str)){
	// 	snprintf(result_str, RESULT_LEN, "Process|%s|%s|%s|%d|%d|%d|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, data->old_uid.val, now_uid, retval, CRED_UP_OP, ktime_get_real_seconds());
	// }
	// pr_info("%s", result_str);

	struct kevent* process_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
	if (likely(process_event)){
		snprintf(process_event->result, RESULT_LEN, "Process|%s|%s|%s|%d|%d|%d|%s",
				current->comm, exe_path, current->real_parent->comm, data->old_uid.val, now_uid, retval, CRED_UP_OP);
        spin_lock(&event_lock);
        if (atomic_read(&event_count) >= MAX_RECORDS) {
            struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
            list_del(&old->list);
            atomic_dec(&event_count);
            kmem_cache_free(event_cache, old);
        }
        list_add_tail(&process_event->list, &event_list);
        atomic_inc(&event_count);
        spin_unlock(&event_lock);
    }

	//释放内存资源
	// if(unlikely(!result_str)){
	// 	kfree(result_str);
	// }
	kfree(exe_buf);


	return 0;
}

static int ip4_datagram_connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct net_data *data;
	data = (struct net_data *)ri->data;
	data->sa_family = AF_INET;
	data->sk = (struct sock *)regs_get_arg1(regs);
	return 0;
}

static int connect_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int retval, dport = 0, sport = 0;

    __be32 dip4 = 0, sip4 = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *exe_buf = NULL;
	// char *result_str = NULL;
    struct sock *sk;
    struct net_data *data;
    struct inet_sock *inet;

    retval = regs_return_value(regs);
    data = (struct net_data *)ri->data;

    sk = data->sk;
    if (IS_ERR_OR_NULL(sk)){
        return 0;
	}
	// if(retval != 0){
	// 	return 0;
	// }

    exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if(unlikely(!exe_buf)){
		return 0;
	}
    exe_path = get_exe_path(current, exe_buf, PATH_MAX);

    //only get AF_INET connect info
    inet = (struct inet_sock *)sk;
	dip4 = inet->inet_daddr;
	sip4 = inet->inet_saddr;
	sport = ntohs(inet->inet_sport);
	dport = ntohs(inet->inet_dport);

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);

    // if (dport != 0) {
    //     if (data->sa_family == AF_INET){
    //         //data->type, dport, dip4, exe_path, sip4,
    //         //               sport, retval;
	// 		snprintf(result_str, RESULT_LEN, "Netflow|%s|%s|%s|%pI4|%d|%pI4|%d|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, &sip4, sport, &dip4, dport, CONNECT_OP, ktime_get_real_seconds());
	// 	}
	// }
	// pr_info("%s", result_str);
    if (dport != 0){
		if (data->sa_family == AF_INET){
			struct kevent* net_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
			if (likely(net_event)){
				snprintf(net_event->result, RESULT_LEN, "Netflow|%s|%s|%s|%pI4|%d|%pI4|%d|%s",
						current->comm, exe_path, current->real_parent->comm, &sip4, sport, &dip4, dport, CONNECT_OP);
				spin_lock(&event_lock);
				if (atomic_read(&event_count) >= MAX_RECORDS) {
					struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
					list_del(&old->list);
					atomic_dec(&event_count);
					kmem_cache_free(event_cache, old);
				}
				list_add_tail(&net_event->list, &event_list);
				atomic_inc(&event_count);
				spin_unlock(&event_lock);
			}
		}
	}

    kfree(exe_buf);
	// kfree(result_str);

    return 0;
}

static int tcp_v4_connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct net_data *data;
	data = (struct net_data *)ri->data;
	data->sa_family = AF_INET;
	data->sk = (struct sock *)regs_get_arg1(regs);
	return 0;
}

static int udp_recvmsg_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
	
	struct net_data *data;
	data = (struct net_data *)ri->data;
	data->sa_family = AF_INET;
	data->sk = (struct sock *)regs_get_arg1(regs);

	return 0;
}

static int udp_recvmsg_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int retval, dport = 0, sport = 0;

    __be32 dip4 = 0, sip4 = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *exe_buf = NULL;
	// char *result_str = NULL;
    struct sock *sk;
    struct net_data *data;
    struct inet_sock *inet;

    retval = regs_return_value(regs);
    data = (struct net_data *)ri->data;

	if(retval < 0){
		return 0;
	}

    sk = data->sk;
    if (IS_ERR_OR_NULL(sk)){
        return 0;
	}

    exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if(unlikely(!exe_buf)){
		return 0;
	}
    exe_path = get_exe_path(current, exe_buf, PATH_MAX);

    //only get AF_INET connect info
    inet = (struct inet_sock *)sk;
	dip4 = inet->inet_daddr;
	sip4 = inet->inet_saddr;
	sport = ntohs(inet->inet_sport);
	dport = ntohs(inet->inet_dport);

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);

    // if (dport != 0) {
    //     if (data->sa_family == AF_INET){
    //         //data->type, dport, dip4, exe_path, sip4,
    //         //               sport, retval;
	// 		snprintf(result_str, RESULT_LEN, "Netflow|%s|%s|%s|%pI4|%d|%pI4|%d|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, &sip4, sport, &dip4, dport, RECV_OP, ktime_get_real_seconds());
	// 	}
	// }
	// pr_info("%s", result_str);
    
	if (dport != 0){
		if (data->sa_family == AF_INET){
			struct kevent* net_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
			if (likely(net_event)){
				snprintf(net_event->result, RESULT_LEN, "Netflow|%s|%s|%s|%pI4|%d|%pI4|%d|%s",
					current->comm, exe_path, current->real_parent->comm, &sip4, sport, &dip4, dport, RECV_OP);
				spin_lock(&event_lock);
				if (atomic_read(&event_count) >= MAX_RECORDS) {
					struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
					list_del(&old->list);
					atomic_dec(&event_count);
					kmem_cache_free(event_cache, old);
				}
				list_add_tail(&net_event->list, &event_list);
				atomic_inc(&event_count);
				spin_unlock(&event_lock);
			}
		}
	}

    kfree(exe_buf);
	// kfree(result_str);

    return 0;
}

static int udp_sendmsg_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
	
	struct net_data *data;
	data = (struct net_data *)ri->data;
	data->sa_family = AF_INET;
	data->sk = (struct sock *)regs_get_arg1(regs);

	return 0;
}

static int udp_sendmsg_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int retval, dport = 0, sport = 0;

    __be32 dip4 = 0, sip4 = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *exe_buf = NULL;
	// char *result_str = NULL;
    struct sock *sk;
    struct net_data *data;
    struct inet_sock *inet;

    retval = regs_return_value(regs);
    data = (struct net_data *)ri->data;

	if(retval < 0){
		return 0;
	}

    sk = data->sk;
    if (IS_ERR_OR_NULL(sk)){
        return 0;
	}
	// if(retval != 0){
	// 	return 0;
	// }

    exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if(unlikely(!exe_buf)){
		return 0;
	}
    exe_path = get_exe_path(current, exe_buf, PATH_MAX);

    //only get AF_INET connect info
    inet = (struct inet_sock *)sk;
	dip4 = inet->inet_daddr;
	sip4 = inet->inet_saddr;
	sport = ntohs(inet->inet_sport);
	dport = ntohs(inet->inet_dport);

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);

    // if (dport != 0) {
    //     if (data->sa_family == AF_INET){
    //         //data->type, dport, dip4, exe_path, sip4,
    //         //               sport, retval;
	// 		snprintf(result_str, RESULT_LEN, "Netflow|%s|%s|%s|%pI4|%d|%pI4|%d|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, &sip4, sport, &dip4, dport, SEND_OP, ktime_get_real_seconds());
	// 	}
	// }
	// pr_info("%s", result_str);
    
	if (dport != 0){
		if (data->sa_family == AF_INET){
			struct kevent* net_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
			if (likely(net_event)){
				snprintf(net_event->result, RESULT_LEN, "Netflow|%s|%s|%s|%pI4|%d|%pI4|%d|%s",
					current->comm, exe_path, current->real_parent->comm, &sip4, sport, &dip4, dport, SEND_OP);
				spin_lock(&event_lock);
				if (atomic_read(&event_count) >= MAX_RECORDS) {
					struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
					list_del(&old->list);
					atomic_dec(&event_count);
					kmem_cache_free(event_cache, old);
				}
				list_add_tail(&net_event->list, &event_list);
				atomic_inc(&event_count);
				spin_unlock(&event_lock);
			}
		}
	}

    kfree(exe_buf);
	// kfree(result_str);

    return 0;
}

static int tcp_sendmsg_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
	
	struct net_data *data;
	data = (struct net_data *)ri->data;
	data->sa_family = AF_INET;
	data->sk = (struct sock *)regs_get_arg1(regs);

	return 0;
}

static int tcp_sendmsg_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int retval, dport = 0, sport = 0;

    __be32 dip4 = 0, sip4 = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *exe_buf = NULL;
	// char *result_str = NULL;
    struct sock *sk;
    struct net_data *data;
    struct inet_sock *inet;

    retval = regs_return_value(regs);
    data = (struct net_data *)ri->data;

	if(retval < 0){
		return 0;
	}

    sk = data->sk;
    if (IS_ERR_OR_NULL(sk)){
        return 0;
	}
	// if(retval != 0){
	// 	return 0;
	// }

    exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if(unlikely(!exe_buf)){
		return 0;
	}
    exe_path = get_exe_path(current, exe_buf, PATH_MAX);

    //only get AF_INET connect info
    inet = (struct inet_sock *)sk;
	dip4 = inet->inet_daddr;
	sip4 = inet->inet_saddr;
	sport = ntohs(inet->inet_sport);
	dport = ntohs(inet->inet_dport);

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);

    // if (dport != 0) {
    //     if (data->sa_family == AF_INET){
    //         //data->type, dport, dip4, exe_path, sip4,
    //         //               sport, retval;
	// 		snprintf(result_str, RESULT_LEN, "Netflow|%s|%s|%s|%pI4|%d|%pI4|%d|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, &sip4, sport, &dip4, dport, SEND_OP, ktime_get_real_seconds());
	// 	}
	// }
	// pr_info("%s", result_str);
    
	if (dport != 0){
		if (data->sa_family == AF_INET){
			struct kevent* net_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
			if (likely(net_event)){
				snprintf(net_event->result, RESULT_LEN, "Netflow|%s|%s|%s|%pI4|%d|%pI4|%d|%s",
					current->comm, exe_path, current->real_parent->comm, &sip4, sport, &dip4, dport, SEND_OP);
				spin_lock(&event_lock);
				if (atomic_read(&event_count) >= MAX_RECORDS) {
					struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
					list_del(&old->list);
					atomic_dec(&event_count);
					kmem_cache_free(event_cache, old);
				}
				list_add_tail(&net_event->list, &event_list);
				atomic_inc(&event_count);
				spin_unlock(&event_lock);
			}
		}
	}

    kfree(exe_buf);
	// kfree(result_str);

    return 0;
}

static int tcp_recvmsg_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
	
	struct net_data *data;
	data = (struct net_data *)ri->data;
	data->sa_family = AF_INET;
	data->sk = (struct sock *)regs_get_arg1(regs);

	return 0;
}

static int tcp_recvmsg_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int retval, dport = 0, sport = 0;

    __be32 dip4 = 0, sip4 = 0;

    char *exe_path = DEFAULT_RET_STR;
    char *exe_buf = NULL;
	// char *result_str = NULL;
    struct sock *sk;
    struct net_data *data;
    struct inet_sock *inet;

    retval = regs_return_value(regs);
    data = (struct net_data *)ri->data;

	if(retval < 0){
		return 0;
	}

    sk = data->sk;
    if (IS_ERR_OR_NULL(sk)){
        return 0;
	}
	// if(retval != 0){
	// 	return 0;
	// }

    exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if(unlikely(!exe_buf)){
		return 0;
	}
    exe_path = get_exe_path(current, exe_buf, PATH_MAX);

    //only get AF_INET connect info
    inet = (struct inet_sock *)sk;
	dip4 = inet->inet_daddr;
	sip4 = inet->inet_saddr;
	sport = ntohs(inet->inet_sport);
	dport = ntohs(inet->inet_dport);

	// result_str = kzalloc(RESULT_LEN, GFP_KERNEL);

    // if (dport != 0) {
    //     if (data->sa_family == AF_INET){
    //         //data->type, dport, dip4, exe_path, sip4,
    //         //               sport, retval;
	// 		snprintf(result_str, RESULT_LEN, "Netflow|%s|%s|%s|%pI4|%d|%pI4|%d|%s|%lld\n",
	// 			current->comm, exe_path, current->real_parent->comm, &sip4, sport, &dip4, dport, RECV_OP, ktime_get_real_seconds());
	// 	}
	// }
	// pr_info("%s", result_str);
    
	if (dport != 0){
		if (data->sa_family == AF_INET){
			struct kevent* net_event = kmem_cache_alloc(event_cache, GFP_ATOMIC);
			if (likely(net_event)){
				snprintf(net_event->result, RESULT_LEN, "Netflow|%s|%s|%s|%pI4|%d|%pI4|%d|%s",
					current->comm, exe_path, current->real_parent->comm, &sip4, sport, &dip4, dport, RECV_OP);
				spin_lock(&event_lock);
				if (atomic_read(&event_count) >= MAX_RECORDS) {
					struct kevent *old = list_first_entry(&event_list,  struct kevent, list);
					list_del(&old->list);
					atomic_dec(&event_count);
					kmem_cache_free(event_cache, old);
				}
				list_add_tail(&net_event->list, &event_list);
				atomic_inc(&event_count);
				spin_unlock(&event_lock);
			}
		}
	}

    kfree(exe_buf);
	// kfree(result_str);

    return 0;
}

static void *event_seq_start(struct seq_file *s, loff_t *pos)
{
    spin_lock(&event_lock);
    return seq_list_start(&event_list, *pos);
}

static void *event_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    return seq_list_next(v, &event_list, pos);
}

static void event_seq_stop(struct seq_file *s, void *v)
{
    spin_unlock(&event_lock);
}

static int event_seq_show(struct seq_file *s, void *v)
{
    struct kevent *event = list_entry(v, struct kevent, list);

    int size = strlen(event->result);
    if (strncmp(event->result, pre_s, size) != 0){
        seq_printf(s, "%s|%lld\n", event->result,  ktime_get_real_ns());
        strncpy(pre_s, event->result, size);
    }
    return 0;
}

static const struct seq_operations event_seq_ops = {
    .start = event_seq_start,
    .next  = event_seq_next,
    .stop  = event_seq_stop,
    .show  = event_seq_show
};


// #if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
static int event_proc_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &event_seq_ops);
}

static const struct file_operations event_proc_fops = {
    .owner   = THIS_MODULE,
    .open    = event_proc_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = seq_release
};
// #else
// static int event_proc_open(struct inode *inode, struct file *file)
// {
//     return seq_open(file, &event_seq_ops);
// }

// static const struct proc_ops event_proc_fops = {
//     .proc_open    = event_proc_open,
//     .proc_read    = seq_read,
//     .proc_lseek   = seq_lseek,
//     .proc_release = seq_release
// };
// #endif

/* For each probe you need to allocate a kprobe structure */

struct kretprobe tcp_recvmsg_kretprobe = {
	.kp.symbol_name = "tcp_recvmsg",
	.data_size = sizeof(struct net_data),
	.handler = tcp_recvmsg_handler,
	.entry_handler = tcp_recvmsg_entry_handler,
};

struct kretprobe tcp_sendmsg_kretprobe = {
	.kp.symbol_name = "tcp_sendmsg",
	.data_size = sizeof(struct net_data),
	.handler = tcp_sendmsg_handler,
	.entry_handler = tcp_sendmsg_entry_handler,
};

struct kretprobe udp_recvmsg_kretprobe = {
	.kp.symbol_name = "udp_recvmsg",
	.data_size = sizeof(struct net_data),
	.handler = udp_recvmsg_handler,
	.entry_handler = udp_recvmsg_entry_handler,
};

struct kretprobe udp_sendmsg_kretprobe = {
	.kp.symbol_name = "udp_sendmsg",
	.data_size = sizeof(struct net_data),
	.handler = udp_sendmsg_handler,
	.entry_handler = udp_sendmsg_entry_handler,
};

struct kretprobe ip4_datagram_connect_kretprobe = {
	.kp.symbol_name = "ip4_datagram_connect",
	.data_size = sizeof(struct net_data),
	.handler = connect_handler,
	.entry_handler = ip4_datagram_connect_entry_handler,
};

struct kretprobe tcp_v4_connect_kretprobe = {
	.kp.symbol_name = "tcp_v4_connect",
	.data_size = sizeof(struct net_data),
	.handler = connect_handler,
	.entry_handler = tcp_v4_connect_entry_handler,
};

static struct kprobe execve_kprobe = {
	.symbol_name	= "security_bprm_check",
	.post_handler = execve_handler_post,
};

static struct kprobe exit_kprobe = {
	.symbol_name	= "do_exit",
	.post_handler = exit_handler_post,
};

static struct kprobe kill_kprobe = {
	.symbol_name = "kill_something_info",
	.post_handler = kill_post_handler,
};

static struct kprobe write_kprobe = {
	.symbol_name	= "vfs_write",
	.pre_handler = write_handler_pre,
};

static struct kprobe read_kprobe = {
	.symbol_name	= "vfs_read",
	.pre_handler = read_handler_pre,
};

static struct kprobe security_rename_kprobe = {
	.symbol_name = "security_inode_rename",
	.pre_handler = rename_handler_pre,
};

static struct kprobe close_kprobe = {
	.symbol_name = "filp_close",
	.pre_handler = close_handler_pre,
};

static struct kprobe create_kprobe = {
	.symbol_name = "ext4_create",
	.post_handler = create_handler_post,
};

static struct kprobe delete_kprobe = {
	.symbol_name = "security_inode_unlink",
	.pre_handler = delete_handler_pre,
};

static struct kprobe open_kprobe = {
	.symbol_name = "security_file_open",
	.pre_handler = open_handler_pre,
};

static struct kretprobe fork_kretprobe = {
    .kp.symbol_name = "_do_fork", // 5.4内核使用_do_fork
    .handler = fork_ret_handler,  // 返回处理函数
    .maxactive = 20,
};

struct kretprobe update_cred_kretprobe = {
	.kp.symbol_name = "commit_creds",
	.data_size = sizeof(struct update_cred_data),
	.handler = update_cred_handler,
	.entry_handler = update_cred_entry_handler,
};


static int register_write_kprobe(void){
	int ret;
	ret = register_kprobe(&write_kprobe);

	return ret;
}

static void unregister_write_kprobe(void){
	unregister_kprobe(&write_kprobe);
}

static int register_read_kprobe(void){
	int ret;
	ret = register_kprobe(&read_kprobe);

	return ret;
}

static void unregister_read_kprobe(void){
	unregister_kprobe(&read_kprobe);
}

static int register_rename_kprobe(void){
	int ret;
	ret = register_kprobe(&security_rename_kprobe);

	return ret;
}

static void unregister_rename_kprobe(void){
	unregister_kprobe(&security_rename_kprobe);
}

static int register_clsoe_kprobe(void){
	int ret;
	ret = register_kprobe(&close_kprobe);

	return ret;
}

static void unregister_close_kprobe(void){
	unregister_kprobe(&close_kprobe);
}

static int register_create_kprobe(void){
	int ret;
	ret = register_kprobe(&create_kprobe);

	return ret;
}

static void unregister_create_kprobe(void){
	unregister_kprobe(&create_kprobe);
}

static int register_delete_kprobe(void){
	int ret;
	ret = register_kprobe(&delete_kprobe);

	return ret;
}

static void unregister_delete_kprobe(void){
	unregister_kprobe(&delete_kprobe);
}

static int register_open_kprobe(void){
	int ret;
	ret = register_kprobe(&open_kprobe);

	return ret;
}

static void unregister_open_kprobe(void){
	unregister_kprobe(&open_kprobe);
}

static int register_fork_kretprobe(void){
	int ret;
	ret = register_kretprobe(&fork_kretprobe);

	return ret;
}

static void unregister_fork_kretprobe(void){
	unregister_kretprobe(&fork_kretprobe);
}

static int register_execve_kprobe(void){
	int ret;
	ret = register_kprobe(&execve_kprobe);

	return ret;
}

static void unregister_execve_kprobe(void){
	unregister_kprobe(&execve_kprobe);
}

static int register_exit_kprobe(void){
	int ret;
	ret = register_kprobe(&exit_kprobe);

	return ret;
}

static void unregister_exit_kprobe(void){
	unregister_kprobe(&exit_kprobe);
}

static int register_kill_kprobe(void){
	int ret;
	ret = register_kprobe(&kill_kprobe);

	return ret;
}

static void unregister_kill_kprobe(void){
	unregister_kprobe(&kill_kprobe);
}

static int register_update_cred_kretprobe(void){
	int ret;
	ret = register_kretprobe(&update_cred_kretprobe);

	return ret;
}

static void unregister_update_cred_kretprobe(void){
	unregister_kretprobe(&update_cred_kretprobe);
}

static int register_ip4_datagram_connect_kretprobe(void){
	int ret;
	ret = register_kretprobe(&ip4_datagram_connect_kretprobe);

	return ret;
}

static void unregister_ip4_datagram_connect_kretprobe(void){
	unregister_kretprobe(&ip4_datagram_connect_kretprobe);
}

static int register_tcp_v4_connect_kretprobe(void){
	int ret;
	ret = register_kretprobe(&tcp_v4_connect_kretprobe);

	return ret;
}

static void unregister_tcp_v4_connect_kretprobe(void){
	unregister_kretprobe(&tcp_v4_connect_kretprobe);
}

static int register_udp_recvmsg_kretprobe(void){
	int ret;
	ret = register_kretprobe(&udp_recvmsg_kretprobe);

	return ret;
}

static void unregister_udp_recvmsg_kretprobe(void){
	unregister_kretprobe(&udp_recvmsg_kretprobe);
}

static int register_udp_sendmsg_kretprobe(void){
	int ret;
	ret = register_kretprobe(&udp_sendmsg_kretprobe);

	return ret;
}

static void unregister_udp_sendmsg_kretprobe(void){
	unregister_kretprobe(&udp_sendmsg_kretprobe);
}

static int register_tcp_sendmsg_kretprobe(void){
	int ret;
	ret = register_kretprobe(&tcp_sendmsg_kretprobe);

	return ret;
}

static void unregister_tcp_sendmsg_kretprobe(void){
	unregister_kretprobe(&tcp_sendmsg_kretprobe);
}

static int register_tcp_recvmsg_kretprobe(void){
	int ret;
	ret = register_kretprobe(&tcp_recvmsg_kretprobe);

	return ret;
}

static void unregister_tcp_recvmsg_kretprobe(void){
	unregister_kretprobe(&tcp_recvmsg_kretprobe);
}

static int install_kprobe(void){
	int ret;
	ret = register_write_kprobe();
	if (ret < 0)
		pr_err("register_write_kprobe failed, returned %d\n", ret);
	
	ret = register_read_kprobe();
	if (ret < 0)
		pr_err("register_read_kprobe failed, returned %d\n", ret);

	ret = register_rename_kprobe();
	if (ret < 0)
		pr_err("register_rename_kprobe failed, returned %d\n", ret);
	
	ret = register_clsoe_kprobe();
	if (ret < 0)
		pr_err("register_close_kprobe failed, returned %d\n", ret);

	ret = register_create_kprobe();
	if (ret < 0)
		pr_err("register_create_kprobe failed, returned %d\n", ret);

	ret = register_delete_kprobe();
	if (ret < 0)
		pr_err("register_delete_kprobe failed, returned %d\n", ret);

	ret = register_open_kprobe();
	if (ret < 0)
		pr_err("register_open_kprobe failed, returned %d\n", ret);	

	ret = register_fork_kretprobe();
	if (ret < 0)
		pr_err("register_fork_kretprobe failed, returned %d\n", ret);	

	ret = register_execve_kprobe();
	if (ret < 0)
		pr_err("register_execve_kprobe failed, returned %d\n", ret);
	
	ret = register_exit_kprobe();
	if (ret < 0)
		pr_err("register_exit_kprobe failed, returned %d\n", ret);

	ret = register_kill_kprobe();
	if (ret < 0)
		pr_err("register_kill_kprobe failed, returned %d\n", ret);

	ret = register_update_cred_kretprobe();
	if (ret < 0)
		pr_err("register_update_cred_kretprobe failed, returned %d\n", ret);

	ret = register_ip4_datagram_connect_kretprobe();
	if (ret < 0)
		pr_err("register_ip4_datagram_connect_kretprobe failed, returned %d\n", ret);

	ret = register_tcp_v4_connect_kretprobe();
	if (ret < 0)
		pr_err("register_tcp_v4_connect_kretprobe failed, returned %d\n", ret);

	ret = register_udp_recvmsg_kretprobe();
	if (ret < 0)
		pr_err("register_udp_recvmsg_kretprobe failed, returned %d\n", ret);

	ret = register_udp_sendmsg_kretprobe();
	if (ret < 0)
		pr_err("register_udp_sendmsg_kretprobe failed, returned %d\n", ret);

	ret = register_tcp_recvmsg_kretprobe();
	if (ret < 0)
		pr_err("register_tcp_recvmsg_kretprobe failed, returned %d\n", ret);

	ret = register_tcp_sendmsg_kretprobe();
	if (ret < 0)
		pr_err("register_tcp_sendmsg_kretprobe failed, returned %d\n", ret);
	
	return ret;
}

static void uninstall_kprobe(void){
	unregister_write_kprobe();
	unregister_read_kprobe();
	unregister_rename_kprobe();
	unregister_close_kprobe();
	unregister_create_kprobe();
	unregister_delete_kprobe();
	unregister_open_kprobe();
	unregister_fork_kretprobe();
	unregister_execve_kprobe();
	unregister_exit_kprobe();
	unregister_kill_kprobe();
	unregister_update_cred_kretprobe();
	unregister_ip4_datagram_connect_kretprobe();
	unregister_tcp_v4_connect_kretprobe();
	unregister_udp_recvmsg_kretprobe();
	unregister_udp_sendmsg_kretprobe();
	unregister_tcp_recvmsg_kretprobe();
	unregister_tcp_sendmsg_kretprobe();
}

static int __init kprobe_init(void)
{
	int ret;

	// mutex_init(&kmutex);
	// rwlock_init(&write_lock);
	event_cache = kmem_cache_create_usercopy(
		"kernel_event_cache",
		sizeof(struct kevent),
		0,
		SLAB_PANIC | SLAB_ACCOUNT,
		0,
		sizeof(struct kevent),
		NULL);
	
		
	proc_entry = proc_create("kernel_events", 0444, NULL, &event_proc_fops);
	if (!proc_entry) {
		kmem_cache_destroy(event_cache);
		return -ENOMEM;
	}
	ret = install_kprobe();
	if (ret < 0) {
		pr_err("register_kprobe failed\n, returned %d\n", ret);
		return ret;
	}

	/* 预处理路径 */
    int i;
	/* 处理排除路径 */
    for (i = 0; i < exclude_count; i++) {
        sorted_exclude[i].path = exclude_paths[i];
        sorted_exclude[i].len = strlen(exclude_paths[i]);
    }

    /* 对排除路径排序 */
    sort(sorted_exclude, exclude_count, sizeof(struct path_info),
         compare_path, NULL);

    pr_info("Sorted exclude paths, %d paths excluded\n", exclude_count);
    // for (i = 0; i < exclude_count; i++) {
    //     pr_info("Exclude %d: %s (len=%zu)\n", 
    //         i, sorted_exclude[i].path, sorted_exclude[i].len);
    // }

	if (path_count == 0) {
        target_paths[0] = "/";
        path_count = 1;
    }

    for (i = 0; i < path_count; i++) {
        sorted_paths[i].path = target_paths[i];
        sorted_paths[i].len = strlen(target_paths[i]);
    }

    /* 按路径长度降序排序 */
    sort(sorted_paths, path_count, sizeof(struct path_info), 
        compare_path, NULL);

    pr_info("Sorted monitoring paths, %d paths monitored\n", path_count);

    // for (i = 0; i < path_count; i++) {
    //     pr_info("Path %d: %s (len=%zu)\n", 
    //         i, sorted_paths[i].path, sorted_paths[i].len);
    // }

	pr_info("register_ kprobe success: create/open/write/read/rename/close/delete/fork/execve/exit/kill/update_cred/connect/send/recv_k(ret)probe.\n");
	rwlock_init(&inode_hash_lock);
	return 0;
}

static void __exit kprobe_exit(void)
{
	struct kevent *event, *tmp;
	uninstall_kprobe();
	remove_proc_entry("kernel_events", NULL);
    
    spin_lock(&event_lock);
    list_for_each_entry_safe(event, tmp, &event_list, list) {
        list_del(&event->list);
        kmem_cache_free(event_cache, event);
    }
    spin_unlock(&event_lock);
    
    kmem_cache_destroy(event_cache);

	pr_info("kprobe unregistered\n");
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
