#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/sched/mm.h>

#include "process_memory_enum.h"   // 包含 enum_process_memory 及相关结构
#include "bypass_cfi.h"            // 提供 generic_kallsyms_lookup_name

/**
 * 通过 enum_process_memory 获取指定模块的基址（RX 段起始地址）
 * @param pid     目标进程 PID
 * @param name    模块文件名（如 "libil2cpp.so"），不含路径
 * @return        模块基址（0 表示未找到）
 */
static uintptr_t get_module_base(pid_t pid, const char *name)
{
    // 静态变量，避免动态分配失败，获取不到模块地址
    static struct memory_info info;
    int ret, i, j;
    uintptr_t base = 0;
    size_t name_len = strlen(name);

    if (!name || name_len == 0)
        return 0;

    // 调用 enum_process_memory 获取完整内存布局
    ret = enum_process_memory(pid, &info);
    if (ret != 0)
        return 0;

    // 遍历所有模块
    for (i = 0; i < info.module_count; i++) {
        struct module_info *mod = &info.modules[i];
        // 从完整路径中提取文件名（最后一个'/'之后的部分）
        const char *slash = strrchr(mod->name, '/');
        const char *file_name = slash ? slash + 1 : mod->name;

        // 比较文件名（不区分路径）
        if (strcmp(file_name, name) == 0) {
            // 找到目标模块，遍历其段，找到第一个 RX 段（index == 0）
            for (j = 0; j < mod->seg_count; j++) {
                if (mod->segs[j].index == 0) {   // RX 段
                    base = mod->segs[j].start;   // 模块基址 = RX 段起始地址
                    break;
                }
            }
            break;
        }
    }

    // 注意：enum_process_memory 内部已分配内存，但所有内存已在函数内部释放，
    // info 中的模块名字符串是复制过的，不会失效，因此上面比较是安全的。

    return base;
}

/* 根据进程名获取 PID - 使用动态解析的 get_cmdline */
static pid_t get_process_pid(const char *name)
{
    typedef int (*get_cmdline_t)(struct task_struct *, char *, int);
    static get_cmdline_t get_cmdline_ptr = NULL;
    struct task_struct *task;
    char cmdline[256];
    pid_t pid = -ESRCH;
    
    if (!name || !*name)
        return -EINVAL;
    
    if (!get_cmdline_ptr) {
        unsigned long addr = generic_kallsyms_lookup_name("get_cmdline");
        if (!addr)
            return -ENOENT;
        get_cmdline_ptr = (get_cmdline_t)addr;
    }
    
    rcu_read_lock();
    for_each_process(task) {
        if (!task->mm)
            continue;
        
        // 使用动态获取的 get_cmdline 函数
        if (get_cmdline_ptr(task, cmdline, sizeof(cmdline)) > 0) {
            if (strcmp(cmdline, name) == 0) {
                pid = task->pid;
                break;
            }
        }
    }
    rcu_read_unlock();
    
    return pid;
}

/* 根据进程名获取 PID */
/*static pid_t get_process_pid(const char *name)
{
    struct task_struct *task;
    pid_t pid = -ESRCH;
    char buf[256];
    
    rcu_read_lock();
    for_each_process(task) {
        struct mm_struct *mm = task->mm;
        if (!mm)
            continue;
        unsigned long arg_start = mm->arg_start;
        unsigned long arg_end = mm->arg_end;
        size_t len = arg_end - arg_start;
        if (len > sizeof(buf) - 1)
            len = sizeof(buf) - 1;
        if (len > 0) {
            // 使用 access_process_vm 读取用户态命令行
            int ret = access_process_vm(task, arg_start, buf, len, FOLL_FORCE);
            if (ret > 0) {
                buf[ret] = '\0';
                if (strcmp(buf, name) == 0) {
                    pid = task->pid;
                    break;
                }
            }
        }
    }
    rcu_read_unlock();
    return pid;
}*/
