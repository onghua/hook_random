#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched/mm.h>
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/memory.h>

// ========== 跨进程读（access_process_vm 版本，静态缓存） ==========
bool read_process_memory(pid_t pid, uintptr_t addr, void __user *buffer, size_t size)
{
    struct task_struct *task;
    struct pid *pid_struct;
    size_t bytes_this_page;
    uintptr_t current_va = addr;
    uint8_t __user *buf = (uint8_t __user *)buffer;
    size_t remaining = size;
    int ret;
    static uint8_t kern_buf[PAGE_SIZE];

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return false;

    get_task_struct(task);

    while (remaining > 0) {
        size_t offset = current_va & (PAGE_SIZE - 1);
        bytes_this_page = PAGE_SIZE - offset;
        if (bytes_this_page > remaining)
            bytes_this_page = remaining;

        ret = access_process_vm(task, current_va, kern_buf, bytes_this_page, FOLL_FORCE);
        if (ret > 0) {
            if (copy_to_user(buf, kern_buf, ret)) {
                put_task_struct(task);
                return false;
            }
        }

        buf += bytes_this_page;
        remaining -= bytes_this_page;
        current_va += bytes_this_page;
    }

    put_task_struct(task);
    return true;
}

// ========== 跨进程写（access_process_vm 版本，静态缓存） ==========
bool write_process_memory(pid_t pid, uintptr_t addr, const void __user *buffer, size_t size)
{
    struct task_struct *task;
    struct pid *pid_struct;
    size_t bytes_this_page;
    uintptr_t current_va = addr;
    const uint8_t __user *buf = (const uint8_t __user *)buffer;
    size_t remaining = size;
    int ret;
    static uint8_t kern_buf[PAGE_SIZE];

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return false;

    get_task_struct(task);

    while (remaining > 0) {
        size_t offset = current_va & (PAGE_SIZE - 1);
        bytes_this_page = PAGE_SIZE - offset;
        if (bytes_this_page > remaining)
            bytes_this_page = remaining;

        if (copy_from_user(kern_buf, buf, bytes_this_page)) {
            put_task_struct(task);
            return false;
        }

        ret = access_process_vm(task, current_va, kern_buf, bytes_this_page, FOLL_FORCE | FOLL_WRITE);

        buf += bytes_this_page;
        remaining -= bytes_this_page;
        current_va += bytes_this_page;
    }

    put_task_struct(task);
    return true;
}
