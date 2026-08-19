#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_process.h"        // PID 哈希链隐藏
#include "bypass_cfi.h"          // 提供 generic_kallsyms_lookup_name 和 bypass_cfi
#include "inline_hook_frame.h"   // 使用 inline hook 框架
#include "hide_kgsl.h"           // 隐藏当前进程（KGSL 节点）
#include "virtual_input.h"
#include "process_memory_enum.h"
#include "hide_proc.h"           // /proc 目录过滤
#include "virtual_gyro.h"        // 虚拟陀螺仪支持

// 打开文件
int my_flip_open(const char *filename, int flags, umode_t mode, struct file **f) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    *f = filp_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#else
    static struct file* (*reserve_flip_open)(const char *filename, int flags, umode_t mode) = NULL;
    if (reserve_flip_open == NULL) {
        reserve_flip_open = (struct file* (*)(const char *, int, umode_t))
            generic_kallsyms_lookup_name("filp_open");
        if (reserve_flip_open == NULL) return 0;
    }
    *f = reserve_flip_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#endif
}

// 关闭文件
int my_flip_close(struct file **f, fl_owner_t id) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    filp_close(*f, id);
    return 0;
#else
    static int (*reserve_flip_close)(struct file *, fl_owner_t) = NULL;
    if (reserve_flip_close == NULL) {
        reserve_flip_close = (int (*)(struct file *, fl_owner_t))
            generic_kallsyms_lookup_name("filp_close");
        if (reserve_flip_close == NULL) return 0;
    }
    return reserve_flip_close(*f, id);
#endif
}

// 检查文件是否存在
bool is_file_exist(const char *filename) {
    struct file* fp;
    if(my_flip_open(filename, O_RDONLY, 0, &fp) == 0) {
        if (!IS_ERR(fp)) {
            my_flip_close(&fp, NULL);
            return true;
        }
        return false;
    }
    return false;
}

// 移除proc文件
void cuteBabyPleaseDontCry(void) {
    if (is_file_exist("/proc/sched_debug"))
        remove_proc_entry("sched_debug", NULL);
    if (is_file_exist("/proc/uevents_records"))
        remove_proc_entry("uevents_records", NULL);
}

/* 隐藏模块（注释）
static struct list_head *mod_list;
void hide_module(void) {
    mod_list = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
}
*/

// ========== 处理 ioctl 调用 ==========
static long dispatch_ioctl(unsigned int cmd, unsigned long arg)
{
        static COPY_MEMORY cm;
        static MODULE_BASE mb;
        static char name[0x100] = {0};
        static struct GET_PID pd;
        static struct virtual_input vi;
        static struct module_scan_arg scan_arg;
        static struct virtual_gyro gyro_data;   // 用于接收陀螺仪上报数据

        switch (cmd) {
                case OP_READ_MEM:
                {
                        if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                                return -1;
                        }
                        if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                                return -1;
                        }
                }
                break;
                case OP_WRITE_MEM:
                {
                        if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                                return -1;
                        }
                        if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                                return -1;
                        }
                }
                break; 
                case OP_MODULE_BASE: // 获取模块基址
                {
                        if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0
                        || copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) !=0) {
                                return -1;
                        }
                        mb.base = get_module_base(mb.pid, name);
                        if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) !=0) {
                                return -1;
                        }
                }
                break;
                case OP_GET_PID: // 根据进程名获取 PID
                {
                        if (copy_from_user(&pd, (void __user*)arg, sizeof(pd)) != 0) {
                                return -1;
                        }
                        pd.pid = get_process_pid(pd.name);
                        if (copy_to_user((void __user*)arg, &pd, sizeof(pd)) != 0) {
                                return -1;
                        }
                }
                break;
                case OP_HIDE_PROCESS: // 手动隐藏当前进程（PID 哈希链删除，退出时自动恢复）
                {
                        hide_kgsl_install(task_pid_nr(current));    // 隐藏高通GPU节点
                        hide_task_install(task_pid_nr(current)); // 隐藏当前进程（/proc 目录过滤）
                        hide_current_process();                     // 隐藏 PID 哈希链隐藏
                }
                break; 
                /* ---------- 触摸操作 ---------- */
                case op_InitTouch:                 // 初始化触摸驱动，获取屏幕最大尺寸
                        if (copy_from_user(&vi, (void __user*)arg, sizeof(vi)) != 0) {
                                return -EFAULT;
                        }
                        if (v_touch_init(&vi.POSITION_X, &vi.POSITION_Y) != 0) {
                                return -EFAULT;
                        }
                        if (copy_to_user((void __user*)arg, &vi, sizeof(vi)) != 0) {
                                return -EFAULT;
                        }
                        break;
                case op_DelTouch:                  // 销毁触摸驱动，清理资源
                        v_touch_destroy();
                        break;
                case op_down:                      // 手指按下，在指定坐标模拟按下事件
                case op_move:                      // 手指移动，更新触摸位置
                case op_up:                        // 手指抬起，结束触摸
                        if (copy_from_user(&vi, (void __user*)arg, sizeof(vi)) != 0) {
                                return -EFAULT;
                        }
                        v_touch_event((req_op)cmd, vi.slot, vi.x, vi.y);
                        break;

                /* ---------- 获取进程所有模块 ---------- */
                case OP_GET_MODULES:
                {
                        // 从用户空间复制参数（包含 pid 和 info）
                        if (copy_from_user(&scan_arg, (void __user *)arg, sizeof(scan_arg)) != 0) {
                                return -EFAULT;
                        }
                        // 调用枚举函数，填充 scan_arg.info
                        if (enum_process_memory(scan_arg.pid, &scan_arg.info) != 0) {
                                return -EFAULT;
                        }
                        // 将填充后的结构体写回用户空间
                        if (copy_to_user((void __user *)arg, &scan_arg, sizeof(scan_arg)) != 0) {
                                return -EFAULT;
                        }
                        break;
                }

                /* ---------- 陀螺仪操作 ---------- */
                case OP_GYRO_INIT:                 // 初始化虚拟陀螺仪，安装 sendto inline hook
                        if (v_gyro_init() != 0) {
                                return -EFAULT;
                        }
                        break;
                case OP_GYRO_REPORT:               // 上报陀螺仪三轴数据（单位：mrad/s）
                        if (copy_from_user(&gyro_data, (void __user*)arg, sizeof(gyro_data)) != 0) {
                                return -EFAULT;
                        }
                        v_gyro_report(gyro_data.gyro_x_mrad_s, gyro_data.gyro_y_mrad_s, gyro_data.gyro_z_mrad_s);
                        break;
                case OP_GYRO_DESTROY:              // 销毁虚拟陀螺仪，卸载 inline hook
                        v_gyro_destroy();
                        break;

                default:
                        return -ENOTTY; // 返回错误
        }
        return 0;
}

// ==================== inline hook 工作函数 ====================
static int random_ioctl_work_fn(struct pt_regs *regs)
{        
    unsigned int cmd = regs->regs[1];   // x1: 第二个参数 cmd
    unsigned long arg = regs->regs[2];  // x2: 第三个参数 arg
    long ret;

    // 只拦截我们关心的 cmd 范围，其它继续原函数
    if (cmd >= OP_READ_MEM && cmd <= OP_GYRO_DESTROY) {
        ret = dispatch_ioctl(cmd, arg);
        regs->regs[0] = ret;            // 修改返回值 x0
        return 1;                       // 跳过原函数执行
    }
    return 0;                           // 继续执行原 random_ioctl
}

// ==================== do_exit 回调 ====================
static int do_exit_work_fn(struct pt_regs *regs)
{
    int pid = task_pid_nr(current);
    printk("[DREAM] 进程退出: PID=%d\n", pid);

    hide_kgsl_remove(pid);    // 恢复 KGSL 隐藏钩子
    hide_task_remove(pid);    // 恢复 /proc 过滤钩子

    return 0;
}

// ========== Hook 条目列表 ==========
static struct hook_entry hooks[] = {
    HOOK_ENTRY("random_ioctl", random_ioctl_work_fn),
    HOOK_ENTRY("do_exit", do_exit_work_fn),
};

static int __init my_module_init(void) {
    // 尝试绕过 CFI
    bypass_cfi();
    // 隐藏模块();
    //hide_module();

    // 移除proc文件();
    cuteBabyPleaseDontCry();
    
    // 安装 inline hook
    if (inline_hook_install(hooks) < 0) {
        printk(KERN_ERR "安装 inline hook 失败\n");
        return 0;
    }

    printk(KERN_INFO "自定义系统调用模块已加载（使用 inline hook）\n");
    return 0;
}

static void __exit my_module_exit(void) {
    inline_hook_remove(hooks); // 卸载 inline hook
    printk(KERN_INFO "自定义系统调用模块已卸载\n");
}

module_init(my_module_init);
module_exit(my_module_exit);
MODULE_LICENSE("GPL");
