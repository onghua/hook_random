#include <linux/slab.h>
#include <linux/random.h>
#include <linux/string.h>

#include "process_memory_enum.h"

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char* name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE; 

struct GET_PID {
    char name[256];        // 进程名
    pid_t pid;             // 返回的PID
};

/* 用户空间传入的结构体（用于扫描模块） */
struct module_scan_arg {
    pid_t pid;
    struct memory_info info;
};

// 触摸相关结构体 
struct virtual_input {
    int slot;        // 触摸槽位
    int x;           // 触摸坐标x（用于 op_down/move/up）
    int y;           // 触摸坐标y（用于 op_down/move/up）
    int POSITION_X;  // 触摸驱动返回屏幕维度X（用于 op_InitTouch）
    int POSITION_Y;  // 触摸驱动返回屏幕维度Y（用于 op_InitTouch）
};
// 为了兼容 v_touch_event 的参数类型，将 req_op 定义为 int
typedef int req_op;

// 陀螺仪相关结构体
struct virtual_gyro {
    int gyro_x_mrad_s;  // 绕 X 轴角速度，单位：mrad/s（毫弧度/秒）
    int gyro_y_mrad_s;  // 绕 Y 轴角速度，单位：mrad/s
    int gyro_z_mrad_s;  // 绕 Z 轴角速度，单位：mrad/s
};

enum OPERATIONS {
	OP_DRIVER_PING  = 0x800,   // 驱动在线检查
	OP_READ_MEM = 0x801, // 读内存
	OP_WRITE_MEM = 0x802, // 写内存
	OP_MODULE_BASE = 0x803, // 内核获取模块地址    
	OP_GET_PID = 0x804, // 内核获取PID进程
	OP_HIDE_PROCESS = 0x805, // 隐藏当前进程

	// ---------- 触摸注入操作 ----------
        op_down = 0x807, // 手指按下	
        op_move = 0x808, // 手指移动
        op_up   = 0x809, // 手指抬起
        op_InitTouch = 0x810, // 初始化触摸
        op_DelTouch = 0x811, // 清理触摸
        
        OP_GET_MODULES = 0x812, // 用于扫描模块
        
        // ---------- 陀螺仪操作 ----------
        OP_GYRO_INIT   = 0x813, // 初始化虚拟陀螺仪
        OP_GYRO_REPORT = 0x814, // 上报陀螺仪三轴数据（单位 mrad/s）
        OP_GYRO_DESTROY= 0x815,  // 销毁虚拟陀螺仪，卸载 hook
};
