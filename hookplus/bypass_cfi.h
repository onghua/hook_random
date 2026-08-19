#ifndef _EXPORT_FUN_H_
#define _EXPORT_FUN_H_

#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/types.h>
#include <linux/kprobes.h>

/* ========================= 第一部分：获取内核符号 ========================= */

// 屏蔽 CFI 检查，统一利用 kprobe 获取 kallsyms_lookup_name 地址
__attribute__((no_sanitize("cfi"))) static unsigned long generic_kallsyms_lookup_name(const char *name)
{
        unsigned long (*fn_kallsyms_lookup_name)(const char *name) = NULL;
        struct kprobe kp = {0};

        if (!fn_kallsyms_lookup_name)
        {
                kp.symbol_name = "kallsyms_lookup_name";
                if (register_kprobe(&kp) < 0)
                        return 0;
                fn_kallsyms_lookup_name = (void *)kp.addr;
                unregister_kprobe(&kp);
        }

        if (!fn_kallsyms_lookup_name)
                return 0;

        return fn_kallsyms_lookup_name(name);
}
int (*fn_aarch64_insn_patch_text)(void *addrs[], uint32_t insns[], int cnt);

/* ========================= 第二部分：绕过 5.x 的 CFI ========================= */

/*

旧版 CFI ( GKI 5.10 / 5.15):
        编译器编译时进行类型哈希计算，在间接调用前插入跳转，跳到一个集中的验证函数（就是 __cfi_slowpath）来运行时比对，
        校验失败直接panic
        你把它 patch 成 RET，相当于让验证永远通过
新版 KCFI (Kernel 6.1+):
        内核去掉了集中验证函数。编译器会在每一个间接跳转（BLR）指令的前面，内联插入几条汇编指令，
        直接比较 hash 值。如果不对，直接触发 BRK 指令宕机。
如果是 6.1+ 内核，不存在 __cfi_slowpath，

所以有好人给了一个5系的解决代码给我，所以5系就不用下面纯汇编进行间接调用了
感谢bypass_cfi由https://github.com/wangchuan2009(忘川)，处理运行时校验函数来过5系cfi
*/

__attribute__((no_sanitize("cfi"))) bool bypass_cfi(void)
{
        // AArch64 RET 指令机器码
#define AARCH64_RET_INSTR 0xD65F03C0
        // 内部状态，记录是否已经热更新成功
        static bool is_cfi_bypassed = false;
        uint64_t cfi_addr = 0;
        void *patch_addrs[1];
        uint32_t patch_insns[1] = {AARCH64_RET_INSTR};

        if (is_cfi_bypassed)
                return true;

        // 获取同步 patch 函数：内部使用 stop_machine，避免其他 CPU 执行到半补丁状态。
        /*
        注意：aarch64_insn_patch_text_nosync不同步多cpu
        在patch目标地址多行指令时很可能导致其他cpu执行到半补丁状态，
        为了防止这个情况使用aarch64_insn_patch_text，
        如继续使用nosync，需要在patch时用stop_machine 来停止所有cpu,再热循环补丁，
        不过aarch64_insn_patch_text就是用的我说的这个方式，
        aarch64_insn_patch_text内部也是stop_machine 停止其他cpu，
        在循环调用aarch64_insn_patch_text_nosync来patch指令
        */
        fn_aarch64_insn_patch_text =
            (void *)generic_kallsyms_lookup_name("aarch64_insn_patch_text");

        if (!fn_aarch64_insn_patch_text)
                return false;

        //  依次查找各个版本的 CFI slowpath 函数
        cfi_addr = generic_kallsyms_lookup_name("__cfi_slowpath"); // 5.10
        if (!cfi_addr)
                cfi_addr = generic_kallsyms_lookup_name("__cfi_slowpath_diag"); // 5.15
        if (!cfi_addr)
                cfi_addr = generic_kallsyms_lookup_name("_cfi_slowpath"); // 5.4

        if (!cfi_addr)
                return false;

        // 强行 Patch 成 RET 指令 (直接返回，使得所有 CFI 校验默认通过)
        patch_addrs[0] = (void *)cfi_addr;
        if (fn_aarch64_insn_patch_text(patch_addrs, patch_insns, 1) != 0)
                return false;

        is_cfi_bypassed = true;
        return true;
}

/* ========================= 第三部分：编码指令 （inline hook 框架） ========================= */

// 编码一条b指令
/*static int arm64_make_b(unsigned long from, unsigned long to, uint32_t *insn)
{
        int64_t offset = (int64_t)to - (int64_t)from;

        if (offset < -(1LL << 27) || offset > ((1LL << 27) - 4))
                return -ERANGE;

        *insn = 0x14000000 | ((offset >> 2) & 0x03FFFFFF);
        return 0;
}*/

// 编码长跳转
static void arm64_make_ldr_ret(uint64_t target, uint32_t *insn)
{
        uint32_t ldr_x16_literal = 0x58000050; // ldr x16, [pc, #8]
        uint32_t ret_x16 = 0xD65F0200;         // ret x16

        /*
        实际编码结果：
           insn[0]: ldr x16, [pc, #8]
           insn[1]: ret x16
           insn[2]: target low32
           insn[3]: target high32
        实际执行的汇编只有2条；后面的8字节是给ldr相对pc寻址到target地址数据。给ret跳
        */
        __builtin_memcpy(&insn[0], &ldr_x16_literal, sizeof(uint32_t));
        __builtin_memcpy(&insn[1], &ret_x16, sizeof(uint32_t));
        __builtin_memcpy(&insn[2], &target, sizeof(target));
}

/* ========================= 第四部分：绕过 6.1+ 的 KCFI ========================= */

/*
 6系内核就不用这个宏了，可以直接拿着函数指针调用

 * ARM64 内联汇编调用宏 (绕过 CFI / KCFI)
 *
 * 通过纯汇编指令 (blr) 直接跳转执行目标地址，从而绕过编译器的插入cfi
 *
 * 核心寄存器保护列表
 * 遵循 AAPCS64 (ARM64 过程调用约定) 声明 Caller-saved (调用者保存 / 易失) 寄存器。
 *
 *  [1] 通用寄存器
 *      - x9 ~ x15  : 临时调用者保存寄存器。
 *      - x16 ~ x17 : 过程内调用寄存器 (IP0, IP1 / PLT 专用)。
 *       (x0~x7和x18~x30是非易失性寄存器，属于 Callee-saved，被调用函数会负责恢复，因此无需在此声明)
 *  [2] 浮点/向量寄存器
 *      - v0 ~ v7   : 浮点参数与返回值寄存器 (调用后可能被修改)。
 *      - v16 ~ v31 : 临时调用者保存寄存器。
 *      (v8~v15 是非易失性寄存器，属于 Callee-saved，被调用函数会负责恢复，因此无需在此声明。如果确认运行环境为纯整数运算不涉及浮点，可删除 v 系列以微调性能)
 *
 *  [3] 特殊标志与屏障
 *      - lr (x30)  : 链接寄存器 (blr 指令执行时必定会覆盖它)。
 *      - cc        : 状态标志寄存器 (如 NZCV，被调用函数可能会修改条件标志)。
 *      - memory    : 编译器内存屏障，强制将寄存器缓存写回内存，并防止指令重排。
 */
#define _KCALL_CLOBBERS                                                                     \
        "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "lr", "cc", "memory", \
            "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",                                 \
            "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",                         \
            "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"

// 调用 0 个参数的函数
#define KCALL_0(fn_addr, ret_type) ({                                                                                                \
        register uint64_t _x0 asm("x0");                                                                                             \
        asm volatile("blr %1\n" : "=r"(_x0) : "r"((uint64_t)(fn_addr)) : "x1", "x2", "x3", "x4", "x5", "x6", "x7", _KCALL_CLOBBERS); \
        (ret_type) _x0;                                                                                                              \
})

// 调用 1 个参数的函数
#define KCALL_1(fn_addr, ret_type, a1) ({                                                                                            \
        register uint64_t _x0 asm("x0") = (uint64_t)(a1);                                                                            \
        asm volatile("blr %1\n" : "+r"(_x0) : "r"((uint64_t)(fn_addr)) : "x1", "x2", "x3", "x4", "x5", "x6", "x7", _KCALL_CLOBBERS); \
        (ret_type) _x0;                                                                                                              \
})

// 调用 2 个参数的函数
#define KCALL_2(fn_addr, ret_type, a1, a2) ({                                                                                             \
        register uint64_t _x0 asm("x0") = (uint64_t)(a1);                                                                                 \
        register uint64_t _x1 asm("x1") = (uint64_t)(a2);                                                                                 \
        asm volatile("blr %2\n" : "+r"(_x0), "+r"(_x1) : "r"((uint64_t)(fn_addr)) : "x2", "x3", "x4", "x5", "x6", "x7", _KCALL_CLOBBERS); \
        (ret_type) _x0;                                                                                                                   \
})

// 调用 3 个参数的函数
#define KCALL_3(fn_addr, ret_type, a1, a2, a3) ({                                                                                              \
        register uint64_t _x0 asm("x0") = (uint64_t)(a1);                                                                                      \
        register uint64_t _x1 asm("x1") = (uint64_t)(a2);                                                                                      \
        register uint64_t _x2 asm("x2") = (uint64_t)(a3);                                                                                      \
        asm volatile("blr %3\n" : "+r"(_x0), "+r"(_x1), "+r"(_x2) : "r"((uint64_t)(fn_addr)) : "x3", "x4", "x5", "x6", "x7", _KCALL_CLOBBERS); \
        (ret_type) _x0;                                                                                                                        \
})

// 调用 4 个参数的函数
#define KCALL_4(fn_addr, ret_type, a1, a2, a3, a4) ({                                                                                               \
        register uint64_t _x0 asm("x0") = (uint64_t)(a1);                                                                                           \
        register uint64_t _x1 asm("x1") = (uint64_t)(a2);                                                                                           \
        register uint64_t _x2 asm("x2") = (uint64_t)(a3);                                                                                           \
        register uint64_t _x3 asm("x3") = (uint64_t)(a4);                                                                                           \
        asm volatile("blr %4\n" : "+r"(_x0), "+r"(_x1), "+r"(_x2), "+r"(_x3) : "r"((uint64_t)(fn_addr)) : "x4", "x5", "x6", "x7", _KCALL_CLOBBERS); \
        (ret_type) _x0;                                                                                                                             \
})

// 调用 5 个参数的函数
#define KCALL_5(fn_addr, ret_type, a1, a2, a3, a4, a5) ({                                                                                                \
        register uint64_t _x0 asm("x0") = (uint64_t)(a1);                                                                                                \
        register uint64_t _x1 asm("x1") = (uint64_t)(a2);                                                                                                \
        register uint64_t _x2 asm("x2") = (uint64_t)(a3);                                                                                                \
        register uint64_t _x3 asm("x3") = (uint64_t)(a4);                                                                                                \
        register uint64_t _x4 asm("x4") = (uint64_t)(a5);                                                                                                \
        asm volatile("blr %5\n" : "+r"(_x0), "+r"(_x1), "+r"(_x2), "+r"(_x3), "+r"(_x4) : "r"((uint64_t)(fn_addr)) : "x5", "x6", "x7", _KCALL_CLOBBERS); \
        (ret_type) _x0;                                                                                                                                  \
})

// 调用 6 个参数的函数
#define KCALL_6(fn_addr, ret_type, a1, a2, a3, a4, a5, a6) ({                                                                                                 \
        register uint64_t _x0 asm("x0") = (uint64_t)(a1);                                                                                                     \
        register uint64_t _x1 asm("x1") = (uint64_t)(a2);                                                                                                     \
        register uint64_t _x2 asm("x2") = (uint64_t)(a3);                                                                                                     \
        register uint64_t _x3 asm("x3") = (uint64_t)(a4);                                                                                                     \
        register uint64_t _x4 asm("x4") = (uint64_t)(a5);                                                                                                     \
        register uint64_t _x5 asm("x5") = (uint64_t)(a6);                                                                                                     \
        asm volatile("blr %6\n" : "+r"(_x0), "+r"(_x1), "+r"(_x2), "+r"(_x3), "+r"(_x4), "+r"(_x5) : "r"((uint64_t)(fn_addr)) : "x6", "x7", _KCALL_CLOBBERS); \
        (ret_type) _x0;                                                                                                                                       \
})

#endif /* _EXPORT_FUN_H_ */
