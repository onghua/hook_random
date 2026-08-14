#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched/mm.h>
#include <linux/ptrace.h>
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/memory.h>

// 硬件mmu翻译
static inline int mmu_translate_va_to_pa(struct mm_struct *mm, uint64_t va, phys_addr_t *pa)
{
    uint64_t pgd_phys;
    int ret;
    uint64_t phys_out;
    uint64_t tmp_daif, tmp_ttbr, tmp_par, tmp_offset, tmp_ttbr_new;

    if (!mm || !mm->pgd || !pa)
        return -EINVAL;

    pgd_phys = virt_to_phys(mm->pgd);

    asm volatile(

        // 关闭所有中断和异常中断
        "mrs    %[tmp_daif], daif\n"
        "msr    daifset, #0xf\n" // 关闭所有中断(D/A/I/F)
        "isb\n"

        /*
        6.12 内核：全面完善并默认启用了 LPA2 特性（支持 4K/16K 页面的 52 位物理地址）。
            如果系统开启了 LPA2，PAR_EL1 寄存器的格式会发生变化，物理地址可以长达 52 位。
            原有代码中的 ubfx %[tmp_par], %[tmp_par], #12, #36 强行将物理地址截断在了 48 位（提取 36 位 + 偏移 12 位 = 48 位）。
            就不能这么写了
            后续当你用这个被截断的错误物理地址去读写内存时，会触发同步外部中止 (Synchronous External Abort / SError)，引发极其底层的硬件级死机。
        准备新的 TTBR0 布局 (兼容 LPA2)
        如果 pgd_phys 超过 48 位 (LPA2 开启)，
        物理地址的 [51:48] 必须移动到寄存器的 [5:2] 位。
        如果没开启 LPA2，pgd_phys[51:48] 为 0，此逻辑依然安全（不影响结果）。
         */
        "lsr    %[tmp_ttbr_new], %[pgd_phys], #48\n"                       // 提取 PA[51:48]
        "and    %[tmp_offset], %[pgd_phys], #0xffffffffffff\n"             // 提取 PA[47:0]
        "orr    %[tmp_ttbr_new], %[tmp_offset], %[tmp_ttbr_new], lsl #2\n" // 组合到新 TTBR 格式

        // 切换 TTBR0
        "mrs    %[tmp_ttbr], ttbr0_el1\n"
        "msr    ttbr0_el1, %[tmp_ttbr_new]\n"
        "isb\n"

        /*
        翻译前先清本地 CPU 上该 VA 的所有 ASID 的TLB，防止旧 ASID+VA 命中影响本次 AT

        ASID允许相同虚拟地址映射不同物理地址，不同进程的地址空间分配不同的ASID到mm,运行时根据TCR_EL1.A1装载到ttbr0_el1或TTBR1_EL1
        TLB entry 是“虚拟地址到物理地址”的缓存；ASID 是这条缓存属于哪个地址空间的标签。
        比如两个进程都有同一个虚拟地址：如果 TLB 只按 VA 查，那 CPU 看到 0x400000 时就分不清这是 A 的还是 B 的。
        进程 A:VA 0x400000 -> PA 0x11100000
        进程 B:VA 0x400000 -> PA 0x22200000
        所以 TLB 实际会类似这样存：这样同一个 VA:0x400000，可以在不同进程里翻译到不同 PA。
        TLB entry0 :{ASID 10 + VA 0x400000 -> PA 0x11100000}
        TLB entry1 :{ASID 20 + VA 0x400000 -> PA 0x22200000}
        ASID 的作用就是避免每次进程切换都把整个 TLB 清空。进程 A 切到进程 B 时，A 的 TLB entry 可以继续留着，只要当前 ASID 变成 B 的 ASID，CPU 就不会命中 A 的 entry。
        */
        "lsr    %[tmp_offset], %[va], #12\n"
        "tlbi   vaae1, %[tmp_offset]\n"
        "dsb    nsh\n"
        "isb\n"

        /*
        硬件地址翻译，这里会导致某个TLB entry(TLB条目)的 ASID(地址空间标识符) 中VA->PA 的被污染，下面清除

        at指令就是为了安全地探测页表，翻译的结果(无论成功还是失败)都会更新到 PAR_EL1寄存器中。
        普通ldr/str 指令导致mmu翻译失败会直接触发翻译异常，CPU 跳入 el1_da，执行翻译异常处理
        现在翻译异常绝大部分都是<缺页>导致的
        因为现在现代系统中，大页是非常普遍的(内核空间几乎全大页)，遇到大页直接就可以返回物理地址了，mmu不需要继续查找下级页表
        */
        "at     s1e0r, %[va]\n"
        "isb\n"
        "mrs    %[tmp_par], par_el1\n"

        /*
        只清除当前va地址所有的ASID并只同步当前cpu，不用vae1清除指定ASID原因是不知道 AT 这次污染在哪个 ASID
        想要知道需要如下判断，太麻烦了
        TCR_EL1.A1 = 0  => ASID 来自 TTBR0_EL1[63:48]
        TCR_EL1.A1 = 1  => ASID 来自 TTBR1_EL1[63:48]
        */
        "lsr    %[tmp_offset], %[va], #12\n" // 清除当前va地址
        "tlbi   vaae1, %[tmp_offset]\n"      // 所有的ASID
        "dsb    nsh\n"                       // 并只同步当前cpu
        "isb\n"

        // 恢复原始 TTBR0
        "msr    ttbr0_el1, %[tmp_ttbr]\n"
        "isb\n"

        // 恢复原始 DAIF 状态
        "msr    daif, %[tmp_daif]\n"
        "isb\n"

        // 检查翻译是否成功 (PAR_EL1.F == 0)
        "tbnz   %[tmp_par], #0, .L_efault%=\n"

        /*
        提取物理地址
        PAR_EL1[51:12] 存放物理页地址。
        提取从 bit 12 开始的 40 位 (即到 bit 51)。
        at s1e0r，遇到 2MB/1GB 大页时
        返回的 PAR_EL1[51:12] 已经包含了完整的 PA[51:12]，大页内偏移 [20:12] 或 [29:12] 已经算进去了
        所以 VA 里只有最低 12 位 [11:0]（页内字节偏移）是 PAR_EL1 没有的，补上就行了
        只要这样拼：pa = (PAR_EL1[51:12] << 12) | (va & 0xfff);
        */
        "ubfx   %[tmp_par], %[tmp_par], #12, #40\n" // 提取 PA[51:12]
        "lsl    %[tmp_par], %[tmp_par], #12\n"      // 恢复偏移
        "and    %[tmp_offset], %[va], #0xFFF\n"     // 提取页内偏移
        "orr    %[phys_out], %[tmp_par], %[tmp_offset]\n"
        "mov    %w[ret], #0\n"
        "b      .L_end%=\n"

        ".L_efault%=:\n"
        "mov    %w[ret], %w[efault_val]\n"
        "mov    %[phys_out], #0\n"

        ".L_end%=:\n"

        : [ret] "=&r"(ret),
          [phys_out] "=&r"(phys_out),
          [tmp_daif] "=&r"(tmp_daif),
          [tmp_ttbr] "=&r"(tmp_ttbr),
          [tmp_par] "=&r"(tmp_par),
          [tmp_offset] "=&r"(tmp_offset),
          [tmp_ttbr_new] "=&r"(tmp_ttbr_new)
        : [pgd_phys] "r"(pgd_phys),
          [va] "r"(va),
          [efault_val] "r"(-EFAULT)
        : "cc", "memory");

    if (ret == 0)
        *pa = phys_out;

    return ret;
}

bool read_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;

    mapped = phys_to_virt(pa);
    if (!mapped) {
        return false;
    }
    if(copy_to_user(buffer, mapped, size)) {
        return false;
    }
    return true;
}

bool write_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;

    mapped = phys_to_virt(pa);
    if (!mapped) {
        return false;
    }
    if(copy_from_user(mapped, buffer, size)) {
        return false;
    }
    return true;
}

bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size)
{
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t max;
    size_t count = 0;
    int ret;

    task = find_task_by_vpid(pid);
    if (!task) {
        return false;
    }
    mm = get_task_mm(task);
    if (!mm) {
        return false;
    }
    while (size > 0) {
        ret = mmu_translate_va_to_pa(mm, addr, &pa);
        max = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));
        if (ret) {   // 翻译失败，跳过此页
            goto none_phy_addr;
        }
        count = read_physical_address(pa, buffer, max);
    none_phy_addr:
        size -= max;
        buffer += max;
        addr += max;
    }
    mmput(mm);
    return count;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size)
{
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t max;
    size_t count = 0;
    int ret;

    task = find_task_by_vpid(pid);
    if (!task) {
        return false;
    }
    mm = get_task_mm(task);
    if (!mm) {
        return false;
    }
    while (size > 0) {
        ret = mmu_translate_va_to_pa(mm, addr, &pa);
        max = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));
        if (ret) {
            goto none_phy_addr;
        }
        count = write_physical_address(pa, buffer, max);
    none_phy_addr:
        size -= max;
        buffer += max;
        addr += max;
    }
    mmput(mm);
    return count;
}
