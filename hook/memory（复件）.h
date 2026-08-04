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

// ========== 1. 地址翻译（支持 4KB / 2MB / 1GB 大页）==========
static phys_addr_t translate_va_to_pa(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    phys_addr_t pa;
    
    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;
    
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 0;
    
    pud = pud_offset(p4d, va);
    if (pud_none(*pud))
        return 0;
    
    // ===== 1GB 大页 =====
    if (pud_leaf(*pud)) {
        pa = (phys_addr_t)(pud_pfn(*pud) << PAGE_SHIFT) + (va & ~PUD_MASK);
        return pa;
    }
    if (pud_bad(*pud))
        return 0;
    
    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd))
        return 0;
    
    // ===== 2MB 大页 =====
    if (pmd_leaf(*pmd)) {
        pa = (phys_addr_t)(pmd_pfn(*pmd) << PAGE_SHIFT) + (va & ~PMD_MASK);
        return pa;
    }
    if (pmd_bad(*pmd))
        return 0;
    
    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte) || !pte_present(*pte))
        return 0;
    
    // ===== 4KB 普通页 =====
    pa = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT) + (va & (PAGE_SIZE - 1));
    return pa;
}

// ========== 2. 读物理内存 -> 用户层 ==========
static bool read_physical(phys_addr_t pa, void __user *buffer, size_t size)
{
    unsigned long pfn = __phys_to_pfn(pa);
    void *vaddr;
    
    if (!pfn_valid(pfn))
        return false;
    
    vaddr = kmap_local_pfn(pfn);
    if (!vaddr)
        return false;
    
    vaddr += (pa & ~PAGE_MASK);
    
    if (copy_to_user(buffer, vaddr, size)) {
        kunmap_local(vaddr);
        return false;
    }
    
    kunmap_local(vaddr);
    return true;
}

// ========== 3. 写物理内存 <- 用户层 ==========
static bool write_physical(phys_addr_t pa, const void __user *buffer, size_t size)
{
    unsigned long pfn = __phys_to_pfn(pa);
    void *vaddr;
    
    if (!pfn_valid(pfn))
        return false;
    
    vaddr = kmap_local_pfn(pfn);
    if (!vaddr)
        return false;
    
    vaddr += (pa & ~PAGE_MASK);
    
    if (copy_from_user(vaddr, buffer, size)) {
        kunmap_local(vaddr);
        return false;
    }
    
    kunmap_local(vaddr);
    return true;
}

// ========== 4. 跨进程读 ==========
bool read_process_memory(pid_t pid, uintptr_t addr, void __user *buffer, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct pid *pid_struct;
    phys_addr_t pa;
    size_t bytes_this_page;
    uintptr_t current_va = addr;
    uint8_t __user *buf = (uint8_t __user *)buffer;
    size_t remaining = size;
    
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return false;
    
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return false;
    
    while (remaining > 0) {
        size_t offset = current_va & (PAGE_SIZE - 1);
        bytes_this_page = PAGE_SIZE - offset;
        if (bytes_this_page > remaining)
            bytes_this_page = remaining;
        
        pa = translate_va_to_pa(mm, current_va);
        if (pa) {
            read_physical(pa, buf, bytes_this_page);
        }
        
        buf += bytes_this_page;
        remaining -= bytes_this_page;
        current_va += bytes_this_page;
    }
    
    mmput(mm);
    return true;
}

// ========== 5. 跨进程写 ==========
bool write_process_memory(pid_t pid, uintptr_t addr, const void __user *buffer, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct pid *pid_struct;
    phys_addr_t pa;
    size_t bytes_this_page;
    uintptr_t current_va = addr;
    const uint8_t __user *buf = (const uint8_t __user *)buffer;
    size_t remaining = size;
    
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return false;
    
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return false;
    
    while (remaining > 0) {
        size_t offset = current_va & (PAGE_SIZE - 1);
        bytes_this_page = PAGE_SIZE - offset;
        if (bytes_this_page > remaining)
            bytes_this_page = remaining;
        
        pa = translate_va_to_pa(mm, current_va);
        if (pa) {
            write_physical(pa, buf, bytes_this_page);
        }
        
        buf += bytes_this_page;
        remaining -= bytes_this_page;
        current_va += bytes_this_page;
    }
    
    mmput(mm);
    return true;
}
