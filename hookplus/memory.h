#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include "bypass_cfi.h"          // 提供 generic_kallsyms_lookup_name

phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va)
{
    static int (*follow_pte_ptr)(struct mm_struct *, unsigned long, pte_t **, spinlock_t **) = NULL;
    pte_t *pte;
    spinlock_t *ptl;
    phys_addr_t phys;
    int ret;

    if (!follow_pte_ptr) {
        follow_pte_ptr = (int (*)(struct mm_struct *, unsigned long, pte_t **, spinlock_t **))generic_kallsyms_lookup_name("follow_pte");
        if (!follow_pte_ptr) {
            return 0;
        }
    }

    ret = follow_pte_ptr(mm, va, &pte, &ptl);
    if (ret) {
        return 0;
    }

    if (!pte_present(*pte)) {
        pte_unmap_unlock(pte, ptl);
        return 0;
    }

    phys = pte_pfn(*pte) << PAGE_SHIFT;
    pte_unmap_unlock(pte, ptl);

    return phys + (va & (PAGE_SIZE - 1));
}

bool read_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;
    
    if (!pfn_valid(__phys_to_pfn(pa))) {
        return false;
    }
    mapped = ioremap_cache(pa, size);
    if (!mapped) {
        return false;
    }
    if(copy_to_user(buffer, mapped, size)) {
        iounmap(mapped);
        return false;
    }
    iounmap(mapped);
    return true;
}

bool write_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;

    if (!pfn_valid(__phys_to_pfn(pa))) {
        return false;
    }
    mapped = ioremap_cache(pa, size);
    if (!mapped) {
        return false;
    }
    if(copy_from_user(mapped, buffer, size)) {
        iounmap(mapped);
        return false;
    }
    iounmap(mapped);
    return true;
}

bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    struct pid* pid_struct;
    phys_addr_t pa;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return false;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        return false;
    }
    put_task_struct(task);
    mm = get_task_mm(task);
    if (!mm) {
        return false;
    }

    while (size > 0) {
        size_t offset = addr & (PAGE_SIZE - 1);
        size_t to_read = size;
        if (to_read > PAGE_SIZE - offset)
            to_read = PAGE_SIZE - offset;

        pa = translate_linear_address(mm, addr);
        if (!pa) {
            mmput(mm);
            return false;
        }
        if (!read_physical_address(pa, buffer, to_read)) {
            mmput(mm);
            return false;
        }
        addr += to_read;
        buffer += to_read;
        size -= to_read;
    }

    mmput(mm);
    return true;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    struct pid* pid_struct;
    phys_addr_t pa;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return false;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        return false;
    }
    put_task_struct(task);
    mm = get_task_mm(task);
    if (!mm) {
        return false;
    }

    while (size > 0) {
        size_t offset = addr & (PAGE_SIZE - 1);
        size_t to_write = size;
        if (to_write > PAGE_SIZE - offset)
            to_write = PAGE_SIZE - offset;

        pa = translate_linear_address(mm, addr);
        if (!pa) {
            mmput(mm);
            return false;
        }
        if (!write_physical_address(pa, buffer, to_write)) {
            mmput(mm);
            return false;
        }
        addr += to_write;
        buffer += to_write;
        size -= to_write;
    }

    mmput(mm);
    return true;
}
