// SPDX-License-Identifier: GPL-2.0-only
// Derived from KernelSU (GPL-2.0)
/*
 * patch_memory.c — fixmap-based kernel memory patching for ARM64
 */

#include <linux/mm.h>
#include <linux/stop_machine.h>
#include <linux/version.h>
#include <asm/fixmap.h>
#include "patch_memory.h"
#include "ksymless.h"

static struct mm_struct *mm_ptr;
static void (*set_fixmap_fn)(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot);
static long (*copy_nofault_fn)(void *dst, const void *src, size_t size);
static void (*flush_dcache_fn)(unsigned long start, unsigned long end);

void cksu_patch_memory_init(void)
{
	mm_ptr = (struct mm_struct *)kallsyms_name_to_addr("init_mm");
	set_fixmap_fn = (void *)kallsyms_name_to_addr("__set_fixmap");
	copy_nofault_fn = (void *)kallsyms_name_to_addr("copy_to_kernel_nofault");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	flush_dcache_fn = (void *)kallsyms_name_to_addr("dcache_clean_inval_poc");
#else
	flush_dcache_fn = (void *)kallsyms_name_to_addr("__flush_dcache_area");
#endif
}

static unsigned long virt_to_phys_walk(unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (!mm_ptr)
		return 0;

	pgd = pgd_offset(mm_ptr, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return 0;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return 0;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return 0;
#if defined(pud_leaf)
	if (pud_leaf(*pud))
		return __pud_to_phys(*pud) + (addr & ~PUD_MASK);
#endif
	if (pud_bad(*pud))
		return 0;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return 0;
#if defined(pmd_leaf)
	if (pmd_leaf(*pmd))
		return __pmd_to_phys(*pmd) + (addr & ~PMD_MASK);
#endif
	if (pmd_bad(*pmd))
		return 0;

	pte = pte_offset_kernel(pmd, addr);
	if (!pte || !pte_present(*pte))
		return 0;

	return __pte_to_phys(*pte) + (addr & ~PAGE_MASK);
}

struct patch_info {
	void *dst;
	void *src;
	size_t len;
	int flags;
	atomic_t cpu_count;
};

static int __nocfi patch_text_cb(void *arg)
{
	struct patch_info *p = arg;
	unsigned long phys, fixmap_va;
	int ret = 0;

	if (atomic_inc_return(&p->cpu_count) == num_online_cpus()) {
		phys = virt_to_phys_walk((unsigned long)p->dst);
		if (!phys) {
			ret = -ENOENT;
			goto done;
		}

		set_fixmap_fn(FIX_TEXT_POKE0, phys & PAGE_MASK, PAGE_KERNEL);
		fixmap_va = fix_to_virt(FIX_TEXT_POKE0) + (phys & ~PAGE_MASK);

		ret = (int)copy_nofault_fn((void *)fixmap_va, p->src, p->len);

		set_fixmap_fn(FIX_TEXT_POKE0, 0, __pgprot(0));

		if (!ret && (p->flags & CKSU_PATCH_FLUSH_DCACHE) && flush_dcache_fn)
			flush_dcache_fn((unsigned long)p->dst,
					(unsigned long)p->dst + p->len);
		if (!ret && (p->flags & CKSU_PATCH_FLUSH_ICACHE)) {
			asm volatile("ic ivau, %0" :: "r"(p->dst));
			asm volatile("dsb ish");
			asm volatile("isb");
		}
done:
		atomic_inc(&p->cpu_count);
	} else {
		while (atomic_read(&p->cpu_count) <= num_online_cpus())
			cpu_relax();
		isb();
	}

	return ret;
}

int cksu_patch_text(void *dst, void *src, size_t len, int flags)
{
	struct patch_info info = {
		.dst = dst,
		.src = src,
		.len = len,
		.flags = flags,
		.cpu_count = ATOMIC_INIT(0),
	};

	if (!set_fixmap_fn || !copy_nofault_fn || !mm_ptr)
		return -ENOSYS;

	return stop_machine(patch_text_cb, &info, cpu_online_mask);
}
