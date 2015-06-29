/*
 * kmaps: simple page table walker based on /dev/mem
 *
 * author: PaX Team <pageexec@freemail.hu> in 2008.01
 *
 * gcc -W -Wall -pedantic -std=c99 -O2 kmaps.c -o kmaps
 *
 * the only argument is the physical address of the page directory, in hex
 *
 * example usage on a normal amd64: kmaps 201000
 *
 * colors represent the page table level and exec/non-exec (light/normal) status
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define GREEN		"\033[32m"
#define LIGHTGREEN	"\033[32m\033[1m"
#define YELLOW		"\033[33m"
#define LIGHTYELLOW	"\033[33m\033[1m"
#define RED		"\033[31m"
#define LIGHTRED	"\033[31m\033[1m"
#define BLUE		"\033[34m"
#define LIGHTBLUE	"\033[34m\033[1m"
#define BRIGHT		"\033[m\033[1m"
#define NORMAL		"\033[m"

#define VA_BITS		48U
#define VA_SIZE		(1ULL << VA_BITS)
#define CANONICALIZE(x)	((((x) | ~(VA_SIZE - 1ULL)) ^ (VA_SIZE / 2)) + (VA_SIZE / 2))
#define PAGE_SIZE	4096U
#define PER_PAGE(x)	(PAGE_SIZE / sizeof (x))
#define PHYS_MASK	0xFFFFF000U
#define PHYS_MASK_PAE	0xFFFFFFFFFF000ULL
#define PTE_PRESENT	0x01U
#define PTE_WRITE	0x02U
#define PTE_LARGE	0x80U
#define PTE_NX		0x8000000000000000ULL
#define PTE_EXECUTABLE	(PTE_PRESENT | PTE_NX)
#define PRESENT(x)	((x) & PTE_PRESENT)
#define LARGE(x)	((x) & PTE_LARGE)
#define EXECUTABLE(x)	((((x) & PTE_EXECUTABLE) == PTE_PRESENT) && exec)
#define _RWX(x)		(((x) & (PTE_EXECUTABLE | PTE_WRITE)) == (PTE_PRESENT | PTE_WRITE))
#define RWX(x)		((_RWX(x) && exec) ? "rwx" : "")
static unsigned int dump_pt(int devmem, unsigned int pte, unsigned int va, int exec)
{
  unsigned int *pt, i;
  static unsigned int buffer[PAGE_SIZE / sizeof(unsigned int)];

  if (!PRESENT(pte))
    goto out;

  if (LARGE(pte)) {
    printf("\t\t\t%spte: LRG %08x %08x\n", LIGHTYELLOW, pte, va);
    goto out;
  }

  pt = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, devmem, pte & PHYS_MASK);
  if (MAP_FAILED == pt) {
    if ((off_t)-1 == lseek(devmem, pte & PHYS_MASK, SEEK_SET))
      goto out;
    if (sizeof buffer != read(devmem, buffer, sizeof buffer))
      goto out;
    pt = buffer;
  }

  for (i = 0; i < PER_PAGE(pte); ++i, va += PAGE_SIZE)
    if (pt[i])
      printf("\t\t\t%spte: %03x %08x %08x\n", LIGHTYELLOW, i, pt[i], va);

  if (pt != buffer)
    munmap(pt, PAGE_SIZE);
  return va;

out:
    return va + PAGE_SIZE * PER_PAGE(pte);
}

static unsigned long long dump_pt_pae(int devmem, unsigned long long pte, unsigned long long va, int exec)
{
  unsigned long long *pt;
  unsigned int i;
  static unsigned long long buffer[PAGE_SIZE / sizeof(unsigned long long)];

  if (!PRESENT(pte))
    goto out;

  if (LARGE(pte)) {
    printf("\t\t\t%spte: %3s LRG %016llx %016llx\n", EXECUTABLE(pte) ? YELLOW : LIGHTYELLOW, RWX(pte), pte, va);
    goto out;
  }

  pt = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, devmem, pte & PHYS_MASK_PAE);
  if (MAP_FAILED == pt) {
    if ((off_t)-1 == lseek(devmem, pte & PHYS_MASK_PAE, SEEK_SET))
      goto out;
    if (sizeof buffer != read(devmem, buffer, sizeof buffer))
      goto out;
    pt = buffer;
  }

  for (i = 0; i < PER_PAGE(pte); ++i, va += PAGE_SIZE) {
    if (pt[i])
      printf("\t\t\t%spte: %3s %03x %016llx %016llx\n", EXECUTABLE(pt[i]) ? YELLOW : LIGHTYELLOW, RWX(pt[i]), i, pt[i], va);
  }

  if (pt != buffer)
    munmap(pt, PAGE_SIZE);
  return va;

out:
  return va + PAGE_SIZE * PER_PAGE(pte);
}

static unsigned long long dump_pmd_pae(int devmem, unsigned long long pmd, unsigned long long va, int exec)
{
  unsigned long long *pt;
  unsigned int i;
  static unsigned long long buffer[PAGE_SIZE / sizeof(unsigned long long)];

  if (!PRESENT(pmd))
    goto out;

  if (LARGE(pmd)) {
    printf("\t\t%spmd: %3s LRG %016llx %016llx\n", EXECUTABLE(pmd) ? GREEN : LIGHTGREEN, RWX(pmd), pmd, va);
    goto out;
  }

  pt = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, devmem, pmd & PHYS_MASK_PAE);
  if (MAP_FAILED == pt) {
    if ((off_t)-1 == lseek(devmem, pmd & PHYS_MASK_PAE, SEEK_SET))
      goto out;
    if (sizeof buffer != read(devmem, buffer, sizeof buffer))
      goto out;
    pt = buffer;
  }

  for (i = 0; i < PER_PAGE(pmd); ++i) {
    if (pt[i])
      printf("\t\t%spmd: %3s %03x %016llx %016llx\n", EXECUTABLE(pt[i]) ? GREEN : LIGHTGREEN, RWX(pt[i]), i, pt[i], va);
    va = dump_pt_pae(devmem, pt[i], va, EXECUTABLE(pt[i]));
  }

  if (pt != buffer)
    munmap(pt, PAGE_SIZE);
  return va;

out:
  return va + PAGE_SIZE * PER_PAGE(pmd) * PER_PAGE(pmd);
}

#ifdef __x86_64__
static unsigned long long dump_pud_pae(int devmem, unsigned long long pud, unsigned long long va, int exec)
{
  unsigned long long *pt;
  unsigned int i;
  static unsigned long long buffer[PAGE_SIZE / sizeof(unsigned long long)];

  if (!PRESENT(pud))
    goto out;

  pt = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, devmem, pud & PHYS_MASK_PAE);
  if (MAP_FAILED == pt) {
    if ((off_t)-1 == lseek(devmem, pud & PHYS_MASK_PAE, SEEK_SET))
      goto out;
    if (sizeof buffer != read(devmem, buffer, sizeof buffer))
      goto out;
    pt = buffer;
  }

  for (i = 0; i < PER_PAGE(pud); ++i) {
    if (pt[i])
      printf("\t%spud: %3s %03x %016llx %016llx\n", EXECUTABLE(pt[i]) ? BLUE : LIGHTBLUE, RWX(pt[i]), i, pt[i], va);
    va = dump_pmd_pae(devmem, pt[i], va, EXECUTABLE(pt[i]));
  }

  if (pt != buffer)
    munmap(pt, PAGE_SIZE);
  return va;

out:
  return va + (unsigned long long)PAGE_SIZE * PER_PAGE(pud) * PER_PAGE(pud) * PER_PAGE(pud);
}
#endif

static void dump_pgd(int devmem, unsigned int pgd, int exec)
{
  unsigned int *pt, i, va = 0;
  static unsigned int buffer[PAGE_SIZE / sizeof(unsigned int)];

  pt = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, devmem, pgd);
  if (MAP_FAILED == pt) {
    if ((off_t)-1 == lseek(devmem, pgd , SEEK_SET))
      return;
    if (sizeof buffer != read(devmem, buffer, sizeof buffer))
      return;
    pt = buffer;
  }

  for (i = 0; i < PER_PAGE(pgd); ++i) {
    if (pt[i])
      printf("%spgd: %03x %08x %08x\n", LIGHTRED, i, pt[i], va);
    va = dump_pt(devmem, pt[i], va, EXECUTABLE(pt[i]));
  }

  if (pt != buffer)
    munmap(pt, PAGE_SIZE);
}

static void dump_pgd_pae(int devmem, unsigned long long pgd, unsigned int pgd_size, int exec)
{
  unsigned long long *pt, va = 0;
  unsigned int i;
  static unsigned long long buffer[PAGE_SIZE / sizeof(unsigned long long)];

#ifdef __i386__
  pgd_size = 4;
#endif

  if (pgd & (PAGE_SIZE-1)) {
#ifdef __i386__
    pt = malloc(32);
    if ((off_t)-1 == lseek(devmem, pgd, SEEK_SET))
      return;
    if (32 != read(devmem, pt, 32))
#endif
      return;
  } else {
    pt = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, devmem, pgd);
    if (MAP_FAILED == pt) {
      if ((off_t)-1 == lseek(devmem, pgd, SEEK_SET))
        return;
      if (sizeof buffer != read(devmem, buffer, sizeof buffer))
        return;
      pt = buffer;
    }
  }

  for (i = 0; i < pgd_size; ++i) {
    if (pt[i])
      printf("%spgd: %3s %03x %016llx %016llx\n", EXECUTABLE(pt[i]) ? RED : LIGHTRED, RWX(pt[i]), i, pt[i], va);
#ifdef __i386__
    va = dump_pmd_pae(devmem, pt[i], va, EXECUTABLE(pt[i]));
#else
    va = CANONICALIZE(dump_pud_pae(devmem, pt[i], va, EXECUTABLE(pt[i])));
#endif
  }

  if (pgd & (PAGE_SIZE-1))
    free(pt);
  else if (pt != buffer)
    munmap(pt, PAGE_SIZE);
}

static int get_pgd_size(int devmem, unsigned long long pgd)
{
  unsigned long long *pt;
  static unsigned long long buffer[PAGE_SIZE / sizeof(unsigned long long)];

#ifdef __x86_64__
  return 512;
#endif

  if (pgd & (PAGE_SIZE - 1) || pgd > 0xFFFFF000ULL)
    return 4;

  pt = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, devmem, pgd);
  if (MAP_FAILED == pt) {
    if ((off_t)-1 == lseek(devmem, pgd, SEEK_SET))
      return -1;
    if (sizeof buffer != read(devmem, buffer, sizeof buffer))
      return -1;
    pt = buffer;
  }

  //FIXME: detect page aligned PAE pgd, can be hacked around by passing pgd+-8 for now
  if (pt != buffer)
    munmap(pt, PAGE_SIZE);
  return 1024;
}

int main(int argc, char *argv[])
{
  unsigned long long pgd;
  int devmem, pgd_size;
  int exec;

  if (argc != 2) {
    printf("usage: %s <pgd %sPHYSICAL%s address, e.g., %sswapper_pg_dir%s or %sinit_level4_pgt%s>\n",
           argv[0], LIGHTRED, NORMAL, LIGHTYELLOW, NORMAL, LIGHTYELLOW, NORMAL);
    return 1;
  }

  if (1 != sscanf(argv[1], "%llx", &pgd))
    return 2;

#ifdef __x86_64__
  if (pgd & (PAGE_SIZE - 1))
    return 3;
#endif

  devmem = open("/dev/mem", O_RDONLY);
  if (-1 == devmem) {
    printf("unable to open /dev/mem\n");
    return 4;
  }

  pgd_size = get_pgd_size(devmem, pgd);
  if (-1 == pgd_size) {
    close(devmem);
    return 5;
  }

  if (1024 == pgd_size)
    dump_pgd(devmem, pgd, 1);
  else
    dump_pgd_pae(devmem, pgd, pgd_size, 1);

  close(devmem);
  return 0;
}
