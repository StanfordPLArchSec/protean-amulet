#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <err.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>

typedef void hook_t(void *sandbox_base, uint64_t sandbox_mask);

int main(int argc, char *argv[]) {
  int fd;
  if ((fd = open(argv[1], O_RDONLY)) < 0)
    err(1, "open");
  struct stat st;
  if (fstat(fd, &st) < 0)
    err(1, "fstat");
  void *code_;
  if ((code_ = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    err(1, "mmap");
  hook_t *code = (hook_t *) code_;
  // Stick a return at the end.4
  const uint8_t code_suffix[] = { 0xB8, 0x3C, 0x00, 0x00, 0x00, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05 };
  memcpy((uint8_t *) code + st.st_size, code_suffix, sizeof code_suffix);

  // Map in data.
  const size_t sandbox_size = 0x10000;
  void *sandbox_base;
  if ((sandbox_base = mmap(NULL, sandbox_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)) == MAP_FAILED)
    err(1, "mmap");

  // Run the code.
  asm volatile ("mov %0, %%r14\n"
                "call *%1\n"
                :: "r"(sandbox_base), "r"(code)
                : "r14");
}

