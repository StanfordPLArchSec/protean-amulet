   .intel_syntax noprefix
   mov    rdi,r14
   mov    rsi,0xfff
   push   rbp
   mov    rbp,rsp
   and    rsp,0xffffffffffffff80
   sub    rsp,0x180
   mov    rsi,rsi
   mov    rdi,rdi
   mfence
   mov    rax,rdi
   and    rax,rsi
   mov    QWORD PTR [rax+rdi*1],0x7d0c5
   lea    rcx,[rsp+0x60]
   and    rcx,rsi
   mov    BYTE PTR [rcx+rdi*1],0x1
   mov    QWORD PTR [rax+rdi*1],0x2e435
   lea    rcx,[rsp+0x70]
   and    rcx,rsi
   .byte 0x36
   cmp BYTE PTR [rcx+rdi*1],0x0
   movabs rcx,0xea8bbcaa3189b928
   mov    QWORD PTR [rax+rdi*1],rcx
   lea    rax,[rsp+0x80]
   .byte 0x36
   cmove rax,rdi
   and    rax,rsi
   movabs rcx,0xffff0000ffffff00
   mov    QWORD PTR [rax+rdi*1],rcx
   mov    DWORD PTR [rax+rdi*1],0xff00ba1d
   mov    BYTE PTR [rsi+rdi*1],0x1
   mfence
   mov    rsp,rbp
   pop    rbp
