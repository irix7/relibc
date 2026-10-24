.set noreorder
.globl _start
_start:
    move $4, $sp
    la $25, main
    jalr $25
    nop
    move $4, $2
    li $2, 6058
    syscall
    nop
1:  b 1b
    nop
