.set noreorder
.globl _start
.type _start,@function
_start:
    move $4, $sp
    la $5, main
    la $25, relibc_start_v1
    jalr $25
    nop
1:  b 1b
    nop
.size _start, .-_start
