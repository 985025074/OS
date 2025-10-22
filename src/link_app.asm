.section .rodata
.align 3
app_0_name:
    .asciz "01helloworld"
.align 3
.section .data
app_0_start:
    .incbin "./results/01helloworld.bin"
.align 3
app_0_end:
.section .rodata
.align 3
app_1_name:
    .asciz "02helloqiukaiyu"
.align 3
.section .data
app_1_start:
    .incbin "./results/02helloqiukaiyu.bin"
.align 3
app_1_end:
.section .rodata
.align 3
app_2_name:
    .asciz "03syscall_test"
.align 3
.section .data
app_2_start:
    .incbin "./results/03syscall_test.bin"
.align 3
app_2_end:
.section .rodata
.align 3
app_3_name:
    .asciz "04test"
.align 3
.section .data
app_3_start:
    .incbin "./results/04test.bin"
.align 3
app_3_end:
.section .rodata
.align 3
    .global num_user_apps
num_user_apps:
    .quad 4
    .quad app_0_start
    .quad app_0_end
    .quad app_0_name
    .quad app_1_start
    .quad app_1_end
    .quad app_1_name
    .quad app_2_start
    .quad app_2_end
    .quad app_2_name
    .quad app_3_start
    .quad app_3_end
    .quad app_3_name
