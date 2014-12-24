
#include "apic.h"

boot_idt = 0

ipi_vector = 0x20

max_cpus = 4

.bss

	. = . + 4096 * max_cpus
	.align 16
stacktop:

	. = . + 4096
	.align 16
ring0stacktop:

.data
		
.align 4096
ptl2:
i = 0
	.rept 512
	.quad 0x1e7 | (i << 21)
	i = i + 1
	.endr

.align 4096
ptl3:
	.quad ptl2 + 7

.align 4096
ptl4:
	.quad ptl3 + 7
	
.align 4096

gdt64_desc:
	.word gdt64_end - gdt64 - 1
	.quad gdt64

gdt64:
	.quad 0
	.quad 0x00af9b000000ffff // 64-bit code segment
	.quad 0x00cf93000000ffff // 64-bit data segment
	.quad 0x00affb000000ffff // 64-bit code segment (user)
	.quad 0x00cff3000000ffff // 64-bit data segment (user)
tss_descr:
	.rept max_cpus
	.quad 0x000089000000ffff // 64-bit avail tss
	.quad 0                  // tss high addr
	.endr
gdt64_end:

i = 0
tss:
	.rept max_cpus
	.long 0
	.quad ring0stacktop - i * 4096
	.quad 0, 0, 0
	.quad 0, 0, 0, 0, 0, 0, 0, 0
	.long 0, 0, 0
i = i + 1
	.endr
tss_end:

.section .init

.code32
	call prepare_64
	jmpl $8, $start64

prepare_64:
	lgdt gdt64_desc

	mov %cr4, %eax
	bts $5, %eax  // pae
	mov %eax, %cr4

	mov $ptl4, %eax
	mov %eax, %cr3

efer = 0xc0000080
	mov $efer, %ecx
	rdmsr
	bts $8, %eax
	wrmsr

	mov %cr0, %eax
	bts $0, %eax
	bts $31, %eax
	mov %eax, %cr0
	ret


smp_init_ipi:
	call prepare_64
	jmpl $8, $ap_start64

.code64
ap_start64:
	call load_tss
	sti
	nop

1:	hlt
	jmp 1b

start64:
	call load_tss
	call smp_init
	call main

1:	hlt
	jmp 1b

load_tss:
	mov $0, %eax
	mov %ax, %ss
	mov $(APIC_BASE + APIC_REG_ID), %dx
	in %dx, %eax
	mov %eax, %ebx
	shl $4, %ebx
	mov $((tss_end - tss) / max_cpus), %edx
	imul %edx
	add $tss, %rax
	mov %ax, tss_descr+2(%rbx)
	shr $16, %rax
	mov %al, tss_descr+4(%rbx)
	shr $8, %rax
	mov %al, tss_descr+7(%rbx)
	shr $8, %rax
	mov %eax, tss_descr+8(%rbx)
	lea tss_descr-gdt64(%rbx), %rax
	ltr %ax
	ret

smp_init:
	lea boot_idt + ipi_vector * 8, %rdi
	mov $smp_init_ipi, %eax
	mov %ax, (%rdi)
	mov %cs, %ax
	mov %ax, 2(%rdi)
	movw $0x8e00, 4(%rdi)
	shr $16, %eax
	mov %ax, 6(%rdi)

	mov $(APIC_BASE + APIC_REG_IPI_VECTOR), %dx
	mov $ipi_vector, %eax
	out %eax, %dx

	mov $(APIC_BASE + APIC_REG_NCPU), %dx
	in %dx, %eax
	mov %eax, %ecx
	mov $1, %esi
smp_loop:
	cmp %esi, %ecx
	je smp_init_done

	mov $(APIC_BASE + APIC_REG_SEND_IPI), %dx
	mov %esi, %eax
	out %eax, %dx

	inc %esi
	jmp smp_loop
smp_init_done:
	ret
