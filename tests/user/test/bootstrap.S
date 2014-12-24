/*
 * minimal bootstrap to set up flat 32-bit protected mode
 */

#include "apic.h"
	
bstart = 0xf0000
	
.code16

stack_top = 0x1000
cpu_up = 0x1000
cpu_up_pmode = 0x1004

pmode_stack_start = 0x10000
pmode_stack_shift = 16
pmode_stack_size = (1 << pmode_stack_shift)

ipi_vec = 0xf0
	
start:
	mov $stack_top, %sp
	call smp_init

	cs lidtl idt_desc
	cs lgdtl gdt_desc
	mov %cr0, %eax
	or $1, %eax
	mov %eax, %cr0
	ljmpl $8, $pmode + bstart

smp_init:
	mov $ipi_vec, %eax
	mov $(APIC_BASE + APIC_REG_IPI_VECTOR), %dx
	out %eax, %dx
	movw $ap_switch_to_pmode, ipi_vec*4
	movw %cs, %ax
	mov %ax, ipi_vec*4+2
	mov $sipi, %eax
	mov $(APIC_BASE + APIC_REG_SIPI_ADDR), %dx
	outl %eax, %dx
	mov $(APIC_BASE + APIC_REG_NCPU), %dx
	inl %dx, %eax
	mov %eax, %ecx
	mov $1, %esi
smp_loop:
	cmp %esi, %ecx
	jbe smp_done
	mov %esi, %eax
	mov $(APIC_BASE + APIC_REG_SEND_SIPI), %dx
	outl %eax, %dx
wait_for_cpu:
	cmp cpu_up, %esi
	jne wait_for_cpu
	mov %esi, %eax
	mov $(APIC_BASE + APIC_REG_SEND_IPI), %dx
	out %eax, %dx
wait_for_cpu_pmode:
	cmp cpu_up_pmode, %esi
	jne wait_for_cpu_pmode
	
	inc %esi
	jmp smp_loop
smp_done:
	ret

sipi:
	mov $(APIC_BASE + APIC_REG_ID), %dx
	inl %dx, %eax
	mov %eax, cpu_up
	shl $12, %eax
	addl $stack_top, %eax
	movl %eax, %esp
	sti
	nop
1:	hlt
	jmp 1b

ap_switch_to_pmode:
	cs lidtl idt_desc
	cs lgdtl gdt_desc
	mov %cr0, %eax
	or $1, %eax
	mov %eax, %cr0
	ljmpl $8, $ap_pmode + bstart

.code32	
ap_pmode:
	mov $0x10, %ax
	mov %ax, %ds
	mov %ax, %es
	mov %ax, %fs
	mov %ax, %gs
	mov %ax, %ss
	mov $(APIC_BASE + APIC_REG_ID), %dx
	in %dx, %eax
	mov %eax, cpu_up_pmode
	shl $pmode_stack_shift, %eax
	lea pmode_stack_start + pmode_stack_size(%eax), %esp
	sti
	nop
ap_pmode_wait:
	hlt
	jmp ap_pmode_wait

pmode:
	mov $0x10, %ax
	mov %ax, %ds
	mov %ax, %es
	mov %ax, %fs
	mov %ax, %gs
	mov %ax, %ss
	mov $pmode_stack_start + pmode_stack_size, %esp
	ljmp $8, $0x100000

.align 16
	
idt_desc:
	.word 8*256-1
	.long 0

gdt_desc:
	.word gdt_end - gdt - 1
	.long gdt + bstart

.align 16

gdt:
	.quad 0
	.quad 0x00cf9b000000ffff // flat 32-bit code segment
	.quad 0x00cf93000000ffff // flat 32-bit data segment
gdt_end:
	
. = 0xfff0
	.code16
	ljmp $0xf000, $start
.align 65536
