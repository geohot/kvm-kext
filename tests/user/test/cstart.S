

.bss

.section .init
	call main
1:	hlt
	jmp 1b


