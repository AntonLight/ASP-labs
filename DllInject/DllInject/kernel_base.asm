
.code

PUBLIC kernel32_base
PUBLIC kernel64_base

kernel32_base PROC
	mov edx, fs:[30h]
	; For some reason MASM sucked in assembling
	db 8bh, 52h, 0ch	;mov edx, [edx+0Ch] ; -> loader
	db 8bh, 52h, 14h	;mov edx, [edx+14h] ; -> in-mem module list
	db 8bh, 12h			;mov edx, [edx]     ; -> next entry
	db 8bh, 12h			;mov edx, [edx]     ; -> next entry
	db 8bh, 42h, 10h	;mov eax, [edx+10h] ; -> base addr
	nop
	nop
	nop
	nop
kernel32_base ENDP

kernel64_base PROC
	mov rdx, gs:[60h]
	mov rdx, [rdx+18h]
	mov rdx, [rdx+20h]
	mov rdx, [rdx]
	mov rdx, [rdx]
	mov rax, [rdx+20h]
	nop
	nop
	nop
	nop
kernel64_base ENDP

END