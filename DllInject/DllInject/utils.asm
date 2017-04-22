
.data

PUBLIC kernel32_base
PUBLIC kernel64_base
PUBLIC find_getproc

kernel32_base PROC
	mov edx, fs:[30h]
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

; ebx <- kernel32.dll base
; esp <- fn name ptr
; eax -> absolute addr of fn
find_getproc PROC
	db 8bh, 53h, 3ch      ;mov edx, [ebx + 0x3c]		; PE header
	db 8bh, 54h, 1ah, 78h ;mov edx, [edx + ebx + 0x78]  ; rva export dir
	db 8bh, 44h, 1ah, 1ch ;mov eax, [edx + ebx + 0x1c]  ; export addr table
	db 8bh, 54h, 1ah, 20h ;mov edx, [edx + ebx + 0x20]  ; rva fn names
	db 01h, 0dah          ;add edx, ebx
	db 01h, 0d8h          ;add eax, ebx			    	; make va
_loop:
	db 89h, 0e6h       ;mov esi, esp ; esp should point to "GetProcAddress"
	db 8bh, 3ah        ;mov edi, [edx] ; edx should be VA of fn names
	db 01h, 0dfh       ;add edi, ebx   ; kernel32 base
	db 0b1h, 0eh       ;mov cl, 0eh    ; strlen
	db 0f3h, 0a6h      ;repe cmpsb [edi], [esi]
	db 74h, 08h         ;je short fin_search
	db 83h, 0c2h, 04h  ;add edx, 4
	db 83h, 0c0h, 04h  ;add eax, 4
	db 0ebh, 0ech      ;jmp _loop
fin_search:
	db 8bh, 40h, 04h   ;mov eax, [eax+4]
	db 1, 0d8h         ;add eax, ebx
	nop
	nop
	nop
	nop
find_getproc ENDP

END