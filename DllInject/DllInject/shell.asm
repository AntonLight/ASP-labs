
IFDEF RAX
mtype typedef qword
ELSE
mtype typedef dword
ENDIF

_TEXT SEGMENT


EXTERN dllname: mtype
EXTERN loadlib: mtype

PUBLIC shellcode
shellcode PROC
	push dllname
	call loadlib

IFDEF RAX
	xor rax, rax
ELSE
	xor eax, eax
ENDIF
L0:
	jmp short L0
shellcode ENDP
shellcode_size dd $ - offset shellcode
PUBLIC shellcode_size

caller PROC
	mov eax, 1234
caller ENDP

_TEXT ENDS
END