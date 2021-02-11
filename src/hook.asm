public InstallHook
.MODEL flat, c
.STACK
.686
MEM_COMMIT equ 1000h
MEM_RESERVE equ 2000h
PAGE_EXECUTE_READWRITE equ 40h
include kernel32.inc
include msvcrt.inc
includelib kernel32.lib

.code
memset PROTO dest:ptr byte, fillchar:byte, size_fill:dword
memcpy PROTO dest:ptr byte, src:ptr byte, size_fill:dword

FillMemory PROC
	;address equ 08h
	;byte equ 0Ch
	;size_1 equ 0010h
	push ebp
	mov ebp, esp
	sub esp, 04h
	lea eax, [esp]
	push eax
	push PAGE_EXECUTE_READWRITE
	push [ebp+0010h]
	push [ebp+08h]
	call VirtualProtect
	push [ebp + 10h] ; size
	push [ebp + 0Ch]
	push [ebp + 08h] ; address
	call memset
	sub esp, 0Ch
	lea eax, [esp]
	push eax
	push eax
	push [ebp+0010h]
	push [ebp+08h]
	call VirtualProtect
	mov esp, ebp
	pop ebp
	ret
FillMemory ENDP

InstallHook PROC
	;address equ 08h
	;pDetour equ 0Ch
	;size_1 equ 0010h
	;trampoline equ 0014h
	push ebp
    mov ebp, esp
	sub esp, 16
	push ecx
	push ebx

	mov eax, [ebp+08h]			; eax = address
	test eax, eax
	je EndInstallHook			; if eax == 0
	mov bl, byte ptr [eax]		; bl = *eax
	cmp bl, 0E8h
	je SetCallHook				; if bl == 0xE8
SetJmpHook:
	mov eax, [ebp+0014h]		; eax = pTrampoline
	test eax, eax
	je JmpHookNoAlloc			; pTrampoline == 0
	push PAGE_EXECUTE_READWRITE	; flProtect
	mov eax, MEM_COMMIT			; 
	or	eax, MEM_RESERVE		;
	push eax					; flAllocationType
	push 1000					; dwSize
	push 0						; lpAddress
	call VirtualAlloc			; stdcall
	mov ecx, [ebp+14h]			; ecx = pTrampoline
	mov dword ptr [ecx], eax	; *ecx = pAllocatedMem
	mov ebx, eax				; ebx = pAllocatedMem
	mov ecx, [ebp+08h]			; eax = address
	mov al, byte ptr [ecx]		; eax = *address
	cmp al, 0E9h				; 
	je SkipMemCpyJumpHook		; if *address == 0xE9

	push [ebp + 10h]			; size_t
	push [ebp + 8h]				; pSrc
	push ebx					; pDest
	call memcpy					;
	sub esp, 0Ch				; cdecl; clear stack
	mov eax, ebx				; eax = pAllocatedMem
	add eax, [ebp+10h]			; eax += size
	mov byte ptr [eax], 00E9h	; *eax = 0xE9;
	mov ebx, eax				; ebx = pAllocatedMem + size
	mov eax, [ebp + 8h]			; eax = address
	sub eax, ebx				; address -= pTrampoline
	mov ecx, eax				; ecx (RelativeAddress) = address - pTrampoline
	mov eax, ebx				; eax = pAllocatedMem + size
	add eax, 6					; eax = pAllocatedMem + size + 6
	jmp SetRelativeToTrampoline
SkipMemCpyJumpHook:
	mov ecx, [ebp+8h]			; ecx = address
	mov eax, [ecx+1]			; eax = *(address + 1)
	add eax, [ebp+8h]			; eax = *(address + 1) + address
	sub eax, ebx				; eax -= pAllocatedMem
	mov dword ptr [ebx + 1], eax; *(ebx + 1) = eax
	mov byte ptr [ebx], 00E9h	; *ebx = 0xE9;
	jmp JmpHookNoAlloc
SetRelativeToTrampoline:
	mov dword ptr [eax], ecx	; *(pAllocatedMem + size + 6) = RelativeAddress
JmpHookNoAlloc:
	push [ebp + 10h]			; size
	push 90h					; NOP-byte
	push [ebp + 8h]				; address
	call FillMemory				; 
	sub esp, 0Ch				; cdecl; clear stack
	mov eax, [ebp+0Ch]			; eax = pDetour
	mov ecx, [ebp+8h]			; ecx = address
	sub eax, ecx				; eax (RelativeAddress) = pDetour - address
	sub eax, 5					; eax -= 5
	mov ebx, eax				; ebx = RelativeAddress
	mov eax, [ebp+8h]			; eax = address
	mov byte ptr [eax], 00E9h	; *eax = 0xE9
	inc eax						; ++eax
	mov dword ptr [eax], ebx	; *eax = RelativeAddress
	jmp EndInstallHook

SetCallHook:
	mov eax, [ebp+0014h]		; eax = pTrampoline
	test eax, eax
	je CallHookNoAlloc			; pTrampoline == 0
	push PAGE_EXECUTE_READWRITE	; flProtect
	mov eax, MEM_COMMIT			; 
	or	eax, MEM_RESERVE		;
	push eax					; flAllocationType
	push 1000					; dwSize
	push 0						; lpAddress
	call VirtualAlloc			; stdcall
	mov ecx, [ebp+14h]			; ecx = pTrampoline
	mov dword ptr [ecx], eax	; *ecx = pAllocatedMem
	mov ebx, eax				; ebx = pAllocatedMem
	mov byte ptr [eax], 0E8h	; *pAllocatedMem = 0xE8
	mov ecx, [ebp+8h]			; ecx = address
	mov eax, [ecx+1]			; eax = *(address + 1)
	add eax, [ebp+8h]			; eax = *(address + 1) + address
	sub eax, ebx				; eax -= pAllocatedMem
	mov dword ptr [ebx + 1], eax; *(ebx + 1) = eax
	
CallHookNoAlloc:
	push [ebp + 10h]			; size
	push 90h					; NOP-byte
	push [ebp + 8h]				; address
	call FillMemory				; 
	sub esp, 0Ch				; cdecl; clear stack
	mov eax, [ebp + 8h]			; eax = address
	mov ecx, [ebp + 0Ch]		; ecx = pDetour
	sub ecx, eax				; ecx = ecx - eax
	sub ecx, 5					; ecx -= 5
	mov byte ptr [eax], 0E8h	; *eax = 0xE8
	mov dword ptr [eax + 1], ecx; *(eax + 1) = ecx

EndInstallHook:
	pop ebx
	pop ecx
	mov esp, ebp
	pop ebp
	ret
InstallHook ENDP

END