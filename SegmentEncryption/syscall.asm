.data
	name db 'codepulze',0

.code 
	hello PROC
		nop
		mov eax,ebx
		mov ebx,edx
		mov ebx,eax
		nop
		mov edx,ebx
		ret
	hello ENDP
end