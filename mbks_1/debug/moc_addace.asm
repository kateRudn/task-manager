; Listing generated by Microsoft (R) Optimizing Compiler Version 19.16.27025.1 

include listing.inc

INCLUDELIB MSVCRTD
INCLUDELIB OLDNAMES

CONST	SEGMENT
?qt_meta_stringdata_AddAce@@3Uqt_meta_stringdata_AddAce_t@@B DD 0ffffffffH ; qt_meta_stringdata_AddAce
	DD	06H
	DD	00H
	ORG $+4
	DQ	0000000000000018H
	DB	041H
	DB	064H
	DB	064H
	DB	041H
	DB	063H
	DB	065H
	DB	00H
	ORG $+1
?qt_meta_data_AddAce@@3QBIB DD 08H			; qt_meta_data_AddAce
	DD	00H
	DD	00H
	DD	00H
	DD	00H
	DD	00H
	DD	00H
	DD	00H
	DD	00H
	DD	00H
	DD	00H
	DD	00H
	DD	00H
	DD	00H
	DD	00H
	ORG $+4
$SG134758 DB	'c:\qt\5.13.1\msvc2017_64\include\qtcore\qmetatype.h', 00H
	ORG $+12
$SG134759 DB	'qRegisterNormalizedMetaType was called with a not normal'
	DB	'ized type name, please call qRegisterMetaType instead.', 00H
	ORG $+1
$SG134760 DB	'qRegisterNormalizedMetaType', 00H
	ORG $+4
$SG135095 DB	'c:\qt\5.13.1\msvc2017_64\include\qtcore\qmetatype.h', 00H
	ORG $+12
$SG135096 DB	'qRegisterNormalizedMetaType was called with a not normal'
	DB	'ized type name, please call qRegisterMetaType instead.', 00H
	ORG $+1
$SG135097 DB	'qRegisterNormalizedMetaType', 00H
	ORG $+4
$SG135432 DB	'c:\qt\5.13.1\msvc2017_64\include\qtcore\qmetatype.h', 00H
	ORG $+12
$SG135433 DB	'qRegisterNormalizedMetaType was called with a not normal'
	DB	'ized type name, please call qRegisterMetaType instead.', 00H
	ORG $+1
$SG135434 DB	'qRegisterNormalizedMetaType', 00H
CONST	ENDS
PUBLIC	?__empty_global_delete@@YAXPEAX@Z		; __empty_global_delete
PUBLIC	?__empty_global_delete@@YAXPEAX_K@Z		; __empty_global_delete
PUBLIC	??C?$QScopedPointer@VQObjectData@@U?$QScopedPointerDeleter@VQObjectData@@@@@@QEBAPEAVQObjectData@@XZ ; QScopedPointer<QObjectData,QScopedPointerDeleter<QObjectData> >::operator->
PUBLIC	?metaObject@AddAce@@UEBAPEBUQMetaObject@@XZ	; AddAce::metaObject
PUBLIC	?qt_metacast@AddAce@@UEAAPEAXPEBD@Z		; AddAce::qt_metacast
PUBLIC	?qt_metacall@AddAce@@UEAAHW4Call@QMetaObject@@HPEAPEAX@Z ; AddAce::qt_metacall
PUBLIC	?qt_static_metacall@AddAce@@CAXPEAVQObject@@W4Call@QMetaObject@@HPEAPEAX@Z ; AddAce::qt_static_metacall
PUBLIC	?staticMetaObject@AddAce@@2UQMetaObject@@B	; AddAce::staticMetaObject
EXTRN	strcmp:PROC
EXTRN	__imp_?dynamicMetaObject@QObjectData@@QEBAPEAUQMetaObject@@XZ:PROC
EXTRN	__imp_?qt_metacast@QDialog@@UEAAPEAXPEBD@Z:PROC
EXTRN	__imp_?qt_metacall@QDialog@@UEAAHW4Call@QMetaObject@@HPEAPEAX@Z:PROC
EXTRN	__imp_?staticMetaObject@QDialog@@2UQMetaObject@@B:BYTE
_BSS	SEGMENT
?staticMetaObject@AddAce@@2UQMetaObject@@B DB 030H DUP (?) ; AddAce::staticMetaObject
_BSS	ENDS
pdata	SEGMENT
$pdata$?metaObject@AddAce@@UEBAPEBUQMetaObject@@XZ DD imagerel $LN5
	DD	imagerel $LN5+88
	DD	imagerel $unwind$?metaObject@AddAce@@UEBAPEBUQMetaObject@@XZ
$pdata$?qt_metacast@AddAce@@UEAAPEAXPEBD@Z DD imagerel $LN5
	DD	imagerel $LN5+75
	DD	imagerel $unwind$?qt_metacast@AddAce@@UEAAPEAXPEBD@Z
$pdata$?qt_metacall@AddAce@@UEAAHW4Call@QMetaObject@@HPEAPEAX@Z DD imagerel $LN3
	DD	imagerel $LN3+61
	DD	imagerel $unwind$?qt_metacall@AddAce@@UEAAHW4Call@QMetaObject@@HPEAPEAX@Z
pdata	ENDS
CRT$XCU	SEGMENT
??staticMetaObject$initializer$@AddAce@@2P6AXXZEA@@3P6AXXZEA DQ FLAT:??__E?staticMetaObject@AddAce@@2UQMetaObject@@B@@YAXXZ ; ??staticMetaObject$initializer$@AddAce@@2P6AXXZEA@@3P6AXXZEA
CRT$XCU	ENDS
xdata	SEGMENT
$unwind$?metaObject@AddAce@@UEBAPEBUQMetaObject@@XZ DD 010901H
	DD	06209H
$unwind$?qt_metacast@AddAce@@UEAAPEAXPEBD@Z DD 010e01H
	DD	0420eH
$unwind$?qt_metacall@AddAce@@UEAAHW4Call@QMetaObject@@HPEAPEAX@Z DD 011701H
	DD	04217H
xdata	ENDS
; Function compile flags: /Odtp
;	COMDAT ??__E?staticMetaObject@AddAce@@2UQMetaObject@@B@@YAXXZ
text$di	SEGMENT
??__E?staticMetaObject@AddAce@@2UQMetaObject@@B@@YAXXZ PROC ; `dynamic initializer for 'AddAce::staticMetaObject'', COMDAT
; File c:\users\user\desktop\mbks_1\mbks_1\debug\moc_addace.cpp
; Line 67
	mov	rax, QWORD PTR __imp_?staticMetaObject@QDialog@@2UQMetaObject@@B
	mov	QWORD PTR ?staticMetaObject@AddAce@@2UQMetaObject@@B, rax
; Line 68
	lea	rax, OFFSET FLAT:?qt_meta_stringdata_AddAce@@3Uqt_meta_stringdata_AddAce_t@@B
	mov	QWORD PTR ?staticMetaObject@AddAce@@2UQMetaObject@@B+8, rax
; Line 69
	lea	rax, OFFSET FLAT:?qt_meta_data_AddAce@@3QBIB
	mov	QWORD PTR ?staticMetaObject@AddAce@@2UQMetaObject@@B+16, rax
; Line 70
	lea	rax, OFFSET FLAT:?qt_static_metacall@AddAce@@CAXPEAVQObject@@W4Call@QMetaObject@@HPEAPEAX@Z ; AddAce::qt_static_metacall
	mov	QWORD PTR ?staticMetaObject@AddAce@@2UQMetaObject@@B+24, rax
; Line 71
	mov	QWORD PTR ?staticMetaObject@AddAce@@2UQMetaObject@@B+32, 0
; Line 72
	mov	QWORD PTR ?staticMetaObject@AddAce@@2UQMetaObject@@B+40, 0
	ret	0
??__E?staticMetaObject@AddAce@@2UQMetaObject@@B@@YAXXZ ENDP ; `dynamic initializer for 'AddAce::staticMetaObject''
text$di	ENDS
; Function compile flags: /Odtp
_TEXT	SEGMENT
_o$ = 8
_c$ = 16
_id$ = 24
_a$ = 32
?qt_static_metacall@AddAce@@CAXPEAVQObject@@W4Call@QMetaObject@@HPEAPEAX@Z PROC ; AddAce::qt_static_metacall
; File c:\users\user\desktop\mbks_1\mbks_1\debug\moc_addace.cpp
; Line 59
	mov	QWORD PTR [rsp+32], r9
	mov	DWORD PTR [rsp+24], r8d
	mov	DWORD PTR [rsp+16], edx
	mov	QWORD PTR [rsp+8], rcx
; Line 64
	ret	0
?qt_static_metacall@AddAce@@CAXPEAVQObject@@W4Call@QMetaObject@@HPEAPEAX@Z ENDP ; AddAce::qt_static_metacall
_TEXT	ENDS
; Function compile flags: /Odtp
_TEXT	SEGMENT
this$ = 48
_c$ = 56
_id$ = 64
_a$ = 72
?qt_metacall@AddAce@@UEAAHW4Call@QMetaObject@@HPEAPEAX@Z PROC ; AddAce::qt_metacall
; File c:\users\user\desktop\mbks_1\mbks_1\debug\moc_addace.cpp
; Line 90
$LN3:
	mov	QWORD PTR [rsp+32], r9
	mov	DWORD PTR [rsp+24], r8d
	mov	DWORD PTR [rsp+16], edx
	mov	QWORD PTR [rsp+8], rcx
	sub	rsp, 40					; 00000028H
; Line 91
	mov	r9, QWORD PTR _a$[rsp]
	mov	r8d, DWORD PTR _id$[rsp]
	mov	edx, DWORD PTR _c$[rsp]
	mov	rcx, QWORD PTR this$[rsp]
	call	QWORD PTR __imp_?qt_metacall@QDialog@@UEAAHW4Call@QMetaObject@@HPEAPEAX@Z
	mov	DWORD PTR _id$[rsp], eax
; Line 92
	mov	eax, DWORD PTR _id$[rsp]
; Line 93
	add	rsp, 40					; 00000028H
	ret	0
?qt_metacall@AddAce@@UEAAHW4Call@QMetaObject@@HPEAPEAX@Z ENDP ; AddAce::qt_metacall
_TEXT	ENDS
; Function compile flags: /Odtp
_TEXT	SEGMENT
this$ = 48
_clname$ = 56
?qt_metacast@AddAce@@UEAAPEAXPEBD@Z PROC		; AddAce::qt_metacast
; File c:\users\user\desktop\mbks_1\mbks_1\debug\moc_addace.cpp
; Line 82
$LN5:
	mov	QWORD PTR [rsp+16], rdx
	mov	QWORD PTR [rsp+8], rcx
	sub	rsp, 40					; 00000028H
; Line 83
	cmp	QWORD PTR _clname$[rsp], 0
	jne	SHORT $LN2@qt_metacas
	xor	eax, eax
	jmp	SHORT $LN1@qt_metacas
$LN2@qt_metacas:
; Line 84
	lea	rdx, OFFSET FLAT:?qt_meta_stringdata_AddAce@@3Uqt_meta_stringdata_AddAce_t@@B+24
	mov	rcx, QWORD PTR _clname$[rsp]
	call	strcmp
	test	eax, eax
	jne	SHORT $LN3@qt_metacas
; Line 85
	mov	rax, QWORD PTR this$[rsp]
	jmp	SHORT $LN1@qt_metacas
$LN3@qt_metacas:
; Line 86
	mov	rdx, QWORD PTR _clname$[rsp]
	mov	rcx, QWORD PTR this$[rsp]
	call	QWORD PTR __imp_?qt_metacast@QDialog@@UEAAPEAXPEBD@Z
$LN1@qt_metacas:
; Line 87
	add	rsp, 40					; 00000028H
	ret	0
?qt_metacast@AddAce@@UEAAPEAXPEBD@Z ENDP		; AddAce::qt_metacast
_TEXT	ENDS
; Function compile flags: /Odtp
_TEXT	SEGMENT
tv82 = 32
this$ = 64
?metaObject@AddAce@@UEBAPEBUQMetaObject@@XZ PROC	; AddAce::metaObject
; File c:\users\user\desktop\mbks_1\mbks_1\debug\moc_addace.cpp
; Line 77
$LN5:
	mov	QWORD PTR [rsp+8], rcx
	sub	rsp, 56					; 00000038H
; Line 78
	mov	rax, QWORD PTR this$[rsp]
	add	rax, 8
	mov	rcx, rax
	call	??C?$QScopedPointer@VQObjectData@@U?$QScopedPointerDeleter@VQObjectData@@@@@@QEBAPEAVQObjectData@@XZ ; QScopedPointer<QObjectData,QScopedPointerDeleter<QObjectData> >::operator->
	cmp	QWORD PTR [rax+40], 0
	je	SHORT $LN3@metaObject
	mov	rax, QWORD PTR this$[rsp]
	add	rax, 8
	mov	rcx, rax
	call	??C?$QScopedPointer@VQObjectData@@U?$QScopedPointerDeleter@VQObjectData@@@@@@QEBAPEAVQObjectData@@XZ ; QScopedPointer<QObjectData,QScopedPointerDeleter<QObjectData> >::operator->
	mov	rcx, rax
	call	QWORD PTR __imp_?dynamicMetaObject@QObjectData@@QEBAPEAUQMetaObject@@XZ
	mov	QWORD PTR tv82[rsp], rax
	jmp	SHORT $LN4@metaObject
$LN3@metaObject:
	lea	rax, OFFSET FLAT:?staticMetaObject@AddAce@@2UQMetaObject@@B ; AddAce::staticMetaObject
	mov	QWORD PTR tv82[rsp], rax
$LN4@metaObject:
	mov	rax, QWORD PTR tv82[rsp]
; Line 79
	add	rsp, 56					; 00000038H
	ret	0
?metaObject@AddAce@@UEBAPEBUQMetaObject@@XZ ENDP	; AddAce::metaObject
_TEXT	ENDS
; Function compile flags: /Odtp
;	COMDAT ??C?$QScopedPointer@VQObjectData@@U?$QScopedPointerDeleter@VQObjectData@@@@@@QEBAPEAVQObjectData@@XZ
_TEXT	SEGMENT
this$ = 8
??C?$QScopedPointer@VQObjectData@@U?$QScopedPointerDeleter@VQObjectData@@@@@@QEBAPEAVQObjectData@@XZ PROC ; QScopedPointer<QObjectData,QScopedPointerDeleter<QObjectData> >::operator->, COMDAT
; File c:\qt\5.13.1\msvc2017_64\include\qtcore\qscopedpointer.h
; Line 117
	mov	QWORD PTR [rsp+8], rcx
; Line 118
	mov	rax, QWORD PTR this$[rsp]
	mov	rax, QWORD PTR [rax]
; Line 119
	ret	0
??C?$QScopedPointer@VQObjectData@@U?$QScopedPointerDeleter@VQObjectData@@@@@@QEBAPEAVQObjectData@@XZ ENDP ; QScopedPointer<QObjectData,QScopedPointerDeleter<QObjectData> >::operator->
_TEXT	ENDS
; Function compile flags: /Odtp
;	COMDAT ?__empty_global_delete@@YAXPEAX_K@Z
_TEXT	SEGMENT
__formal$ = 8
__formal$ = 16
?__empty_global_delete@@YAXPEAX_K@Z PROC		; __empty_global_delete, COMDAT
; File c:\users\user\desktop\mbks_1\mbks_1\debug\moc_addace.cpp
; Line 96
	mov	QWORD PTR [rsp+16], rdx
	mov	QWORD PTR [rsp+8], rcx
	ret	0
?__empty_global_delete@@YAXPEAX_K@Z ENDP		; __empty_global_delete
_TEXT	ENDS
; Function compile flags: /Odtp
;	COMDAT ?__empty_global_delete@@YAXPEAX@Z
_TEXT	SEGMENT
__formal$ = 8
?__empty_global_delete@@YAXPEAX@Z PROC			; __empty_global_delete, COMDAT
; File c:\users\user\desktop\mbks_1\mbks_1\debug\moc_addace.cpp
; Line 96
	mov	QWORD PTR [rsp+8], rcx
	ret	0
?__empty_global_delete@@YAXPEAX@Z ENDP			; __empty_global_delete
_TEXT	ENDS
END
