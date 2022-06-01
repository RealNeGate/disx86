#ifndef DISX86_H
#define DISX86_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "public.inc"

typedef enum X86_DataType {
	X86_TYPE_NONE = 0,

	X86_TYPE_BYTE,     // 1
	X86_TYPE_WORD,     // 2
	X86_TYPE_DWORD,    // 4
	X86_TYPE_QWORD,    // 8

	X86_TYPE_PBYTE,   // int8 x 16 = 16
	X86_TYPE_PWORD,   // int16 x 8 = 16
	X86_TYPE_PDWORD,  // int32 x 4 = 16
	X86_TYPE_PQWORD,  // int64 x 2 = 16

	X86_TYPE_SSE_SS,  // float32 x 1 = 4
	X86_TYPE_SSE_SD,  // float64 x 1 = 8
	X86_TYPE_SSE_PS,  // float32 x 4 = 16
	X86_TYPE_SSE_PD,   // float64 x 2 = 16

	X86_TYPE_XMMWORD, // the generic idea of them
} X86_DataType;

typedef enum X86_GPR {
	// this is used for DWORD or QWORD operand types
	X86_RAX = 0, X86_RCX, X86_RDX, X86_RBX, X86_RSP, X86_RBP, X86_RSI, X86_RDI,
	X86_R8, X86_R9, X86_R10, X86_R11, X86_R12, X86_R13, X86_R14, X86_R15,

	X86_EAX = 0, X86_ECX, X86_EDX, X86_EBX, X86_ESP, X86_EBP, X86_ESI, X86_EDI,
	X86_R8D, X86_R9D, X86_R10D, X86_R11D, X86_R12D, X86_R13D, X86_R14D, X86_R15D,

	// when using BYTE as the operand type, these are used instead
	X86_AL = 0, X86_CL, X86_DL, X86_BL, X86_BPL, X86_SPL, X86_SIL, X86_DIL,
	X86_R8B, X86_R9B, X86_R10B, X86_R11B, X86_R12B, X86_R13B, X86_R14B, X86_R15B,

	// high registers are weird
	X86_AH = 16, X86_CH, X86_DH, X86_BH,

	// when using WORD as the operand type
	X86_AX = 0, X86_CX, X86_DX, X86_BX, X86_SP, X86_BP, X86_SI, X86_DI,

    X86_GPR_NONE = -1
} X86_GPR;
#define X86_IS_HIGH_GPR(x)  ((x) >= 16)
#define X86_GET_HIGH_GPR(x) ((x) - 16)

typedef enum X86_XMM {
	X86_XMM0, X86_XMM1, X86_XMM2,  X86_XMM3,  X86_XMM4,  X86_XMM5,  X86_XMM6,  X86_XMM7,
    X86_XMM8, X86_XMM9, X86_XMM10, X86_XMM11, X86_XMM12, X86_XMM13, X86_XMM14, X86_XMM15,

	X86_XMM_NONE = -1
} X86_XMM;

typedef enum X86_Cond {
	X86_O, X86_NO, X86_B, X86_AE, X86_E, X86_NE, X86_BE, X86_A,
	X86_S, X86_NS, X86_P, X86_NP, X86_L, X86_GE, X86_LE, X86_G
} X86_Cond;

typedef enum X86_Segment {
	X86_SEGMENT_DEFAULT = 0,

	X86_SEGMENT_ES, X86_SEGMENT_CS,
	X86_SEGMENT_SS, X86_SEGMENT_DS,
	X86_SEGMENT_GS, X86_SEGMENT_FS,
} X86_Segment;

typedef enum X86_Scale {
	X86_SCALE_X1,
	X86_SCALE_X2,
	X86_SCALE_X4,
	X86_SCALE_X8
} X86_Scale;

typedef enum X86_InstrFlags {
	// uses xmm registers for the reg array
	X86_INSTR_XMMREG = (1u << 0u),

	// r/m is a memory operand
	X86_INSTR_USE_MEMOP = (1u << 1u),

	// r/m is a rip-relative address (X86_INSTR_USE_MEMOP is always set when this is set)
	X86_INSTR_USE_RIPMEM = (1u << 2u),

	// LOCK prefix is present
	X86_INSTR_LOCK = (1u << 3u),

	// uses a signed immediate
	X86_INSTR_IMMEDIATE = (1u << 4u),

	// absolute means it's using the 64bit immediate (cannot be applied while a memory operand is active)
	X86_INSTR_ABSOLUTE = (1u << 5u),

	// set if the r/m can be found on the right hand side
	X86_INSTR_DIRECTION = (1u << 6u),

	// uses the second data type because the instruction is weird like MOVSX or MOVZX
	X86_INSTR_TWO_DATA_TYPES = (1u << 7u)
} X86_InstrFlags;

typedef enum X86_OperandType {
	X86_OPERAND_NONE = 0,

	X86_OPERAND_GPR,      // rax rcx rdx
	X86_OPERAND_GPR_HIGH, // ah  ch  dh
	X86_OPERAND_XMM,      // xmmN
	X86_OPERAND_MEM,      // [base + index * scale + disp]
	X86_OPERAND_RIP,      // rip relative addressing
	X86_OPERAND_IMM,      // imm8/16/32
	X86_OPERAND_OFFSET,   // offset
	X86_OPERAND_ABS64,    // abs64
} X86_OperandType;

typedef struct {
	X86_OperandType type;
	union {
		X86_GPR gpr;
		X86_XMM xmm;
		int32_t imm;
		int32_t offset;
		uint64_t abs64;
		struct {
			X86_GPR base    : 8; // can be X86_GPR_NONE
			X86_GPR index   : 8; // can be X86_GPR_NONE
			X86_Scale scale : 8;
			int32_t disp;
		} mem;
		struct {
			// RIP-relative addressing
			int32_t disp;
		} rip_mem;
	};
} X86_Operand;

typedef struct {
	const uint8_t* data;
	size_t length;
} X86_Buffer;

typedef struct X86_Inst {
	X86_InstType type;

	X86_DataType data_type  : 8;
	X86_DataType data_type2 : 8;
	X86_Segment segment     : 8;
	X86_InstrFlags flags    : 8;
	uint8_t length;

	// normal operands
	int8_t regs[4];

	// immediate operand
	//   imm for INSTR_IMMEDIATE
	//   abs for INSTR_ABSOLUTE
	union {
		int32_t  imm;
		uint64_t abs;
	};

	// memory operand
	struct {
		X86_GPR   base  : 8;
		X86_GPR   index : 8;
		X86_Scale scale : 8;
		int32_t   disp;
	};
} X86_Inst;

typedef enum {
	X86_RESULT_SUCCESS = 0,

	X86_RESULT_OUT_OF_SPACE,
	X86_RESULT_UNKNOWN_OPCODE,
	X86_RESULT_INVALID_RX
} X86_ResultCode;

void x86_print_dfa_DEBUG(void);
X86_ResultCode x86_disasm(X86_Buffer in, X86_Inst* restrict out);
X86_Buffer x86_advance(X86_Buffer in, size_t amount);

// Pretty formats
size_t x86_format_operand(char* out, size_t out_capacity, const X86_Operand* op, X86_DataType dt);
size_t x86_format_inst(char* out, size_t out_capacity, X86_InstType inst, X86_DataType dt);

const char* x86_get_segment_string(X86_Segment segment);
const char* x86_get_result_string(X86_ResultCode res);
const char* x86_get_data_type_string(X86_DataType dt);

#endif //DISX86_H
