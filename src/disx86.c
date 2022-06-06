#include "disx86.h"
#include <string.h>
#include <assert.h>

typedef struct {
	const char* name;

	// if the instruction has a condition code, it's
	// found in the bottom 4bits of the opcode
	bool has_cc;
} InstructionDesc;

#include "table.inc"

#ifdef __BYTE_ORDER__
#  if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#    define DISX86_NEEDS_SWAP 1
#  else
#    define DISX86_NEEDS_SWAP 0
#  endif
#else
#pragma message("Disx86: assumming little endian architecture")
#define DISX86_NEEDS_SWAP 0
#endif

#define DECODE_MODRXRM(mod, rx, rm, src) \
(mod = (src >> 6) & 3, rx = (src >> 3) & 7, rm = (src & 7))

enum {
	MOD_INDIRECT = 0,        // [rax]
	MOD_INDIRECT_DISP8 = 1,  // [rax + disp8]
	MOD_INDIRECT_DISP32 = 2, // [rax + disp32]
	MOD_DIRECT = 3,          // rax
};

inline static void x86__prev(X86_Buffer* restrict in, int adv) {
	in->data -= adv;
	in->length += adv;
}

inline static uint8_t x86__read_uint8(X86_Buffer* restrict in) {
	assert(in->length >= 1);

	uint8_t result = *in->data;
	in->data++;
	in->length--;

	return result;
}

inline static uint16_t x86__read_uint16(X86_Buffer* restrict in) {
	assert(in->length >= 2);

	uint16_t result = *((uint16_t*)in->data);
#if DISX86_NEEDS_SWAP
	result = __builtin_bswap16(result);
#endif

	in->data += 2;
	in->length -= 2;
	return result;
}

inline static uint32_t x86__read_uint32(X86_Buffer* restrict in) {
	assert(in->length >= 4);

	uint32_t result = *((uint32_t*)in->data);
#if DISX86_NEEDS_SWAP
	result = __builtin_bswap32(result);
#endif

	in->data += 4;
	in->length -= 4;
	return result;
}

inline static uint64_t x86__read_uint64(X86_Buffer* restrict in) {
	assert(in->length >= 8);

	uint64_t result = *((uint64_t*)in->data);
#if DISX86_NEEDS_SWAP
	result = __builtin_bswap64(result);
#endif

	in->data += 8;
	in->length -= 8;
	return result;
}

static int8_t x86_parse_memory_op(X86_Buffer* restrict in, X86_Inst* restrict out, uint8_t mod, uint8_t rm, uint8_t rex) {
	if (mod == MOD_DIRECT) {
		return ((rex&1 ? 8 : 0) | rm);
	} else {
		out->disp = 0;
		out->flags |= X86_INSTR_USE_MEMOP;

		// indirect
		if (rm == X86_RSP) {
			uint8_t sib = x86__read_uint8(in);

			uint8_t scale, index, base;
			DECODE_MODRXRM(scale, index, base, sib);

			X86_GPR base_gpr = base != X86_RBP ? ((rex&1 ? 8 : 0) | base) : X86_GPR_NONE;
			X86_GPR index_gpr = index != X86_RSP ? ((rex&2 ? 8 : 0) | index) : X86_GPR_NONE;

			// odd rule but when mod=00,base=101,index=100
			// and using SIB, enable Disp32. this would technically
			// apply to R13 too which means you can't do
			//   lea rax, [r13 + rcx*2] or lea rax, [rbp + rcx*2]
			// only
			//   lea rax, [r13 + rcx*2 + 0] or lea rax, [rbp + rcx*2 + 0]
			if (mod == 0 && base == X86_RBP) {
				mod = MOD_INDIRECT_DISP32;
			}

			out->base = base_gpr;
			out->index = index_gpr;
			out->scale = scale;
		} else {
			if (mod == MOD_INDIRECT && rm == X86_RBP) {
				// RIP-relative addressing
				int32_t disp = x86__read_uint32(in);

				out->flags |= X86_INSTR_USE_RIPMEM;
				out->disp = disp;
			} else {
				out->base = (rex&1 ? 8 : 0) | rm;
				out->index = X86_GPR_NONE;
				out->scale = X86_SCALE_X1;
			}
		}

		if (mod == MOD_INDIRECT_DISP8) {
			int8_t disp = x86__read_uint8(in);
			out->disp = disp;
		} else if (mod == MOD_INDIRECT_DISP32) {
			int32_t disp = x86__read_uint32(in);
			out->disp = disp;
		}

		return X86_GPR_NONE;
	}
}

static void dump(int start, int depth) {
	printf(" %s\n\n", descs[0].name);

	for (int i = 0; i < 256; i++) if (dfa[start+i] != 0) {
		for (int j = 0; j < depth; j++) printf("  ");
		printf("0x%02x", i);
		if (dfa[start+i] & 0x40000000) {
			printf(" +R");
		}

		if (dfa[start+i] & 0x10000000) {
			printf(" RX");
		}

		if ((dfa[start+i] & 0x20000000) == 0) {
			printf("\n");
			dump(dfa[start+i] & 0xFFFF, depth+1);
		} else if (descs[dfa[start+i] & 0xFFFF].has_cc) {
			printf(" %s\n", descs[(dfa[start+i] & 0xFFFF) + i].name);
		} else {
			printf(" %s\n", descs[dfa[start+i] & 0xFFFF].name);
		}
	}
}

void x86_print_dfa_DEBUG(void) {
	dump(DFA_ENTRYPOINT, 0);
}

X86_ResultCode x86_disasm(X86_Buffer in, X86_Inst* restrict out) {
	memset(out, 0, sizeof(*out));
	memset(out->regs, 0xFF, sizeof(out->regs));

	if (in.length >= 4 && memcmp(in.data, (uint8_t[]) { 0xF3, 0x0F, 0x1E, 0xFA }, 4) == 0) {
		// endbr64 hack
		out->type = X86_INST_ENDBR64;
		out->length = 4;
		return X86_RESULT_SUCCESS;
	}

	const uint8_t* start = in.data;
	uint8_t rex = 0;     // 0x4X
	bool addr32 = false; // 0x67
	bool addr16 = false; // 0x66
	bool rep    = false; // 0xF3 these are both used
	bool repne  = false; // 0xF2 to define SSE types

	// parse some prefixes
	uint8_t op;
	while (true) {
		op = x86__read_uint8(&in);

		if ((op & 0xF0) == 0x40) rex = op;
		else if (op == 0x66) addr16 = true;
		else if (op == 0x67) addr32 = true;
		else if (op == 0xF3) rep = true;
		else if (op == 0xF2) repne = true;
		else if (op == 0x2E) out->segment = X86_SEGMENT_CS;
		else if (op == 0x36) out->segment = X86_SEGMENT_SS;
		else if (op == 0x3E) out->segment = X86_SEGMENT_DS;
		else if (op == 0x26) out->segment = X86_SEGMENT_ES;
		else if (op == 0x64) out->segment = X86_SEGMENT_FS;
		else if (op == 0x65) out->segment = X86_SEGMENT_GS;
		else break;
	}

	// DFAs amirite
	X86_ResultCode code = X86_RESULT_SUCCESS;

	// if you use the F2 or F3 prefixes then we'll start the DFA at those bytes
	int val = DFA_ENTRYPOINT;
	if (addr16)  {
		val = dfa[val + 0x66];

		// if there's no match then we'll just neglect the 66h prefix
		if (dfa[val + op] == 0) val = DFA_ENTRYPOINT;
	}
	if (rex & 8) val = dfa[val + 0x48];
	if (rep)     val = dfa[val + 0xF3];
	if (repne)   val = dfa[val + 0xF2];

	// +r means that the bottom 8bits of the opcode encode a register
	bool is_plus_r = false;
	uint8_t opcode_byte = op;
	while (true) {
		val = dfa[val + op];
		if (val & 0x40000000) is_plus_r = true;

		// error state
		if (val == 0) {
			code = X86_RESULT_UNKNOWN_OPCODE;
			goto done;
		} else if (val & 0x20000000) {
			// proper termination
			val &= ~0xF0000000;
			break;
		} else if (val & 0x10000000) {
			// we need to do some RX field digging
			uint8_t mod_rx_rm = x86__read_uint8(&in);
			x86__prev(&in, 1);

			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			val &= ~0xF0000000;
			op = rx;
		} else {
			opcode_byte = op = x86__read_uint8(&in);
		}
	}

	X86_EncodingMode encoding_mode = (val >> 16);
    const InstructionDesc* desc = &descs[val & 0xFFFF];

	out->type = (val & 0xFFFF);
	if (desc->has_cc) {
		out->type += (opcode_byte & 0xF);
	}

	// payload
	uint8_t mod_rx_rm = 0;

	// rules
	bool uses_modrxrm = false;
	bool direction = false;
	bool uses_xmm = false;
	bool single_operand = false;
	bool uses_implicit_rax = false;
	bool uses_implicit_rcx = false;

	enum {
		NO_IMM, UNITY, IMM8, IMM16, IMM32, IMM64
	} uses_imm = NO_IMM;

	// TODO(NeGate): redo the ruleset such that i dont need translation here
	switch (encoding_mode) {
		case X86_ENCODE_void: break;

		case X86_ENCODE_imm_short: {
			uses_imm = IMM8;
			break;
		}

		case X86_ENCODE_imm32_near:
		case X86_ENCODE_imm64_near: {
			uses_imm = IMM32;
			break;
		}

        case X86_ENCODE_reg8_imm: {
			uses_imm = IMM8;
            if (!is_plus_r) {
                uses_modrxrm = true;
                mod_rx_rm = x86__read_uint8(&in);
			}
            break;
        }

        case X86_ENCODE_rm8_imm:
        case X86_ENCODE_rm8_imm8:
        case X86_ENCODE_mem_imm8: {
			uses_imm = IMM8;
			uses_modrxrm = true;
			mod_rx_rm = x86__read_uint8(&in);
			break;
		}

		case X86_ENCODE_reg8:
		case X86_ENCODE_reg16:
		case X86_ENCODE_reg32:
		case X86_ENCODE_reg64: {
			if (!is_plus_r) {
				uses_modrxrm = true;
				mod_rx_rm = x86__read_uint8(&in);
			}
			single_operand = true;
			break;
		}

		case X86_ENCODE_rm8:
		case X86_ENCODE_rm16:
		case X86_ENCODE_rm32:
		case X86_ENCODE_rm64: {
			uses_modrxrm = true;
			mod_rx_rm = x86__read_uint8(&in);
			single_operand = true;
			break;
		}

		case X86_ENCODE_rm8_unity:
		case X86_ENCODE_rm16_unity:
		case X86_ENCODE_rm32_unity:
		case X86_ENCODE_rm64_unity: {
			uses_imm = UNITY;
			uses_modrxrm = true;
			mod_rx_rm = x86__read_uint8(&in);
			single_operand = true;
			break;
		}

		case X86_ENCODE_rm64_reg_cl: {
			uses_implicit_rcx = true;
			mod_rx_rm = x86__read_uint8(&in);
			single_operand = true;
			break;
		}

		case X86_ENCODE_rm8_reg8:
		case X86_ENCODE_rm16_reg16:
		case X86_ENCODE_rm32_reg32:
		case X86_ENCODE_rm64_reg64:
		case X86_ENCODE_reg32_reg32:
		case X86_ENCODE_reg64_reg64:
		case X86_ENCODE_rm64_xmmreg: {
			uses_modrxrm = true;
			mod_rx_rm = x86__read_uint8(&in);
			break;
		}

		case X86_ENCODE_reg8_mem:
		case X86_ENCODE_reg16_mem:
		case X86_ENCODE_reg32_mem:
		case X86_ENCODE_reg64_mem:
		case X86_ENCODE_reg8_rm8:
		case X86_ENCODE_reg16_rm16:
		case X86_ENCODE_reg32_rm32:
		case X86_ENCODE_reg64_rm64: {
			uses_modrxrm = true;
			mod_rx_rm = x86__read_uint8(&in);
			direction = true;
			break;
		}

		case X86_ENCODE_rm32_imm8:
		case X86_ENCODE_rm32_imm32: {
			uses_modrxrm = true;
			mod_rx_rm = x86__read_uint8(&in);
			uses_imm = encoding_mode == X86_ENCODE_rm32_imm8 ? IMM8 : IMM32;
			break;
		}

		case X86_ENCODE_rm64_imm8:
		case X86_ENCODE_rm64_imm32: {
			uses_modrxrm = true;
			mod_rx_rm = x86__read_uint8(&in);
			uses_imm = encoding_mode == X86_ENCODE_rm64_imm8 ? IMM8 : IMM32;
			break;
		}

		case X86_ENCODE_mem_imm32: {
			uses_modrxrm = true;
			mod_rx_rm = x86__read_uint8(&in);
			uses_imm = IMM32;
			break;
		}

		case X86_ENCODE_mem_xmmreg:
		case X86_ENCODE_xmmreg_mem:
		case X86_ENCODE_xmmrm_xmmreg:
		case X86_ENCODE_xmmreg_xmmrm:
		case X86_ENCODE_xmmreg_xmmrm128: {
			uses_modrxrm = true;
			uses_xmm = true;
			direction = true;
			mod_rx_rm = x86__read_uint8(&in);
			break;
		}

		case X86_ENCODE_xmmrm128_xmmreg: {
			uses_modrxrm = true;
			uses_xmm = true;
			mod_rx_rm = x86__read_uint8(&in);
			break;
		}

        case X86_ENCODE_reg_al_imm: {
			uses_imm = IMM8;
			uses_implicit_rax = true;
			break;
        }

        case X86_ENCODE_reg_eax_imm:
		case X86_ENCODE_reg_rax_imm: {
			uses_imm = IMM32;
			uses_implicit_rax = true;
			break;
		}

        case X86_ENCODE_reg_eax_sbytedword:
		case X86_ENCODE_reg_rax_sbytedword: {
			uses_imm = IMM8;
			uses_implicit_rax = true;
			break;
		}

		case X86_ENCODE_reg32_imm: {
			uses_imm = IMM32;
			break;
		}

		case X86_ENCODE_rm64_imm: {
			uses_modrxrm = true;
			mod_rx_rm = x86__read_uint8(&in);
			uses_imm = IMM32;
			break;
		}

		case X86_ENCODE_reg64_imm: {
			uses_imm = IMM64;
			break;
		}

		case X86_ENCODE_reg32_rm8:
		case X86_ENCODE_reg32_rm16:
		case X86_ENCODE_reg64_rm8:
		case X86_ENCODE_reg64_rm16:
		case X86_ENCODE_reg64_rm32: {
			direction = true;
			uses_modrxrm = true;
			mod_rx_rm = x86__read_uint8(&in);
			break;
		}

		case X86_ENCODE_xmmreg_imm: {
			uses_modrxrm = true;
			uses_xmm = true;
			mod_rx_rm = x86__read_uint8(&in);
			uses_imm = IMM8;
			break;
		}

		default: assert(0);
	}

	switch (encoding_mode) {
		case X86_ENCODE_void:
		out->data_type = X86_TYPE_NONE;
		break;

        case X86_ENCODE_reg_al_imm:
        case X86_ENCODE_rm8_imm:
        case X86_ENCODE_reg8_imm:
        case X86_ENCODE_rm8_imm8:
        case X86_ENCODE_mem_imm8:
		case X86_ENCODE_reg8_rm8:
		case X86_ENCODE_reg8_mem:
		case X86_ENCODE_rm8_reg8:
		case X86_ENCODE_rm8:
		case X86_ENCODE_reg8:
		case X86_ENCODE_rm8_unity:
		out->data_type = X86_TYPE_BYTE;
		break;

        case X86_ENCODE_reg_ax_imm:
        case X86_ENCODE_reg16_rm16:
		case X86_ENCODE_reg16_mem:
		case X86_ENCODE_rm16_reg16:
		case X86_ENCODE_rm16:
		case X86_ENCODE_reg16:
		case X86_ENCODE_rm16_unity:
		out->data_type = X86_TYPE_WORD;
		break;

		/*case X86_ENCODE_reg16_rm8:
		out->data_type  = X86_TYPE_WORD;
		out->data_type2 = X86_TYPE_BYTE;
		out->flags |= X86_INSTR_TWO_DATA_TYPES;
		break;*/

		case X86_ENCODE_reg32_rm8:
		out->data_type  = X86_TYPE_DWORD;
		out->data_type2 = X86_TYPE_BYTE;
		out->flags |= X86_INSTR_TWO_DATA_TYPES;
		break;

		case X86_ENCODE_reg32_rm16:
		out->data_type  = X86_TYPE_DWORD;
		out->data_type2 = X86_TYPE_WORD;
		out->flags |= X86_INSTR_TWO_DATA_TYPES;
		break;

		case X86_ENCODE_reg64_rm8:
		out->data_type  = X86_TYPE_QWORD;
		out->data_type2 = X86_TYPE_BYTE;
		out->flags |= X86_INSTR_TWO_DATA_TYPES;
		break;

		case X86_ENCODE_reg64_rm16:
		out->data_type  = X86_TYPE_QWORD;
		out->data_type2 = X86_TYPE_WORD;
		out->flags |= X86_INSTR_TWO_DATA_TYPES;
		break;

		case X86_ENCODE_reg64_rm32: // this is only stuff like MOVSX or MOVZX
		out->data_type  = X86_TYPE_QWORD;
		out->data_type2 = X86_TYPE_DWORD;
		out->flags |= X86_INSTR_TWO_DATA_TYPES;
		break;

		case X86_ENCODE_rm32_imm8:
		case X86_ENCODE_rm32_imm32:
		case X86_ENCODE_reg32_imm:
		case X86_ENCODE_reg32_rm32:
		case X86_ENCODE_reg32_mem:
		case X86_ENCODE_rm32_reg32:
		case X86_ENCODE_rm32:
		case X86_ENCODE_reg32:
		case X86_ENCODE_reg_eax_imm:
		case X86_ENCODE_mem_imm32:
		case X86_ENCODE_rm32_unity:
		out->data_type = X86_TYPE_DWORD;
		break;

		case X86_ENCODE_rm64_imm8:
		case X86_ENCODE_rm64_imm32:
		case X86_ENCODE_reg64_imm:
		case X86_ENCODE_rm64_imm:
		case X86_ENCODE_reg64_reg64:
		case X86_ENCODE_reg64_rm64:
		case X86_ENCODE_reg64_mem:
		case X86_ENCODE_rm64_reg64:
		case X86_ENCODE_rm64_xmmreg:
		case X86_ENCODE_reg_rax_imm:
		case X86_ENCODE_rm64:
		case X86_ENCODE_reg64:
		case X86_ENCODE_imm_short:
		case X86_ENCODE_imm32_near:
		case X86_ENCODE_imm64_near:
		case X86_ENCODE_rm64_unity:
		case X86_ENCODE_reg_eax_sbytedword:
		case X86_ENCODE_reg_rax_sbytedword:
        out->data_type = X86_TYPE_QWORD;
		break;

		case X86_ENCODE_mem_xmmreg:
		case X86_ENCODE_xmmreg_mem:
		case X86_ENCODE_xmmrm_xmmreg:
		case X86_ENCODE_xmmreg_xmmrm:
		case X86_ENCODE_xmmrm128_xmmreg:
		case X86_ENCODE_xmmreg_xmmrm128: {
			// detect data type
			if (rep) out->data_type = X86_TYPE_SSE_SS;
			else if (repne) out->data_type = X86_TYPE_SSE_SD;
			else if (addr16) out->data_type = X86_TYPE_SSE_PD;
			else out->data_type = X86_TYPE_SSE_PS;
			break;
		}

		case X86_ENCODE_xmmreg_imm: {
			out->data_type = X86_TYPE_SSE_SS;
			break;
		}

		default: assert(0);
	}

	if (uses_xmm) {
		out->flags |= X86_INSTR_XMMREG;
	}

	if (direction) {
		out->flags |= X86_INSTR_DIRECTION;
	}

	// Memory operands
	if (uses_modrxrm) {
		uint8_t mod, rx, rm;
		DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

		// immediate usage will use the RX for extended opcode
		if (uses_imm == NO_IMM) {
			out->regs[!direction] = (rex & 4 ? 8 : 0) | rx;
			if (rex == 0 && out->data_type == X86_TYPE_BYTE && out->regs[!direction] >= 4) {
				// use high registers
				out->regs[!direction] += 16;
			}
		} else {
			out->regs[!direction] = X86_GPR_NONE;
		}

		out->regs[direction] = x86_parse_memory_op(&in, out, mod, rm, rex);
		if (rex == 0 && out->data_type == X86_TYPE_BYTE && out->regs[direction] >= 4) {
			// use high registers
			out->regs[direction] += 16;
		}

		if (single_operand) out->regs[1] = X86_GPR_NONE;
		else if (uses_implicit_rax) out->regs[1] = X86_RCX;
	} else if (is_plus_r) {
		out->regs[0] = (rex & 1 ? 8 : 0) | (opcode_byte & 0x7);

		if (rex == 0 && out->data_type == X86_TYPE_BYTE && out->regs[0] >= 4) {
			// use high registers
			out->regs[0] += 16;
		}
	} else if (uses_implicit_rax) {
		out->regs[0] = X86_RAX;
		out->regs[1] = X86_GPR_NONE;
	}

	// Immediates
	switch (uses_imm) {
		case UNITY: {
			out->flags |= X86_INSTR_IMMEDIATE;
			out->imm = 1;
			break;
		}
		case IMM8: {
			out->flags |= X86_INSTR_IMMEDIATE;
			out->imm = (int8_t)x86__read_uint8(&in);
			break;
		}
		case IMM16: {
			out->flags |= X86_INSTR_IMMEDIATE;
			out->imm = (int16_t)x86__read_uint16(&in);
			break;
		}
		case IMM32: {
			out->flags |= X86_INSTR_IMMEDIATE;
			out->imm = (int32_t)x86__read_uint32(&in);
			break;
		}
		case IMM64: {
			out->flags |= X86_INSTR_ABSOLUTE;
			out->abs = x86__read_uint64(&in);
			break;
		}
		default: break;
	}

	done:
	out->length = in.data - start;
	return code;
}

#if 0
X86_ResultCode x86_disasm(X86_Buffer in, X86_Inst* restrict out) {
	// clear out the stuff without clearing the giant chunk
	// of operand storage... it's not actually that big but
	// eh
	out->type = X86_INST_NONE;
	out->length = 0;
	out->data_type = X86_TYPE_NONE;
	out->segment = X86_SEGMENT_DEFAULT;
	out->operand_count = 0;

	if (in.length >= 4 &&
		memcmp(in.data, (uint8_t[]) { 0xF3, 0x0F, 0x1E, 0xFA }, 4) == 0) {
		// endbr64 hack
		out->type = X86_INST_ENDBR64;
		out->length = 4;
		return X86_RESULT_SUCCESS;
	}

	const uint8_t* start = in.data;
	uint8_t rex = 0;     // 0x4X
	bool addr32 = false; // 0x67
	bool addr16 = false; // 0x66
	bool rep    = false; // 0xF3 these are both used
	bool repne  = false; // 0xF2 to define SSE types

	// parse some prefixes
	uint8_t op;
	while (true) {
		op = x86__read_uint8(&in);

		if ((op & 0xF0) == 0x40) rex = op;
		else if (op == 0x66) addr16 = true;
		else if (op == 0x67) addr32 = true;
		else if (op == 0xF3) rep = true;
		else if (op == 0xF2) repne = true;
		else if (op == 0x2E) out->segment = X86_SEGMENT_CS;
		else if (op == 0x36) out->segment = X86_SEGMENT_SS;
		else if (op == 0x3E) out->segment = X86_SEGMENT_DS;
		else if (op == 0x26) out->segment = X86_SEGMENT_ES;
		else if (op == 0x64) out->segment = X86_SEGMENT_FS;
		else if (op == 0x65) out->segment = X86_SEGMENT_GS;
		else break;
	}

	// DFAs amirite
	X86_ResultCode code = X86_RESULT_SUCCESS;

	// if you use the F2 or F3 prefixes then we'll start the DFA at those bytes
	int val = DFA_ENTRYPOINT;
	if (addr16)  {
		val = dfa[val + 0x66];

		// if there's no match then we'll just neglect the 66h prefix
		if (dfa[val + op] == 0) val = DFA_ENTRYPOINT;
	}
	if (rex & 8) val = dfa[val + 0x48];
	if (rep)     val = dfa[val + 0xF3];
	if (repne)   val = dfa[val + 0xF2];

	// +r means that the bottom 8bits of the opcode encode a register
	bool is_plus_r = false;
	while (true) {
		val = dfa[val + op];
		if (val & 0x40000000) is_plus_r = true;

		// error state
		if (val == 0) {
			code = X86_RESULT_UNKNOWN_OPCODE;
			goto done;
		} else if (val & 0x20000000) {
			// proper termination
			val &= ~0xF0000000;
			break;
		} else if (val & 0x10000000) {
			// we need to do some RX field digging
			uint8_t mod_rx_rm = x86__read_uint8(&in);
			x86__prev(&in, 1);

			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			val &= ~0xF0000000;
			op = rx;
		} else {
			op = x86__read_uint8(&in);
		}
	}

	X86_EncodingMode encoding_mode = (val >> 16);
    const InstructionDesc* desc = &descs[val & 0xFFFF];

	out->type = (val & 0xFFFF);
	if (desc->has_cc) {
		out->type += (op & 0xF);
	}

	switch (encoding_mode) {
		case X86_ENCODE_void: break;
		case X86_ENCODE_reg_al_imm: {
			out->data_type = X86_TYPE_BYTE;

			out->operand_count = 2;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_GPR, .gpr = X86_RAX
			};

			int8_t imm = (int8_t)x86__read_uint8(&in);
			out->operands[1] = (X86_Operand){
				X86_OPERAND_IMM, .imm = imm
			};
			break;
		}
		case X86_ENCODE_reg_ax_imm: {
			out->data_type = X86_TYPE_WORD;

			out->operand_count = 2;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_GPR, .gpr = X86_RAX
			};

			int32_t imm = (int16_t)x86__read_uint16(&in);
			out->operands[1] = (X86_Operand){
				X86_OPERAND_IMM, .imm = imm
			};
			break;
		}
		case X86_ENCODE_reg_eax_imm: {
			out->data_type = X86_TYPE_DWORD;

			out->operand_count = 2;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_GPR, .gpr = X86_RAX
			};

			int32_t imm = x86__read_uint32(&in);
			out->operands[1] = (X86_Operand){
				X86_OPERAND_IMM, .imm = imm
			};
			break;
		}
		case X86_ENCODE_reg_rax_imm: {
			out->data_type = X86_TYPE_QWORD;

			out->operand_count = 2;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_GPR, .gpr = X86_RAX
			};

			int32_t imm = x86__read_uint32(&in);
			out->operands[1] = (X86_Operand){
				X86_OPERAND_IMM, .imm = imm
			};
			break;
		}
		case X86_ENCODE_xmmreg_imm: {
			uint8_t mod_rx_rm = x86__read_uint8(&in);
			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->operand_count = 2;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_XMM, .xmm = (rex & 1 ? 8 : 0) | rm
			};

			int8_t imm = x86__read_uint8(&in);
			out->operands[1] = (X86_Operand){
				X86_OPERAND_IMM, .imm = imm
			};
			break;
		}
		case X86_ENCODE_xmmreg_rm64:
		case X86_ENCODE_rm64_xmmreg: {
			bool direction = (encoding_mode == X86_ENCODE_xmmreg_rm64);
			out->data_type = X86_TYPE_QWORD;

			uint8_t mod_rx_rm = x86__read_uint8(&in);
			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->operand_count = 2;
			out->operands[!direction] = (X86_Operand){
				X86_OPERAND_XMM, .xmm = (rex & 4 ? 8 : 0) | rx
			};

			out->operands[direction] = (X86_Operand){
				X86_OPERAND_GPR, .gpr = (rex & 1 ? 8 : 0) | rm
			};
			break;
		}
		case X86_ENCODE_xmmreg_xmmreg: {
			// detect data type
			if (rep) out->data_type = X86_TYPE_SSE_SS;
			else if (repne) out->data_type = X86_TYPE_SSE_SD;
			else if (addr16) out->data_type = X86_TYPE_SSE_PD;
			else out->data_type = X86_TYPE_SSE_PS;

			uint8_t mod_rx_rm = x86__read_uint8(&in);
			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->operand_count = 2;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_XMM, .xmm = (rex & 4 ? 8 : 0) | rx
			};

			out->operands[1] = (X86_Operand){
				X86_OPERAND_XMM, .xmm = (rex & 1 ? 8 : 0) | rm
			};
			break;
		}
		case X86_ENCODE_mem_xmmreg:
		case X86_ENCODE_xmmreg_mem:
		case X86_ENCODE_xmmrm_xmmreg:
		case X86_ENCODE_xmmreg_xmmrm:
		case X86_ENCODE_xmmrm128_xmmreg:
		case X86_ENCODE_xmmreg_xmmrm128: {
			bool direction = (encoding_mode == X86_ENCODE_xmmreg_xmmrm128)
				|| (encoding_mode == X86_ENCODE_xmmreg_mem)
				|| (encoding_mode == X86_ENCODE_xmmreg_xmmrm);

			// detect data type
			if (rep) out->data_type = X86_TYPE_SSE_SS;
			else if (repne) out->data_type = X86_TYPE_SSE_SD;
			else if (addr16) out->data_type = X86_TYPE_SSE_PD;
			else out->data_type = X86_TYPE_SSE_PS;

			uint8_t mod_rx_rm = x86__read_uint8(&in);
			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->operand_count = 2;
			out->operands[!direction] = (X86_Operand){
				X86_OPERAND_XMM, .xmm = (rex & 4 ? 8 : 0) | rx
			};

			X86_Operand* rm_operand = &out->operands[direction];
			if (!x86_parse_memory_op(&in, rm_operand, mod, rm, rex)) {
				code = X86_RESULT_OUT_OF_SPACE;
				goto done;
			}

			if (rm_operand->type == X86_OPERAND_GPR) {
				rm_operand->type = X86_OPERAND_XMM;
			}
			break;
		}
		case X86_ENCODE_imm_short:
		case X86_ENCODE_imm32_near:
		case X86_ENCODE_imm64_near: {
			out->data_type = X86_TYPE_NONE;

			int32_t offset;
			if (encoding_mode == X86_ENCODE_imm64_near) offset = x86__read_uint32(&in);
			else if (encoding_mode == X86_ENCODE_imm32_near) offset = x86__read_uint32(&in);
			else offset = (int8_t)x86__read_uint8(&in);

			out->operand_count = 1;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_OFFSET, .offset = offset
			};
			break;
		}
		case X86_ENCODE_reg8:
		case X86_ENCODE_reg16:
		case X86_ENCODE_reg32:
		case X86_ENCODE_reg64: {
			out->data_type = (rex & 8) ? X86_TYPE_QWORD : X86_TYPE_DWORD;

			if (is_plus_r) {
				out->operand_count = 1;
				out->operands[0] = (X86_Operand){ X86_OPERAND_GPR, .gpr = (rex & 1 ? 8 : 0) | (op & 0x7) };
			} else {
				uint8_t mod_rx_rm = x86__read_uint8(&in);

				uint8_t mod, rx, rm;
				DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

				out->operand_count = 1;
				out->operands[0] = (X86_Operand){ X86_OPERAND_GPR, .gpr = (rex & 4 ? 8 : 0) | rx };
			}
			break;
		}
		case X86_ENCODE_reg32_reg32:
		case X86_ENCODE_reg64_reg64: {
			out->data_type = (rex & 8) ? X86_TYPE_QWORD : X86_TYPE_DWORD;

			uint8_t mod_rx_rm = x86__read_uint8(&in);

			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->operand_count = 2;
			out->operands[0] = (X86_Operand){ X86_OPERAND_GPR, .gpr = (rex & 4 ? 8 : 0) | rx };
			out->operands[1] = (X86_Operand){ X86_OPERAND_GPR, .gpr = (rex & 1 ? 8 : 0) | rm };
			break;
		}
		case X86_ENCODE_rm8_reg8:
		case X86_ENCODE_reg8_rm8:
		case X86_ENCODE_rm16_reg16:
		case X86_ENCODE_reg16_rm16:
		case X86_ENCODE_rm32_reg32:
		case X86_ENCODE_reg32_rm32:
		case X86_ENCODE_rm64_reg64:
		case X86_ENCODE_reg64_rm32:
		case X86_ENCODE_reg64_rm64: {
			bool direction = (encoding_mode == X86_ENCODE_reg64_rm64 ||
							  encoding_mode == X86_ENCODE_reg64_rm32 ||
							  encoding_mode == X86_ENCODE_reg32_rm32 ||
							  encoding_mode == X86_ENCODE_reg16_rm16 ||
							  encoding_mode == X86_ENCODE_reg8_rm8);

			// detect data type
			if (encoding_mode != X86_ENCODE_reg8_rm8 &&
				encoding_mode != X86_ENCODE_rm8_reg8) {
				if (rex & 8) out->data_type = X86_TYPE_QWORD;
				else if (addr16) out->data_type = X86_TYPE_WORD;
				else out->data_type = X86_TYPE_DWORD;
			} else out->data_type = X86_TYPE_BYTE;

			out->data_type = (rex & 8) ? X86_TYPE_QWORD : X86_TYPE_DWORD;

			uint8_t mod_rx_rm = x86__read_uint8(&in);
			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->operand_count = 2;
			out->operands[!direction] = (X86_Operand){
				X86_OPERAND_GPR, .xmm = (rex & 4 ? 8 : 0) | rx
			};

			X86_Operand* rm_operand = &out->operands[direction];
			if (!x86_parse_memory_op(&in, rm_operand, mod, rm, rex)) {
				code = X86_RESULT_OUT_OF_SPACE;
				goto done;
			}
			break;
		}
		case X86_ENCODE_reg8_mem:
		case X86_ENCODE_reg16_mem:
		case X86_ENCODE_reg32_mem:
		case X86_ENCODE_reg64_mem: {
			if (encoding_mode == X86_ENCODE_reg8) out->data_type = X86_TYPE_BYTE;
			else if (encoding_mode == X86_ENCODE_reg16) out->data_type = X86_TYPE_WORD;
			else out->data_type = (rex & 8) ? X86_TYPE_QWORD : X86_TYPE_DWORD;

			uint8_t mod_rx_rm = x86__read_uint8(&in);
			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->operand_count = 2;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_GPR, .xmm = (rex & 4 ? 8 : 0) | rx
			};

			if (!x86_parse_memory_op(&in, &out->operands[1], mod, rm, rex)) {
				code = X86_RESULT_OUT_OF_SPACE;
				goto done;
			}
			break;
		}
		case X86_ENCODE_mem_imm8:
		case X86_ENCODE_rm16_imm8:
		case X86_ENCODE_rm32_imm8:
		case X86_ENCODE_rm64_imm8: {
			// classify type
			if (encoding_mode == X86_ENCODE_rm64_imm8) out->data_type = X86_TYPE_QWORD;
			else if (encoding_mode == X86_ENCODE_rm32_imm8) out->data_type = X86_TYPE_DWORD;
			else if (encoding_mode == X86_ENCODE_rm16_imm8) out->data_type = X86_TYPE_WORD;
			else out->data_type = X86_TYPE_BYTE;

			uint8_t mod_rx_rm = x86__read_uint8(&in);

			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->operand_count = 2;
			if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
				code = X86_RESULT_OUT_OF_SPACE;
				goto done;
			}

			int8_t imm = x86__read_uint8(&in);
			out->operands[1] = (X86_Operand){
				X86_OPERAND_IMM, .imm = imm
			};
			break;
		}
		case X86_ENCODE_mem_imm32:
		case X86_ENCODE_rm32_imm32:
		case X86_ENCODE_rm64_imm32: {
			// classify type
			if (encoding_mode == X86_ENCODE_rm64_imm32) out->data_type = X86_TYPE_QWORD;
			else out->data_type = X86_TYPE_DWORD;

			uint8_t mod_rx_rm = x86__read_uint8(&in);

			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->operand_count = 2;
			if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
				code = X86_RESULT_OUT_OF_SPACE;
				goto done;
			}

			int32_t imm = x86__read_uint32(&in);
			out->operands[1] = (X86_Operand){
				X86_OPERAND_IMM, .imm = imm
			};
			break;
		}
		case X86_ENCODE_rm16_imm:
		case X86_ENCODE_rm32_imm:
		case X86_ENCODE_rm64_imm: {
			uint8_t mod_rx_rm = x86__read_uint8(&in);

			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->operand_count = 2;
			if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
				code = X86_RESULT_OUT_OF_SPACE;
				goto done;
			}

			// classify type
			uint64_t imm = 0;
			if (encoding_mode == X86_ENCODE_rm64_imm) {
				imm = (int64_t) ((int32_t)x86__read_uint32(&in));
				out->data_type = X86_TYPE_QWORD;
			} else if (encoding_mode == X86_ENCODE_rm32_imm) {
				imm = x86__read_uint32(&in);
				out->data_type = X86_TYPE_DWORD;
			} else if (encoding_mode == X86_ENCODE_rm16_imm) {
				imm = x86__read_uint16(&in);
				out->data_type = X86_TYPE_WORD;
			} else {
				imm = x86__read_uint8(&in);
				out->data_type = X86_TYPE_BYTE;
			}

			out->operands[1] = (X86_Operand){ X86_OPERAND_ABS64, .abs64 = imm };
			break;
		}
		case X86_ENCODE_reg16_imm:
		case X86_ENCODE_reg32_imm:
		case X86_ENCODE_reg64_imm: {
			out->operand_count = 2;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_GPR, .xmm = (rex & 1 ? 8 : 0) | (op & 0x7)
			};

			// classify type
			uint64_t imm = 0;
			if (encoding_mode == X86_ENCODE_reg64_imm) {
				imm = x86__read_uint64(&in);
				out->data_type = X86_TYPE_QWORD;
			} else if (encoding_mode == X86_ENCODE_reg32_imm) {
				imm = x86__read_uint32(&in);
				out->data_type = X86_TYPE_DWORD;
			} else if (encoding_mode == X86_ENCODE_reg16_imm) {
				imm = x86__read_uint16(&in);
				out->data_type = X86_TYPE_WORD;
			} else {
				imm = x86__read_uint8(&in);
				out->data_type = X86_TYPE_BYTE;
			}

			out->operands[1] = (X86_Operand){ X86_OPERAND_ABS64, .abs64 = imm };
			break;
		}
		case X86_ENCODE_rm16:
		case X86_ENCODE_rm32:
		case X86_ENCODE_rm64: {
			// classify type
			if (encoding_mode == X86_ENCODE_rm64) out->data_type = X86_TYPE_QWORD;
			else if (encoding_mode == X86_ENCODE_rm32) out->data_type = X86_TYPE_DWORD;
			else if (encoding_mode == X86_ENCODE_rm16) out->data_type = X86_TYPE_WORD;
			else out->data_type = X86_TYPE_BYTE;

			uint8_t mod_rx_rm = x86__read_uint8(&in);

			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->operand_count = 1;
			if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
				code = X86_RESULT_OUT_OF_SPACE;
				goto done;
			}
			break;
		}
		default: {
			fprintf(stderr, "error: unknown encoding mode!\n");
			abort();
		}
	}

	done:
	out->length = (in.data - start);
	return code;
}
#endif

#if 0
X86_Result x86_disasm(X86_Buffer in, X86_Inst* restrict out) {
	// clear out the stuff without clearing the giant chunk
	// of operand storage... it's not actually that big but
	// eh
	out->type = X86_INST_NONE;
	out->data_type = X86_TYPE_NONE;
	out->segment = X86_SEGMENT_DEFAULT;
	out->operand_count = 0;

	const uint8_t* start = in.data;
	uint8_t rex = 0;     // 0x4X
	bool addr16 = false; // 0x66
	bool rep    = false; // 0xF3 these are both used
	bool repne  = false; // 0xF2 to define SSE types

	// parse some prefixes
	uint8_t op;
	while (true) {
		op = x86__read_uint8(&in);

		if ((op & 0xF0) == 0x40) rex = op;
		else if (op == 0x66) addr16 = true;
		else if (op == 0xF3) rep = true;
		else if (op == 0xF2) repne = true;
		else if (op == 0x2E) out->segment = X86_SEGMENT_CS;
		else if (op == 0x36) out->segment = X86_SEGMENT_SS;
		else if (op == 0x3E) out->segment = X86_SEGMENT_DS;
		else if (op == 0x26) out->segment = X86_SEGMENT_ES;
		else if (op == 0x64) out->segment = X86_SEGMENT_FS;
		else if (op == 0x65) out->segment = X86_SEGMENT_GS;
		else break;
	}

	// bottom two bits aren't opcode, they're
	// fields for different instructions... except
	// when they are which is something we handle
	// as it comes up
	X86_ResultCode code = X86_RESULT_SUCCESS;
	switch (op & 0xFC) {
		case 0xC0: {
			if (op == 0xC0 || op == 0xC1) {
				// shl, shr, sar
				// detect data type
				if (op & 1) {
					if (rex & 8) out->data_type = X86_TYPE_QWORD;
					else if (addr16) out->data_type = X86_TYPE_WORD;
					else out->data_type = X86_TYPE_DWORD;
				} else out->data_type = X86_TYPE_BYTE;

				uint8_t mod_rx_rm = x86__read_uint8(&in);

				uint8_t mod, rx, rm;
				DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

				switch (rx) {
					case 4: out->type = X86_INST_SHL; break;
					case 5: out->type = X86_INST_SHR; break;
					case 7: out->type = X86_INST_SAR; break;
					default: {
						// TODO(NeGate): incomplete... maybe
						code = X86_RESULT_UNKNOWN_OPCODE;
						goto done;
					}
				}

				out->operand_count = 2;
				if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
					code = X86_RESULT_OUT_OF_SPACE;
					goto done;
				}

				uint8_t imm = x86__read_uint8(&in);
				out->operands[1] = (X86_Operand){
					X86_OPERAND_IMM, .imm = imm
				};
			} else if (op == 0xC2) {
				uint16_t imm = x86__read_uint16(&in);

				out->type = X86_INST_RET;
				out->data_type = X86_TYPE_NONE;
				out->operand_count = 1;
				out->operands[0] = (X86_Operand){ X86_OPERAND_IMM, .imm = imm };
			} else if (op == 0xC3) {
				out->type = X86_INST_RET;
				out->data_type = X86_TYPE_NONE;
				out->operand_count = 0;
			} else {
				// TODO(NeGate): incomplete... maybe
				code = X86_RESULT_UNKNOWN_OPCODE;
				goto done;
			}
			break;
		}
		case 0x00:
		case 0x08:
		case 0x18:
		case 0x28:
		case 0x30:
		case 0x38:
		case 0x88: {
			switch (op & 0xFC) {
				case 0x00: out->type = X86_INST_ADD; break;
				case 0x08: out->type = X86_INST_OR; break;
				case 0x18: out->type = X86_INST_SBB; break;
				case 0x28: out->type = X86_INST_SUB; break;
				case 0x30: out->type = X86_INST_XOR; break;
				case 0x38: out->type = X86_INST_CMP; break;
				case 0x88: out->type = X86_INST_MOV; break;
				default: __builtin_unreachable();
			}

			// detect data type
			if (op & 1) {
				if (rex & 8) out->data_type = X86_TYPE_QWORD;
				else if (addr16) out->data_type = X86_TYPE_WORD;
				else out->data_type = X86_TYPE_DWORD;
			} else out->data_type = X86_TYPE_BYTE;

			// direction flag controls which side gets the r/m
			// 0: OP r/m, reg, 1: OP reg, r/m
			bool direction = op & 2;
			uint8_t mod_rx_rm = x86__read_uint8(&in);

			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->operand_count = 2;
			out->operands[direction ? 0 : 1] = (X86_Operand){
				X86_OPERAND_GPR, .gpr = (rex & 4 ? 8 : 0) | rx
			};

			if (!x86_parse_memory_op(&in, &out->operands[direction ? 1 : 0], mod, rm, rex)) {
				code = X86_RESULT_OUT_OF_SPACE;
				goto done;
			}
			break;
		}
		case 0x50:
		case 0x54: {
			// 50+ rd PUSH
			out->type = X86_INST_PUSH;
			out->data_type = X86_TYPE_QWORD;
			out->operand_count = 1;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_GPR, .gpr = (rex & 1 ? 8 : 0) | (op - 0x50)
			};
			break;
		}
		case 0x58:
		case 0x5C: {
			// 58+ rd POP
			out->type = X86_INST_POP;
			out->data_type = X86_TYPE_QWORD;
			out->operand_count = 1;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_GPR, .gpr = (rex & 1 ? 8 : 0) | (op - 0x58)
			};
			break;
		}
		case 0x60: {
			if (op != 0x63) {
				code = X86_RESULT_UNKNOWN_OPCODE;
				goto done;
			}

			// MOVSXD
			uint8_t mod_rx_rm = x86__read_uint8(&in);

			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->type = X86_INST_MOVSXD;
			out->data_type = rex & 8 ? X86_TYPE_QWORD : X86_TYPE_DWORD;
			out->operand_count = 2;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_GPR, .gpr = (rex & 4 ? 8 : 0) | rx
			};

			if (!x86_parse_memory_op(&in, &out->operands[1], mod, rm, rex)) {
				code = X86_RESULT_OUT_OF_SPACE;
				goto done;
			}
			break;
		}
		case 0x68: {
			if (op == 0x68) {
				// PUSH imm8
				int8_t imm = x86__read_uint8(&in);

				out->type = X86_INST_PUSH;
				out->data_type = X86_TYPE_QWORD;
				out->operand_count = 1;
				out->operands[0] = (X86_Operand){
					X86_OPERAND_IMM, .imm = imm
				};
			} else if (op == 0x6A) {
				// PUSH imm32
				int32_t imm = x86__read_uint32(&in);

				out->type = X86_INST_PUSH;
				out->data_type = X86_TYPE_QWORD;
				out->operand_count = 1;
				out->operands[0] = (X86_Operand){
					X86_OPERAND_IMM, .imm = imm
				};
			} else {
				code = X86_RESULT_UNKNOWN_OPCODE;
				goto done;
			}
			break;
		}
		case 0x70:
		case 0x74:
		case 0x78:
		case 0x7C: {
			out->type = X86_INST_JO + (op - 0x70);
			out->data_type = X86_TYPE_NONE;

			int8_t offset = x86__read_uint8(&in);

			out->operand_count = 1;
			out->operands[0] = (X86_Operand){
				X86_OPERAND_OFFSET, .offset = offset
			};
			break;
		}
		case 0x80: {
			// detect data type
			if (op & 1) {
				if (rex & 8) out->data_type = X86_TYPE_QWORD;
				else if (addr16) out->data_type = X86_TYPE_WORD;
				else out->data_type = X86_TYPE_DWORD;
			} else out->data_type = X86_TYPE_BYTE;

			// OP r/m, imm
			uint8_t mod_rx_rm = x86__read_uint8(&in);

			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			switch (rx) {
				case 0: out->type = X86_INST_ADD; break;
				case 1: out->type = X86_INST_OR; break;
				case 4: out->type = X86_INST_AND; break;
				case 5: out->type = X86_INST_SUB; break;
				case 6: out->type = X86_INST_XOR; break;
				case 7: out->type = X86_INST_CMP; break;
			}

			out->operand_count = 2;

			// parse r/m operand
			if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
				code = X86_RESULT_OUT_OF_SPACE;
				goto done;
			}

			// parse immediate
			if ((op & 2) || out->data_type == X86_TYPE_BYTE) {
				// imm8
				int8_t imm = x86__read_uint8(&in);
				out->operands[1] = (X86_Operand){ X86_OPERAND_IMM, .imm = imm };
			} else {
				// imm32
				int32_t imm = x86__read_uint32(&in);
				out->operands[1] = (X86_Operand){ X86_OPERAND_IMM, .imm = imm };
			}
			break;
		}
		case 0x84: {
			if (op != 0x84 && op != 0x85) {
				code = X86_RESULT_OUT_OF_SPACE;
				goto done;
			}

			// OP r/m, imm
			uint8_t mod_rx_rm = x86__read_uint8(&in);

			uint8_t mod, rx, rm;
			DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

			out->type = X86_INST_TEST;

			// detect data type
			if (op & 1) {
				if (rex & 8) out->data_type = X86_TYPE_QWORD;
				if (addr16) out->data_type = X86_TYPE_WORD;
				else out->data_type = X86_TYPE_DWORD;
			} else out->data_type = X86_TYPE_BYTE;

			out->operand_count = 2;
			out->operands[1] = (X86_Operand){
				X86_OPERAND_GPR, .gpr = (rex & 4 ? 8 : 0) | rx
			};

			// parse r/m operand
			if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
				code = X86_RESULT_OUT_OF_SPACE;
				goto done;
			}
			break;
		}
		case 0x8C: {
			if (op == 0x8D) {
				// 0x8D lea
				uint8_t mod_rx_rm = x86__read_uint8(&in);

				uint8_t mod, rx, rm;
				DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

				out->type = X86_INST_LEA;
				out->data_type = (rex & 8) ? X86_TYPE_QWORD : X86_TYPE_DWORD;
				out->operand_count = 2;
				out->operands[0] = (X86_Operand) {
					X86_OPERAND_GPR, .gpr = rx
				};

				// parse r/m operand
				if (!x86_parse_memory_op(&in, &out->operands[1], mod, rm, rex)) {
					code = X86_RESULT_OUT_OF_SPACE;
					goto done;
				}
			} else if (op == 0x8F) {
				// 0x8F /0 pop
				uint8_t mod_rx_rm = x86__read_uint8(&in);

				uint8_t mod, rx, rm;
				DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

				out->type = X86_INST_POP;
				out->data_type = (rex & 8) ? X86_TYPE_QWORD : X86_TYPE_DWORD;
				out->operand_count = 1;

				if (rx != 0) {
					code = X86_RESULT_UNKNOWN_OPCODE;
					goto done;
				}

				// parse r/m operand
				if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
					code = X86_RESULT_OUT_OF_SPACE;
					goto done;
				}
			} else {
				// TODO(NeGate): incomplete... probably?
				code = X86_RESULT_UNKNOWN_OPCODE;
				goto done;
			}
			break;
		}
		case 0x90: {
			// single byte NOP
			out->type = X86_INST_NOP;
			out->data_type = X86_TYPE_NONE;
			out->operand_count = 0;
			break;
		}
		case 0xB8:
		case 0xBC: {
			// MOV with immediates
			//       B8+ rd imm32
			// REX.W B8+ rd imm32
			uint8_t rx = op - 0xB8;

			out->type = X86_INST_MOV;
			out->data_type = rex & 8 ? X86_TYPE_QWORD : X86_TYPE_DWORD;
			out->operand_count = 2;
			out->operands[0] = (X86_Operand){ X86_OPERAND_GPR, .gpr = (rex & 4 ? 8 : 0) | rx };

			if (rex & 8) {
				uint64_t imm = x86__read_uint64(&in);
				out->operands[1] = (X86_Operand){ X86_OPERAND_ABS64, .abs64 = imm };
			} else {
				uint32_t imm = x86__read_uint32(&in);
				out->operands[1] = (X86_Operand){ X86_OPERAND_IMM, .imm = imm };
			}
			break;
		}
		case 0xC4: {
			if (op == 0xC6) {
				// OP r/m8, imm8
				uint8_t mod_rx_rm = x86__read_uint8(&in);

				uint8_t mod, rx, rm;
				DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

				out->type = X86_INST_MOV;
				out->data_type = X86_TYPE_BYTE;
				out->operand_count = 2;

				// parse r/m operand
				if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
					code = X86_RESULT_OUT_OF_SPACE;
					goto done;
				}

				// parse immediate
				int8_t imm = x86__read_uint8(&in);
				out->operands[1] = (X86_Operand){ X86_OPERAND_IMM, .imm = imm };
			} else if (op == 0xC7) {
				// OP r/m, imm
				uint8_t mod_rx_rm = x86__read_uint8(&in);

				uint8_t mod, rx, rm;
				DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

				out->type = X86_INST_MOV;
				out->data_type = rex & 8 ? X86_TYPE_QWORD : (addr16 ? X86_TYPE_WORD : X86_TYPE_DWORD);
				out->operand_count = 2;

				// parse r/m operand
				if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
					code = X86_RESULT_OUT_OF_SPACE;
					goto done;
				}

				// parse immediate
				int32_t imm = x86__read_uint32(&in);
				out->operands[1] = (X86_Operand){ X86_OPERAND_IMM, .imm = imm };
			} else {
				// TODO(NeGate): incomplete... maybe
				code = X86_RESULT_UNKNOWN_OPCODE;
				goto done;
			}
			break;
		}
		case 0xCC: {
			if (op == 0xCC) {
				out->type = X86_INST_INT;
				out->operand_count = 1;
				out->operands[0] = (X86_Operand){ X86_OPERAND_IMM, .imm = 3 };
			} else if (op == 0xCD) {
				uint8_t imm = x86__read_uint8(&in);

				out->type = X86_INST_INT;
				out->operand_count = 1;
				out->operands[0] = (X86_Operand){ X86_OPERAND_IMM, .imm = imm };
			} else {
				// TODO(NeGate): incomplete... maybe
				code = X86_RESULT_UNKNOWN_OPCODE;
				goto done;
			}
			break;
		}
		case 0xE8: {
			out->data_type = X86_TYPE_NONE;
			out->operand_count = 1;
			out->operands[0] = (X86_Operand){ X86_OPERAND_OFFSET };

			if (op == 0xE8) {
				// call rel32
				out->type = X86_INST_CALL;
				out->operands[0].offset = x86__read_uint32(&in);
			} else if (op == 0xE9) {
				// jmp rel32
				out->type = X86_INST_JMP;
				out->operands[0].offset = x86__read_uint32(&in);
			} else if (op == 0xEB) {
				// jmp rel8
				out->type = X86_INST_JMP;
				out->operands[0].offset = x86__read_uint8(&in);
			} else {
				// TODO(NeGate): incomplete... maybe
				code = X86_RESULT_UNKNOWN_OPCODE;
				goto done;
			}
			break;
		}
		case 0x0C: {
			if (op != 0x0F) {
				// TODO(NeGate): incomplete... maybe
				code = X86_RESULT_UNKNOWN_OPCODE;
				goto done;
			}

			// 0x0F is fancy extensions
			uint8_t ext_opcode = x86__read_uint8(&in);
			switch (ext_opcode) {
				case 0x1F: {
					// multibyte NOP
					// yes... NOPs have data types and operands... that's where the
					// weird variety of NOPs comes from, it's just abusing different
					// addressing modes
					uint8_t mod_rx_rm = x86__read_uint8(&in);

					uint8_t mod, rx, rm;
					DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

					out->type = X86_INST_NOP;
					out->data_type = addr16 ? X86_TYPE_WORD : X86_TYPE_DWORD;
					out->operand_count = 1;

					if (rx != 0) {
						// rx has to be 0 tho
						code = X86_RESULT_INVALID_RX;
						goto done;
					}

					// parse r/m operand
					if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
						code = X86_RESULT_UNKNOWN_OPCODE;
						goto done;
					}
					break;
				}
				case 0x10:
				case 0x11: {
					// movups
					// direction is set, then it's storing not loading
					bool direction = (ext_opcode & 1);
					out->type = X86_INST_SSE_MOVU;

					// detect data type
					if (rep) out->data_type = X86_TYPE_SSE_SS;
					else if (repne) out->data_type = X86_TYPE_SSE_SD;
					else if (addr16) out->data_type = X86_TYPE_SSE_PD;
					else out->data_type = X86_TYPE_SSE_PS;

					uint8_t mod_rx_rm = x86__read_uint8(&in);
					uint8_t mod, rx, rm;
					DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

					out->operand_count = 2;
					out->operands[direction ? 1 : 0] = (X86_Operand){
						X86_OPERAND_XMM, .xmm = (rex & 4 ? 8 : 0) | rx
					};

					X86_Operand* rm_operand = &out->operands[direction ? 0 : 1];
					if (!x86_parse_memory_op(&in, rm_operand, mod, rm, rex)) {
						code = X86_RESULT_OUT_OF_SPACE;
						goto done;
					}

					if (rm_operand->type == X86_OPERAND_GPR) {
						rm_operand->type = X86_OPERAND_XMM;
					}
					break;
				}
				case 0x40 ... 0x4F: {
					// cmovcc reg, r/m
					out->type = X86_INST_CMOVO + (ext_opcode - 0x40);

					// detect data type
					if (rex & 8) out->data_type = X86_TYPE_QWORD;
					if (addr16) out->data_type = X86_TYPE_WORD;
					else out->data_type = X86_TYPE_DWORD;

					uint8_t mod_rx_rm = x86__read_uint8(&in);
					uint8_t mod, rx, rm;
					DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

					out->operand_count = 2;
					out->operands[0] = (X86_Operand){
						X86_OPERAND_GPR, .gpr = (rex & 4 ? 8 : 0) | rx
					};

					if (!x86_parse_memory_op(&in, &out->operands[1], mod, rm, rex)) {
						code = X86_RESULT_OUT_OF_SPACE;
						goto done;
					}
					break;
				}
				case 0x58:
				case 0x59:
				case 0x5C:
				case 0x5E:
				case 0xC2:
				case 0x5A:
				case 0x51:
				case 0x52:
				case 0x54:
				case 0x56:
				case 0x57: {
					// xorps
					switch (ext_opcode) {
						case 0x58: out->type = X86_INST_SSE_ADD; break;
						case 0x59: out->type = X86_INST_SSE_MUL; break;
						case 0x5C: out->type = X86_INST_SSE_SUB; break;
						case 0x5E: out->type = X86_INST_SSE_DIV; break;
						case 0xC2: out->type = X86_INST_SSE_CMP; break;
						case 0x5A: out->type = X86_INST_SSE_CVT; break;
						case 0x51: out->type = X86_INST_SSE_SQRT; break;
						case 0x52: out->type = X86_INST_SSE_RSQRT; break;
						case 0x54: out->type = X86_INST_SSE_AND; break;
						case 0x56: out->type = X86_INST_SSE_OR; break;
						case 0x57: out->type = X86_INST_SSE_XOR; break;
					}

					// detect data type
					if (rep) out->data_type = X86_TYPE_SSE_SS;
					else if (repne) out->data_type = X86_TYPE_SSE_SD;
					else if (addr16) out->data_type = X86_TYPE_SSE_PD;
					else out->data_type = X86_TYPE_SSE_PS;

					uint8_t mod_rx_rm = x86__read_uint8(&in);

					uint8_t mod, rx, rm;
					DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

					out->operand_count = 2;
					out->operands[0] = (X86_Operand){
						X86_OPERAND_XMM, .xmm = (rex & 4 ? 8 : 0) | rx
					};

					if (!x86_parse_memory_op(&in, &out->operands[1], mod, rm, rex)) {
						code = X86_RESULT_OUT_OF_SPACE;
						goto done;
					}

					// hacky but the parse_memory_op code will make DIRECT addressing
					// as a GPR but in this case we want an XMM register, since the GPR
					// and XMM field overlap it's only a matter of changing the operand
					// type.
					if (out->operands[1].type == X86_OPERAND_GPR) {
						out->operands[1].type = X86_OPERAND_XMM;
					}
					break;
				}
				case 0xFC:
				case 0xFD:
				case 0xFE:
				case 0xD4: {
					if (!addr16) {
						// TODO(NeGate): without the addr16, they map to MMX stuff
						// which im not implementing quite yet
						code = X86_RESULT_UNKNOWN_OPCODE;
						goto done;
					}

					// padd(b|w|d|q) xmm, xmm/m128
					out->type = X86_INST_SSE_PADD;

					// detect data type
					if (ext_opcode == 0xFC) out->data_type = X86_TYPE_PBYTE;
					else if (ext_opcode == 0xFD) out->data_type = X86_TYPE_PWORD;
					else if (ext_opcode == 0xFE) out->data_type = X86_TYPE_PDWORD;
					else out->data_type = X86_TYPE_PQWORD;

					uint8_t mod_rx_rm = x86__read_uint8(&in);

					uint8_t mod, rx, rm;
					DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

					out->operand_count = 2;
					out->operands[0] = (X86_Operand){
						X86_OPERAND_XMM, .xmm = (rex & 4 ? 8 : 0) | rx
					};

					if (!x86_parse_memory_op(&in, &out->operands[1], mod, rm, rex)) {
						code = X86_RESULT_OUT_OF_SPACE;
						goto done;
					}

					if (out->operands[1].type == X86_OPERAND_GPR) {
						out->operands[1].type = X86_OPERAND_XMM;
					}
					break;
				}
				case 0x6F:
				case 0x7F: {
					// movdq(u/a)
					// direction is set, then it's storing not loading
					bool direction = (ext_opcode == 0x7F);
					if (addr16) out->type = X86_INST_SSE_MOVDQA;
					else if (rep) out->type = X86_INST_SSE_MOVDQU;
					else {
						code = X86_RESULT_UNKNOWN_OPCODE;
						goto done;
					}

					uint8_t mod_rx_rm = x86__read_uint8(&in);
					uint8_t mod, rx, rm;
					DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

					out->data_type = X86_TYPE_XMMWORD;
					out->operand_count = 2;
					out->operands[direction ? 1 : 0] = (X86_Operand){
						X86_OPERAND_XMM, .xmm = (rex & 4 ? 8 : 0) | rx
					};

					X86_Operand* rm_operand = &out->operands[direction ? 0 : 1];
					if (!x86_parse_memory_op(&in, rm_operand, mod, rm, rex)) {
						code = X86_RESULT_OUT_OF_SPACE;
						goto done;
					}

					if (rm_operand->type == X86_OPERAND_GPR) {
						rm_operand->type = X86_OPERAND_XMM;
					}
					break;
				}
				case 0x6E:
				case 0x7E: {
					// mov(d/q)
					// direction is set, then it's storing not loading
					bool direction = (ext_opcode == 0x7E);
					if (addr16) {
						out->type = X86_INST_SSE_MOVDQ;

						// REX.W means it's MOVQ instead of MOVD
						out->data_type = (rex & 8) ? X86_TYPE_QWORD : X86_TYPE_DWORD;
					} else {
						code = X86_RESULT_UNKNOWN_OPCODE;
						goto done;
					}

					uint8_t mod_rx_rm = x86__read_uint8(&in);
					uint8_t mod, rx, rm;
					DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

					out->operand_count = 2;
					out->operands[direction ? 1 : 0] = (X86_Operand){
						X86_OPERAND_XMM, .xmm = (rex & 4 ? 8 : 0) | rx
					};

					X86_Operand* rm_operand = &out->operands[direction ? 0 : 1];
					if (!x86_parse_memory_op(&in, rm_operand, mod, rm, rex)) {
						code = X86_RESULT_OUT_OF_SPACE;
						goto done;
					}
					break;
				}
				case 0x73: {
					// TODO(NeGate): this has other modes... i think?
					out->data_type = X86_TYPE_PQWORD;

					// funky imm8 based instruction variants like PSRLDQ
					uint8_t mod_rx_rm = x86__read_uint8(&in);

					uint8_t mod, rx, rm;
					DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

					switch (rx) {
						case 0x03: out->type = X86_INST_SSE_PSRLD; break;
						default: {
							code = X86_RESULT_UNKNOWN_OPCODE;
							goto done;
						}
					}

					out->operand_count = 2;
					if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
						code = X86_RESULT_OUT_OF_SPACE;
						goto done;
					}

					if (out->operands[0].type == X86_OPERAND_GPR) {
						out->operands[0].type = X86_OPERAND_XMM;
					}

					int8_t imm = x86__read_uint8(&in);
					out->operands[1] = (X86_Operand){ X86_OPERAND_IMM, .imm = imm };
					break;
				}
				case 0x80 ... 0x8F: {
					// jcc rel32
					out->type = X86_INST_JO + (ext_opcode - 0x80);
					out->data_type = X86_TYPE_NONE;

					int32_t offset = x86__read_uint32(&in);

					out->operand_count = 1;
					out->operands[0] = (X86_Operand){
						X86_OPERAND_OFFSET, .offset = offset
					};
					break;
				}
				case 0x90 ... 0x9F: {
					// setc r/m8
					out->type = X86_INST_SETO + (ext_opcode - 0x90);
					out->data_type = X86_TYPE_BYTE;

					uint8_t mod_rx_rm = x86__read_uint8(&in);

					uint8_t mod, rx, rm;
					DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

					out->operand_count = 1;
					if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
						code = X86_RESULT_OUT_OF_SPACE;
						goto done;
					}
					break;
				}
				case 0xAF: {
					// imul reg, r/m
					out->type = X86_INST_IMUL;

					if (rex & 8) out->data_type = X86_TYPE_QWORD;
					if (addr16) out->data_type = X86_TYPE_WORD;
					else out->data_type = X86_TYPE_DWORD;

					uint8_t mod_rx_rm = x86__read_uint8(&in);

					uint8_t mod, rx, rm;
					DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

					out->operand_count = 2;
					out->operands[0] = (X86_Operand){
						X86_OPERAND_GPR, .gpr = rx
					};

					if (!x86_parse_memory_op(&in, &out->operands[1], mod, rm, rex)) {
						code = X86_RESULT_OUT_OF_SPACE;
						goto done;
					}
					break;
				}
				case 0xB6:
				case 0xB7: {
					out->type = op & 1 ? X86_INST_MOVZXW : X86_INST_MOVZXB;
					out->data_type = rex & 8 ? X86_TYPE_QWORD : X86_TYPE_DWORD;
					if ((rex & 8) == 0 && addr16 && op == 0xB6) {
						out->data_type = X86_TYPE_WORD;
					}

					uint8_t mod_rx_rm = x86__read_uint8(&in);
					uint8_t mod, rx, rm;
					DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

					out->operand_count = 2;
					out->operands[0] = (X86_Operand){
						X86_OPERAND_GPR, .gpr = rx
					};

					if (!x86_parse_memory_op(&in, &out->operands[1], mod, rm, rex)) {
						code = X86_RESULT_OUT_OF_SPACE;
						goto done;
					}
					break;
				}
				default: {
					code = X86_RESULT_UNKNOWN_OPCODE;
					goto done;
				}
			}
			break;
		}
		case 0xF4: {
			if (op == 0xF6 || op == 0xF7) {
				out->type = X86_INST_TEST;

				if (op & 1) {
					if (rex & 8) out->data_type = X86_TYPE_QWORD;
					if (addr16) out->data_type = X86_TYPE_WORD;
					else out->data_type = X86_TYPE_DWORD;
				} else out->data_type = X86_TYPE_BYTE;

				uint8_t mod_rx_rm = x86__read_uint8(&in);

				uint8_t mod, rx, rm;
				DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

				out->operand_count = 2;
				if (rx != 0) {
					// rx has to be 0 tho
					code = X86_RESULT_INVALID_RX;
					goto done;
				}

				// parse r/m operand
				if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
					code = X86_RESULT_UNKNOWN_OPCODE;
					goto done;
				}

				if (op & 1) {
					uint32_t imm = x86__read_uint32(&in);
					out->operands[1] = (X86_Operand){ X86_OPERAND_IMM, .imm = imm };
				} else {
					uint8_t imm = x86__read_uint8(&in);
					out->operands[1] = (X86_Operand){ X86_OPERAND_IMM, .imm = imm };
				}
			} else {
				code = X86_RESULT_UNKNOWN_OPCODE;
				goto done;
			}
			break;
		}
		case 0xFC: {
			if (op == 0xFF) {
				uint8_t mod_rx_rm = x86__read_uint8(&in);

				uint8_t mod, rx, rm;
				DECODE_MODRXRM(mod, rx, rm, mod_rx_rm);

				out->type = X86_INST_PUSH;
				out->data_type = addr16 ? X86_TYPE_WORD : X86_TYPE_DWORD;
				out->operand_count = 1;

				if (rx != 0) {
					// rx has to be 0 tho
					code = X86_RESULT_INVALID_RX;
					goto done;
				}

				// parse r/m operand
				if (!x86_parse_memory_op(&in, &out->operands[0], mod, rm, rex)) {
					code = X86_RESULT_UNKNOWN_OPCODE;
					goto done;
				}
			} else {
				code = X86_RESULT_UNKNOWN_OPCODE;
				goto done;
			}
			break;
		}
		default: {
			code = X86_RESULT_UNKNOWN_OPCODE;
			break;
		}
	}

	done:
	return (X86_Result){ code, in.data - start };
}
#endif

X86_Buffer x86_advance(X86_Buffer in, size_t amount) {
	assert(in.length >= amount);

	in.data += amount;
	in.length -= amount;

	return in;
}

size_t x86_format_operand(char* out, size_t out_capacity, const X86_Operand* op, X86_DataType dt) {
	static const char* X86__GPR_NAMES[4][16] = {
		{ "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
			"r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b" },

		{ "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
			"r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w" },

		{ "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
			"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" },

		{ "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
			"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" }
	};

	static const char* X86__HIGH_NAMES[] = {
		"ah", "ch", "dh", "bh"
	};

	switch (op->type) {
		case X86_OPERAND_NONE: {
			out[0] = '\0';
			return 0;
		}
		case X86_OPERAND_GPR: {
			return snprintf(out, out_capacity, "%s", X86__GPR_NAMES[dt - X86_TYPE_BYTE][op->gpr]);
		}
		case X86_OPERAND_GPR_HIGH: {
			return snprintf(out, out_capacity, "%s", X86__HIGH_NAMES[op->gpr]);
		}
		case X86_OPERAND_XMM: {
			return snprintf(out, out_capacity, "xmm%d", op->xmm);
		}
		case X86_OPERAND_IMM: {
			return snprintf(out, out_capacity, "%d", op->imm);
		}
		case X86_OPERAND_OFFSET: {
			return snprintf(out, out_capacity, "%d", op->offset);
		}
		case X86_OPERAND_ABS64: {
			return snprintf(out, out_capacity, "%lld", (long long)op->abs64);
		}
		case X86_OPERAND_MEM: {
			if (op->mem.index == X86_GPR_NONE) {
				if (op->mem.base == X86_GPR_NONE) {
					return snprintf(out, out_capacity, "[%xh]",
									op->mem.disp);
				} else {
					if (op->mem.disp == 0) {
						return snprintf(out, out_capacity, "[%s]",
										X86__GPR_NAMES[3][op->mem.base]);
					} else if (op->mem.disp < 0) {
						return snprintf(out, out_capacity, "[%s-%Xh]",
										X86__GPR_NAMES[3][op->mem.base],
										-op->mem.disp);
					} else {
						return snprintf(out, out_capacity, "[%s+%Xh]",
										X86__GPR_NAMES[3][op->mem.base],
										op->mem.disp);
					}
				}
			} else {
				if (op->mem.base == X86_GPR_NONE) {
					if (op->mem.disp == 0) {
						return snprintf(out, out_capacity, "[%s*%d]",
										X86__GPR_NAMES[3][op->mem.index],
										1 << op->mem.scale);
					} else {
						return snprintf(out, out_capacity, "[%s*%d+%xh]",
										X86__GPR_NAMES[3][op->mem.index],
										1 << op->mem.scale,
										op->mem.disp);
					}
				} else {
					if (op->mem.disp == 0) {
						return snprintf(out, out_capacity, "[%s+%s*%d]",
										X86__GPR_NAMES[3][op->mem.base],
										X86__GPR_NAMES[3][op->mem.index],
										1 << op->mem.scale);
					} else {
						return snprintf(out, out_capacity, "[%s+%s*%d+%Xh]",
										X86__GPR_NAMES[3][op->mem.base],
										X86__GPR_NAMES[3][op->mem.index],
										1 << op->mem.scale,
										op->mem.disp);
					}
				}
			}
		}
		case X86_OPERAND_RIP: {
			return snprintf(out, out_capacity, "[rip + %d]", op->rip_mem.disp);
		}
		default: abort();
	}
}

size_t x86_format_inst(char* out, size_t out_capacity, X86_InstType inst, X86_DataType dt) {
	return snprintf(out, out_capacity, "%s", descs[inst].name);
}

const char* x86_get_segment_string(X86_Segment res) {
	switch (res) {
		case X86_SEGMENT_ES: return "es";
		case X86_SEGMENT_CS: return "cs";
		case X86_SEGMENT_SS: return "ss";
		case X86_SEGMENT_DS: return "ds";
		case X86_SEGMENT_GS: return "gs";
		case X86_SEGMENT_FS: return "fs";
		default: return "";
	}
}

const char* x86_get_result_string(X86_ResultCode res) {
	switch (res) {
		case X86_RESULT_SUCCESS: return "success";
		case X86_RESULT_OUT_OF_SPACE: return "out of space";
		case X86_RESULT_UNKNOWN_OPCODE: return "unknown opcode";
		case X86_RESULT_INVALID_RX: return "invalid rx";
		default: return "unknown";
	}
}

const char* x86_get_data_type_string(X86_DataType dt) {
	switch (dt) {
		case X86_TYPE_BYTE: return "byte";
		case X86_TYPE_WORD: return "word";
		case X86_TYPE_DWORD: return "dword";
		case X86_TYPE_QWORD: return "qword";
		case X86_TYPE_SSE_SS: return "dword";
		case X86_TYPE_SSE_SD: return "qword";

		// TODO(NeGate): umm... these are all technically xmm words...
		case X86_TYPE_PBYTE: return "xmmword";
		case X86_TYPE_PWORD: return "xmmword";
		case X86_TYPE_PDWORD: return "xmmword";
		case X86_TYPE_PQWORD: return "xmmword";
		case X86_TYPE_SSE_PS: return "xmmword";
		case X86_TYPE_SSE_PD: return "xmmword";
		case X86_TYPE_XMMWORD: return "xmmword";
		default: return "none";
	}
}
