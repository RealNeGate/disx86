#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <time.h>
#include "disx86.h"

#include "elf.h"
#include "coff.h"

static long get_nanos(void) {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (long)ts.tv_sec * 1000000000L + ts.tv_nsec;
}

static void dissassemble_crap(X86_Buffer input) {
    #if 0
    long start_time = get_nanos();
    int instruction_count = 0;

    while (input.length > 0) {
        X86_Inst inst;
        X86_ResultCode result = x86_disasm(input, &inst);
        if (result != X86_RESULT_SUCCESS) {
            fprintf(stderr, "disassembler error: %s (", x86_get_result_string(result));
            for (int i = 0; i < inst.length; i++) {
                if (i) fprintf(stderr, " ");
                fprintf(stderr, "%x", input.data[i]);
            }
            fprintf(stderr, ")\n");

            abort();
        }

        input = x86_advance(input, inst.length);
        instruction_count++;
    }
    long end_time = get_nanos();
    printf("Elapsed: %.3f seconds (%d instructions)\n", (end_time - start_time) / 1000000000.0, instruction_count);
    #else
    const uint8_t* start = input.data;

    fprintf(stderr, "error: disassembling %zu bytes...\n", input.length);
    while (input.length > 0) {
        X86_Inst inst;
        X86_ResultCode result = x86_disasm(input, &inst);
        if (result != X86_RESULT_SUCCESS) {
            printf("disassembler error: %s (", x86_get_result_string(result));

            if (result == X86_RESULT_UNKNOWN_OPCODE) inst.length = 10;
            for (int i = 0; i < inst.length; i++) {
                if (i) printf(" ");
                printf("%02x", input.data[i]);
            }
            printf(")\n");

            abort();
        }

        // Print the address
        printf("    %016llX: ", (long long)(input.data - start));

        // Print code bytes
        for (int j = 0; j < 6 && j < inst.length; j++) {
            printf("%02X ", input.data[j]);
        }

        int remaining = inst.length > 6 ? 0 : 6 - inst.length;
        while (remaining--) printf("   ");

        // Print some instruction
        char tmp[32];
        x86_format_inst(tmp, sizeof(tmp), inst.type, inst.data_type);
        if (inst.flags & X86_INSTR_LOCK) {
            printf("lock %-7s", tmp);
        } else {
            printf("%-12s", tmp);
        }

        bool has_mem_op = inst.flags & X86_INSTR_USE_MEMOP;
        bool has_immediate = inst.flags & (X86_INSTR_IMMEDIATE | X86_INSTR_ABSOLUTE);

        for (int j = 0; j < 4; j++) {
            X86_DataType dt = inst.data_type;
            if ((inst.flags & X86_INSTR_TWO_DATA_TYPES) != 0 && j == 1) {
                dt = inst.data_type2;
            }

            if (inst.regs[j] == X86_GPR_NONE) {
                // GPR_NONE is either exit or a placeholder if we've got crap
                if (has_mem_op) {
                    has_mem_op = false;

                    if (inst.flags & X86_INSTR_USE_RIPMEM) {
                        size_t next_rip = (input.data - start) + inst.length;

                        snprintf(tmp, sizeof(tmp), "%s ptr [%016"PRIX64"h]", x86_get_data_type_string(dt), next_rip + inst.disp);
                    } else {
                        int l = snprintf(tmp, sizeof(tmp), "%s ptr ", x86_get_data_type_string(dt));
                        if (l < 0 || l >= sizeof(tmp)) abort();

                        X86_Operand dummy = {
                            X86_OPERAND_MEM,
                            .mem = {
                                inst.base, inst.index, inst.scale, inst.disp
                            }
                        };
                        x86_format_operand(tmp + l, sizeof(tmp) - l, &dummy, dt);
                    }
                } else if (has_immediate) {
                    has_immediate = false;

                    int64_t val = (inst.flags & X86_INSTR_ABSOLUTE ? inst.abs : inst.imm);
                    if (val < 0) {
                        snprintf(tmp, sizeof(tmp), "-%"PRIX64"h", (long long) -val);
                    } else {
                        snprintf(tmp, sizeof(tmp), "%"PRIX64"h", (long long) val);
                    }
                } else {
                    break;
                }
            } else {
                bool use_xmm = (inst.flags & X86_INSTR_XMMREG);

                // hack for MOVQ which does xmm and gpr in the same instruction
                if (inst.type == X86_INST_MOVQ) {
                    if (j != ((inst.flags & X86_INSTR_DIRECTION) ? 1 : 0)) use_xmm = true;
                } else if (inst.type == X86_INST_MOVSXD) {
                    if (j == 0) dt = X86_TYPE_QWORD;
                }

                X86_Operand dummy = {
                    use_xmm ? X86_OPERAND_XMM : X86_OPERAND_GPR, .gpr = inst.regs[j]
                };

                if (dummy.type == X86_OPERAND_GPR && X86_IS_HIGH_GPR(inst.regs[j])) {
                    dummy.gpr = X86_GET_HIGH_GPR(inst.regs[j]);
                }
                x86_format_operand(tmp, sizeof(tmp), &dummy, dt);
            }

            if (j) printf(",");
            printf("%s", tmp);
        }

        printf("\n");

        if (inst.length > 6) {
            printf("                      ");

            size_t j = 6;
            while (j < inst.length) {
                printf("%02X ", input.data[j]);

                if (j && j % 6 == 5) {
                    printf("\n");
                    printf("                      ");
                }
                j++;
            }

            printf("\n");
        }

        input = x86_advance(input, inst.length);
    }
    #endif
}

int main(int argc, char* argv[]) {
    //setvbuf(stdout, NULL, _IONBF, 0);

    if (argc <= 1) {
        x86_print_dfa_DEBUG();

        fprintf(stderr, "error: no input file!\n");
        return 1;
    }

    bool is_binary = false;
    const char* source_file = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0) is_binary = true;
        else {
            if (source_file != NULL) {
                fprintf(stderr, "error: can't hecking open multiple files!\n");
                return 1;
            }

            source_file = argv[i];
        }
    }

    fprintf(stderr, "info: opening %s...\n", source_file);

    // Read sum bites
    FILE* file = fopen(source_file, "rb");
    if (file == NULL) {
        fprintf(stderr, "error: could not open file!\n");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    size_t length = ftell(file);
    rewind(file);

    char* buffer = malloc(length * sizeof(char));
    fread(buffer, length, sizeof(char), file);
    fclose(file);

    if (is_binary) {
        dissassemble_crap((X86_Buffer){ (uint8_t*)buffer, length });
    } else {
        ELF_Context ctx = {};
        if (!parse_elf((uint8_t *)buffer, length, &ctx)) {
            uint8_t *text_start = NULL;
            uint64_t text_size = 0;

            for (int i = 0; i < ctx.num_sects; i++) {
                Section s = ctx.sections[i];
                if (!strcmp(s.name, ".text")) {
                    text_start = s.data.data;
                    text_size = s.data.length;
                    break;
                }
            }
            if (!text_start) {
                fprintf(stderr, "error: could not find .text section in ELF file!\n");
            }

            dissassemble_crap((X86_Buffer){ text_start, text_size });
        } else {
            COFF_SectionHeader *text_section = get_text_section(buffer);
            const uint8_t* text_section_start = (uint8_t*) &buffer[text_section->raw_data_pos];
            dissassemble_crap((X86_Buffer){ text_section_start, text_section->raw_data_size });
        }
    }

    return 0;
}
