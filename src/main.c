#define _CRT_SECURE_NO_WARNINGS
#include <string.h>
#include "disx86.h"

typedef struct COFF_SectionHeader {
	char name[8];
	union {
		uint32_t physical_address;
		uint32_t virtual_size;
	} misc;
	uint32_t  virtual_address;
	uint32_t  raw_data_size;
	uint32_t  raw_data_pos;
	uint32_t  pointer_to_reloc;
	uint32_t  pointer_to_lineno;
	uint16_t  num_reloc;
	uint16_t  num_lineno;
	uint32_t  characteristics;
} COFF_SectionHeader;
static_assert(sizeof(COFF_SectionHeader) == 40, "COFF Section header size != 40 bytes");

typedef struct COFF_FileHeader {
	uint16_t machine;
	uint16_t num_sections;
	uint32_t timestamp;
	uint32_t symbol_table;
	uint32_t symbol_count;
	uint16_t optional_header_size;
	uint16_t characteristics;
} COFF_FileHeader;
static_assert(sizeof(COFF_FileHeader) == 20, "COFF File header size != 20 bytes");

int main(int argc, char* argv[]) {
	if (argc < 1) {
		printf("error: no input file!\n");
		return 1;
	}
	
	printf("Opening %s...\n", argv[1]);
	
	// Read sum bites
	static char buffer[1 << 20];
	FILE* file = fopen(argv[1], "rb");
	if (file == NULL) {
		printf("could not open file!\n");
		return 1;
	}
	
	fseek(file, 0, SEEK_END);
	size_t length = ftell(file);
	rewind(file);
	
	if (length >= sizeof(buffer)) {
		printf("File too big!!");
		abort();
	}
	
	fread(buffer, length, sizeof(char), file);
	fclose(file);
	
	// Locate .text section
	// TODO(NeGate): this isn't properly checked for endianness... i dont care
	// here...
	COFF_FileHeader* file_header = ((COFF_FileHeader*) buffer);
	COFF_SectionHeader* text_section = NULL;
	for (size_t i = 0; i < file_header->num_sections; i++) {
		size_t section_offset = sizeof(COFF_FileHeader) + (i * sizeof(COFF_SectionHeader));
		COFF_SectionHeader* sec = ((COFF_SectionHeader*) &buffer[section_offset]);
		
		// not very robust because it assumes that the compiler didn't 
		// put .text name into a text section and instead did it inplace
		if (strcmp(sec->name, ".text") == 0 ||
			strcmp(sec->name, ".text$mn") == 0) {
			text_section = sec;
			break;
		}
	}
	
	if (text_section == NULL) {
		printf("Could not locate .text section\n");
		abort();
	}
	
	const uint8_t* text_section_start = (uint8_t*) &buffer[text_section->raw_data_pos];
	
	X86_Buffer input = { 
		text_section_start,
		text_section->raw_data_size
	};
	
	printf("Disassembling %zu bytes...\n", input.length);
	while (input.length > 0) {
		X86_Inst inst;
		X86_Result result = x86_disasm(input, &inst);
		if (result.code != X86_RESULT_SUCCESS) {
			printf("disassembler error: %s\n", x86_get_result_string(result.code));
			abort();
		}
		
		// Print the address
		printf("    %016llx: ", input.data - text_section_start);
		
		// Print code bytes
		int j = 0;
		while (j < result.instruction_length) {
			printf("%02x ", input.data[j]);
			
			if (j && j % 6 == 5) {
				break;
			}
			j++;
		}
		
		int remaining = result.instruction_length > 6 
			? 0 : 6 - result.instruction_length;
		
		while (remaining--) {
			printf("   ");
		}
		
		// Print some instruction
		char tmp[32];
		x86_format_inst(tmp, sizeof(tmp), inst.type, inst.data_type);
		printf("%s\t", tmp);
		
		for (int j = 0; j < inst.operand_count; j++) {
			if (j) printf(",");
			
			x86_format_operand(tmp, sizeof(tmp), &inst.operands[j], inst.data_type);
			if (inst.operands[j].type == X86_OPERAND_OFFSET) {
				int64_t base_address = (input.data - text_section_start)
					+ result.instruction_length;
				
				printf("%llx", base_address + inst.operands[j].offset);
			} else if (inst.operands[j].type == X86_OPERAND_RIP ||
					   inst.operands[j].type == X86_OPERAND_MEM) {
				printf("%s ptr ", x86_get_data_type_string(inst.data_type));
				
				if (inst.segment != X86_SEGMENT_DEFAULT) {
					printf("%s:%s", x86_get_segment_string(inst.segment), tmp);
				} else {
					printf("%s", tmp);
				}
			} else {
				printf("%s", tmp);
			}
		}
		
		printf("\n");
		
		if (j > result.instruction_length) {
			printf("                      ");
			
			while (j < result.instruction_length) {
				printf("%02x ", input.data[j]);
				
				if (j && j % 6 == 5) {
					printf("\n");
					printf("                      ");
				}
				j++;
			}
		}
		
		input = x86_advance(input, result.instruction_length);
	}
	
	return 0;
}
