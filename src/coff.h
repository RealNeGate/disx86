#ifndef COFF_H
#define COFF_H

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

COFF_SectionHeader *get_text_section(char *buffer) {
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
		fprintf(stderr, "error: could not locate .text section\n");
		abort();
	}

	return text_section;
}

#endif
