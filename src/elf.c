#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "elf.h"

#define myassert(x, ...) do { if (!(x)) { dprintf(2, __VA_ARGS__); exit(1); } } while (0)

static inline Slice into_slice(u8 *data, u64 length) {
	Slice s;
	s.data = data;
	s.length = length;
	return s;
}

// s = [1,2,3,4]
// s[1:] -> [2,3,4]
static inline Slice sub_slice(Slice in, u64 offset) {
	myassert(offset <= in.length, "invalid subslice! (slice[%llu:], %llu > %llu)\n", offset, offset, in.length);

	Slice s;
	s.data = in.data + offset;
	s.length = in.length - offset;
	return s;
}

// s = [1,2,3,4]
// s[1:2] -> [2,3]
static inline Slice chunk_slice(Slice in, u64 offset, u64 length) {
	u64 new_tail = offset + length;
	myassert(new_tail <= in.length, "invalid subslice! (slice[%llu:%llu], %llu > %llu)\n", offset, new_tail, new_tail, in.length);

	Slice s;
	s.data = in.data + offset;
	s.length = length;
	return s;
}

/*
 * Convert from foreign endian to native endian
*/

static inline u16 fe_to_ne16(bool little_endian, u16 fe) {
#ifdef __LITTLE_ENDIAN__
	if (little_endian) return fe;
	return __builtin_bswap16(fe);
#elif __BIG_ENDIAN__
	if (!little_endian) return fe;
	return __builtin_bswap16(fe);
#endif
}

static inline u32 fe_to_ne32(bool little_endian, u32 fe) {
#ifdef __LITTLE_ENDIAN__
	if (little_endian) return fe;
	return __builtin_bswap32(fe);
#elif __BIG_ENDIAN__
	if (!little_endian) return fe;
	return __builtin_bswap32(fe);
#endif
}

static inline u64 fe_to_ne64(bool little_endian, u64 fe) {
#ifdef __LITTLE_ENDIAN__
	if (little_endian) return fe;
	return __builtin_bswap64(fe);
#elif __BIG_ENDIAN__
	if (!little_endian) return fe;
	return __builtin_bswap64(fe);
#endif
}

int parse_common_header(Slice binary, ELF_Context *ctx, ELF_Header *ret_hdr) {
	memset(ret_hdr, 0, sizeof(ELF_Header));

	if (ctx->bits_64) {
		ELF64_Header *hdr = (ELF64_Header *)binary.data;
		if (binary.length < sizeof(ELF64_Header)) {
			printf("File too small for ELF64 Header!\n");
			return 1;
		}

		ret_hdr->program_hdr_offset     = fe_to_ne64(ctx->little_endian, hdr->program_hdr_offset);
		ret_hdr->program_hdr_num        = fe_to_ne16(ctx->little_endian, hdr->program_hdr_num);
		ret_hdr->program_hdr_entry_size = fe_to_ne16(ctx->little_endian, hdr->program_hdr_entry_size);
		ret_hdr->section_hdr_offset     = fe_to_ne64(ctx->little_endian, hdr->section_hdr_offset);
		ret_hdr->section_hdr_str_idx    = fe_to_ne16(ctx->little_endian, hdr->section_hdr_str_idx);
		ret_hdr->section_hdr_num        = fe_to_ne16(ctx->little_endian, hdr->section_hdr_num);
		ret_hdr->section_entry_size     = fe_to_ne16(ctx->little_endian, hdr->section_entry_size);

		ctx->isa        = hdr->machine;
		ctx->file_type  = hdr->type;
		ctx->entrypoint = fe_to_ne64(ctx->little_endian, hdr->entry);
	} else {
		ELF32_Header *hdr = (ELF32_Header *)binary.data;
		if (binary.length < sizeof(ELF32_Header)) {
			printf("File too small for ELF32 Header!\n");
			return 1;
		}

		ret_hdr->program_hdr_offset     = (u64)fe_to_ne32(ctx->little_endian, hdr->program_hdr_offset);
		ret_hdr->program_hdr_num        = fe_to_ne16(ctx->little_endian, hdr->program_hdr_num);
		ret_hdr->program_hdr_entry_size = fe_to_ne16(ctx->little_endian, hdr->program_hdr_entry_size);
		ret_hdr->section_hdr_offset     = (u64)fe_to_ne32(ctx->little_endian, hdr->section_hdr_offset);
		ret_hdr->section_hdr_str_idx    = fe_to_ne16(ctx->little_endian, hdr->section_hdr_str_idx);
		ret_hdr->section_hdr_num        = fe_to_ne16(ctx->little_endian, hdr->section_hdr_num);
		ret_hdr->section_entry_size     = fe_to_ne16(ctx->little_endian, hdr->section_entry_size);

		ctx->isa        = hdr->machine;
		ctx->file_type  = hdr->type;
		ctx->entrypoint = (u64)fe_to_ne32(ctx->little_endian, hdr->entry);
	}

	return 0;
}

int parse_section_header(ELF_Context *ctx, Slice binary, ELF_Section_Header *ret_hdr) {
	memset(ret_hdr, 0, sizeof(ELF_Section_Header));

	if (ctx->bits_64) {
		ELF64_Section_Header *hdr = (ELF64_Section_Header *)binary.data;
		if (binary.length < sizeof(ELF64_Section_Header)) {
			printf("File too small for ELF64 Section Header!\n");
			return 1;
		}

		ret_hdr->name       = fe_to_ne32(ctx->little_endian, hdr->name);
		ret_hdr->type       = fe_to_ne32(ctx->little_endian, hdr->type);
		ret_hdr->flags      = fe_to_ne64(ctx->little_endian, hdr->flags);
		ret_hdr->addr       = fe_to_ne64(ctx->little_endian, hdr->addr);
		ret_hdr->offset     = fe_to_ne64(ctx->little_endian, hdr->offset);
		ret_hdr->size       = fe_to_ne64(ctx->little_endian, hdr->size);
		ret_hdr->link       = fe_to_ne32(ctx->little_endian, hdr->link);
		ret_hdr->info       = fe_to_ne32(ctx->little_endian, hdr->info);
		ret_hdr->addr_align = fe_to_ne64(ctx->little_endian, hdr->addr_align);
		ret_hdr->entry_size = fe_to_ne64(ctx->little_endian, hdr->entry_size);
	} else {
		ELF32_Section_Header *hdr = (ELF32_Section_Header *)binary.data;
		if (binary.length < sizeof(ELF32_Section_Header)) {
			printf("File too small for ELF32 Section Header!\n");
			return 1;
		}

		ret_hdr->name       = fe_to_ne32(ctx->little_endian, hdr->name);
		ret_hdr->type       = fe_to_ne32(ctx->little_endian, hdr->type);
		ret_hdr->flags      = (u64)fe_to_ne32(ctx->little_endian, hdr->flags);
		ret_hdr->addr       = (u64)fe_to_ne32(ctx->little_endian, hdr->addr);
		ret_hdr->offset     = (u64)fe_to_ne32(ctx->little_endian, hdr->offset);
		ret_hdr->size       = fe_to_ne32(ctx->little_endian, hdr->size);
		ret_hdr->link       = fe_to_ne32(ctx->little_endian, hdr->link);
		ret_hdr->info       = fe_to_ne32(ctx->little_endian, hdr->info);
		ret_hdr->addr_align = (u64)fe_to_ne32(ctx->little_endian, hdr->addr_align);
		ret_hdr->entry_size = (u64)fe_to_ne32(ctx->little_endian, hdr->entry_size);
	}

	return 0;
}

int parse_program_header(ELF_Context *ctx, Slice binary, ELF_Program_Header *ret_hdr) {
	memset(ret_hdr, 0, sizeof(ELF_Program_Header));

	if (ctx->bits_64) {
		ELF64_Program_Header *hdr = (ELF64_Program_Header *)binary.data;
		if (binary.length < sizeof(ELF64_Program_Header)) {
			printf("File too small for ELF64 Program Header!\n");
			return 1;
		}

		ret_hdr->type          = fe_to_ne32(ctx->little_endian, hdr->type);
		ret_hdr->flags         = fe_to_ne32(ctx->little_endian, hdr->flags);
		ret_hdr->offset        = fe_to_ne64(ctx->little_endian, hdr->offset);
		ret_hdr->virtual_addr  = fe_to_ne64(ctx->little_endian, hdr->virtual_addr);
		ret_hdr->physical_addr = fe_to_ne64(ctx->little_endian, hdr->physical_addr);
		ret_hdr->file_size     = fe_to_ne64(ctx->little_endian, hdr->file_size);
		ret_hdr->mem_size      = fe_to_ne64(ctx->little_endian, hdr->mem_size);
		ret_hdr->align         = fe_to_ne64(ctx->little_endian, hdr->align);
	} else {
		ELF32_Program_Header *hdr = (ELF32_Program_Header *)binary.data;
		if (binary.length < sizeof(ELF32_Section_Header)) {
			printf("File too small for ELF32 Program Header!\n");
			return 1;
		}

		ret_hdr->type          = fe_to_ne32(ctx->little_endian, hdr->type);
		ret_hdr->flags         = fe_to_ne32(ctx->little_endian, hdr->flags);
		ret_hdr->offset        = (u64)fe_to_ne32(ctx->little_endian, hdr->offset);
		ret_hdr->virtual_addr  = (u64)fe_to_ne32(ctx->little_endian, hdr->virtual_addr);
		ret_hdr->physical_addr = (u64)fe_to_ne32(ctx->little_endian, hdr->physical_addr);
		ret_hdr->file_size     = (u64)fe_to_ne32(ctx->little_endian, hdr->file_size);
		ret_hdr->mem_size      = (u64)fe_to_ne32(ctx->little_endian, hdr->mem_size);
		ret_hdr->align         = (u64)fe_to_ne32(ctx->little_endian, hdr->align);
	}

	return 0;
}

int parse_elf(uint8_t *bin, uint64_t length, ELF_Context *ctx) {
	Slice binary = into_slice(bin, length);

	ELF_PreHeader *pre_hdr = (ELF_PreHeader *)binary.data;
	if (binary.length < sizeof(ELF_PreHeader)) {
		printf("File too small for ELF Pre Header!\n");
		return 1;
	}

	u8 elf_magic[] = { 0x7f, 'E', 'L', 'F' };
	if (memcmp(pre_hdr->magic, elf_magic, 4)) {
		printf("Invalid ELF magic!\n");
		return 2;
	}

	if (pre_hdr->hdr_version != 1) {
		printf("Invalid Pre Header\n");
		return 3;
	}

	memset(ctx, 0, sizeof(ELF_Context));
	if (pre_hdr->class == ELFCLASS64) {
		ctx->bits_64 = true;
	} else if (pre_hdr->class == ELFCLASS32) {
		ctx->bits_64 = false;
	} else {
		return 4;
	}

	if (pre_hdr->endian == ELFDATA2LSB) {
		ctx->little_endian = true;
	} else if (pre_hdr->endian == ELFDATA2MSB) {
		ctx->little_endian = false;
	} else {
		return 5;
	}
	ctx->target_abi = pre_hdr->target_abi;

	ELF_Header common_hdr;
	int ret = parse_common_header(binary, ctx, &common_hdr);
	if (ret) {
		return 6;
	}

	if (common_hdr.section_hdr_offset > binary.length) {
		printf("Section header offset invalid!\n");
		return 7;
	}

	u64 str_table_hdr_offset = common_hdr.section_hdr_offset + ((u64)common_hdr.section_hdr_str_idx * (u64)common_hdr.section_entry_size);
	if (str_table_hdr_offset > binary.length) {
		printf("Invalid string table header!\n");
		return 8;
	}

	Slice str_table = sub_slice(binary, str_table_hdr_offset);
	ELF_Section_Header str_table_hdr;
	if (parse_section_header(ctx, str_table, &str_table_hdr)) {
		return 9;
	}

	if (str_table_hdr.type != sht_strtab) {
		printf("Invalid string table header section type!\n");
		return 10;
	}

	if (str_table_hdr.offset > binary.length) {
		printf("Invalid string table header offset!\n");
		return 11;
	}

	u64 section_header_array_size = common_hdr.section_hdr_num * common_hdr.section_entry_size;
	Slice section_header_blob = chunk_slice(binary, common_hdr.section_hdr_offset, section_header_array_size);

	Section *sections = (Section *)calloc(sizeof(Section), common_hdr.section_hdr_num);
	u64 sect_idx = 0;
	for (u64 i = 0; i < section_header_array_size; i += common_hdr.section_entry_size) {
		ELF_Section_Header section_hdr;
		if (parse_section_header(ctx, sub_slice(section_header_blob, i), &section_hdr)) {
			free(sections);
			return 12;
		}

		if (section_hdr.offset > binary.length) {
			printf("Section Header offset invalid!\n");
			free(sections);
			return 13;
		}

		Slice section_name_blob = sub_slice(binary, str_table_hdr.offset + section_hdr.name);

		Section *sect = &sections[sect_idx];
		sect->name = (char *)section_name_blob.data;
		sect->data = chunk_slice(binary, section_hdr.offset, section_hdr.size);
		sect_idx++;
	}

	ctx->num_sects = common_hdr.section_hdr_num;
	ctx->sections = sections;

	u64 program_header_array_size = common_hdr.program_hdr_num * common_hdr.program_hdr_entry_size;
	Slice program_header_blob = chunk_slice(binary, common_hdr.program_hdr_offset, program_header_array_size);

	ELF_Program_Header *phdrs = (ELF_Program_Header *)calloc(sizeof(ELF_Program_Header), common_hdr.program_hdr_num);
	u64 phdr_idx = 0;
	for (u64 i = 0; i < program_header_array_size; i += common_hdr.program_hdr_entry_size) {
		ELF_Program_Header program_hdr;
		if (parse_program_header(ctx, sub_slice(program_header_blob, i), &program_hdr)) {
			free(phdrs);
			free(sections);
			return 14;
		}

		if (program_hdr.offset > binary.length) {
			printf("Program Header offset invalid!\n");
			free(phdrs);
			free(sections);
			return 15;
		}

		if (program_hdr.type == pt_interp) {
			Slice linker_path = chunk_slice(binary, program_hdr.offset, program_hdr.mem_size);
			ctx->linker_path = (char *)linker_path.data;
		}

		memcpy(&phdrs[phdr_idx], &program_hdr, sizeof(program_hdr));
		phdr_idx++;
	}

	ctx->num_phdrs = common_hdr.program_hdr_num;
	ctx->phdrs = phdrs;

	return 0;
}

void free_elf_ctx(ELF_Context *ctx) {
	free(ctx->phdrs);
	free(ctx->sections);
}
