#ifndef ELF_H
#define ELF_H

/*
	 Copyright (c) 2022 Colin Davidson

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/

#include <stdbool.h>
#include <stdint.h>

/*
Handy References:
- https://refspecs.linuxbase.org/elf/elf.pdf
- http://man7.org/linux/man-pages/man5/elf.5.html
*/

typedef uint8_t   u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef unsigned long long u64;

typedef int8_t   i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef struct {
	u8 *data;
	u64 length;
} Slice;


// BIG NASTY ENDIAN NORMALIZATION NONSENSE
#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
#if (defined(__BYTE_ORDER__)  && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || \
     (defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN) || \
	 (defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN) || \
	 (defined(BYTE_ORDER) && BYTE_ORDER == BIG_ENDIAN)
#define __BIG_ENDIAN__
#elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || \
     (defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN) || \
	 (defined(_BYTE_ORDER) && _BYTE_ORDER == _LITTLE_ENDIAN)
#define __LITTLE_ENDIAN__
#endif
#endif

#if !defined(__LITTLE_ENDIAN__) & !defined(__BIG_ENDIAN__)
#  error "No defined endian?"
#endif

#define ELFCLASS32  1
#define ELFCLASS64  2
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

typedef enum {
	ft_none        = 0x0,
	ft_relocatable = 0x1,
	ft_executable  = 0x2,
	ft_shared_obj  = 0x3,
	ft_core        = 0x4,
	ft_lo_os       = 0xFE00,
	ft_hi_os       = 0xFEFF,
	ft_lo_proc     = 0xFF00,
	ft_hi_proc     = 0xFFFF,
} File_Type;

typedef enum {
	pt_none              = 0x000,
	pt_att_we_32100      = 0x001,
	pt_sparc             = 0x002,
	pt_x86               = 0x003,
	pt_m68k              = 0x004,
	pt_m88k              = 0x005,
	pt_imcu              = 0x006,
	pt_i80860            = 0x007,
	pt_mips              = 0x008,
	pt_system_370        = 0x009,
	pt_mips_rs3000_le    = 0x00A,
	pt_hp_pa_risc        = 0x00E,
	pt_i80960            = 0x013,
	pt_ppc               = 0x014,
	pt_ppc_64            = 0x015,
	pt_s390              = 0x016,
	pt_ibm_spu           = 0x017,
	pt_nec_v800          = 0x024,
	pt_fujitsu_fr20      = 0x025,
	pt_trw_rh32          = 0x026,
	pt_motorola_rce      = 0x027,
	pt_arm               = 0x028,
	pt_alpha             = 0x029,
	pt_super_h           = 0x02A,
	pt_sparc_v9          = 0x02B,
	pt_siemens_tricore   = 0x02C,
	pt_argonaut_risc     = 0x02D,
	pt_hitachi_h8_300    = 0x02E,
	pt_hitachi_h8_300h   = 0x02F,
	pt_hitachi_h8s       = 0x030,
	pt_hitachi_h8_500    = 0x031,
	pt_itanium           = 0x032,
	pt_stanford_mips_x   = 0x033,
	pt_motorola_coldfire = 0x034,
	pt_motorola_m68hc12  = 0x035,
	pt_fujitsu_mma       = 0x036,
	pt_siemens_pcp       = 0x037,
	pt_sony_ncpu_risc    = 0x038,
	pt_denso_ndr1        = 0x039,
	pt_motorola_starcore = 0x03A,
	pt_toyota_me16       = 0x03B,
	pt_stmicro_st100     = 0x03C,
	pt_alc_tinyj         = 0x03D,
	pt_x86_64            = 0x03E,
	pt_tms320c6000       = 0x08C,
	pt_mcst_elbrus_e2k   = 0x0AF,
	pt_arm_64            = 0x0B7,
	pt_risc_v            = 0x0F3,
	pt_bpf               = 0x0F7,
	pt_wdc_65c816        = 0x101,
} Processor_Type;

typedef enum {
	ta_system_v       = 0x00,
	ta_hp_ux          = 0x01,
	ta_netbsd         = 0x02,
	ta_linux          = 0x03,
	ta_gnu_hurd       = 0x04,
	ta_solaris        = 0x06,
	ta_aix            = 0x07,
	ta_irix           = 0x08,
	ta_freebsd        = 0x09,
	ta_tru64          = 0x0A,
	ta_novell_modesto = 0x0B,
	ta_openbsd        = 0x0C,
	ta_openvms        = 0x0D,
	ta_nonstop_kernel = 0x0E,
	ta_aros           = 0x0F,
	ta_fenix_os       = 0x10,
	ta_cloud_abi      = 0x11,
	ta_open_vos       = 0x12,
} Target_ABI;

typedef enum {
	sf_write      = 0x1,
	sf_alloc      = 0x2,
	sf_executable = 0x4,
	sf_merge      = 0x10,
	sf_strings    = 0x20,
	sf_info_link  = 0x40,
	sf_os_nonconforming = 0x100,
	sf_group      = 0x200,
	sf_tls        = 0x400,
	sf_mask_os    = 0x0FF00000,
	sf_mask_proc  = 0xF0000000,
	sf_ordered    = 0x4000000,
	sf_exclude    = 0x8000000,
} Section_Flags;

typedef enum {
	sht_null     = 0x00,
	sht_progbits = 0x01,
	sht_symtab   = 0x02,
	sht_strtab   = 0x03,
	sht_rela     = 0x04,
	sht_hash     = 0x05,
	sht_dyn      = 0x06,
	sht_note     = 0x07,
	sht_nobits   = 0x08,
	sht_rel      = 0x09,
	sht_dynsym   = 0x0B,
	sht_init_array  = 0x0E,
	sht_fini_array  = 0x0F,
	sht_gnu_hash    = 0x6FFFFFF6,
	sht_gnu_verdef  = 0x6FFFFFFD,
	sht_gnu_verneed = 0x6FFFFFFE,
	sht_gnu_versym  = 0x6FFFFFFF,
	sht_unwind      = 0x70000001,
} Section_Header_Type;

typedef enum {
	pt_null    = 0,
	pt_load    = 1,
	pt_dyn     = 2,
	pt_interp  = 3,
	pt_note    = 4,
	pt_shlib   = 5,
	pt_phdr    = 6,
	pt_tls     = 7,
	pt_gnu_eh_frame = 0x6474e550,
	pt_gnu_stack    = 0x6474e551,
	pt_gnu_relro    = 0x6474e552,
	pt_gnu_property = 0x6474e553,
	pt_lowproc      = 0x70000000,
	pt_hiproc       = 0x7FFFFFFF,
} Segment_Type;

#pragma pack(push)

typedef struct {
	u8 magic[4];
	u8 class;
	u8 endian;
	u8 hdr_version;
	u8 target_abi;
	u8 pad[8];
} ELF_PreHeader;

typedef struct {
	u8  ident[16];
	u16 type;
	u16 machine;
	u32 version;
	u32 entry;
	u32 program_hdr_offset;
	u32 section_hdr_offset;
	u32 flags;
	u16 ehsize;
	u16 program_hdr_entry_size;
	u16 program_hdr_num;
	u16 section_entry_size;
	u16 section_hdr_num;
	u16 section_hdr_str_idx;
} ELF32_Header;

typedef struct {
	u8  ident[16];
	u16 type;
	u16 machine;
	u32 version;
	u64 entry;
	u64 program_hdr_offset;
	u64 section_hdr_offset;
	u32 flags;
	u16 ehsize;
	u16 program_hdr_entry_size;
	u16 program_hdr_num;
	u16 section_entry_size;
	u16 section_hdr_num;
	u16 section_hdr_str_idx;
} ELF64_Header;

typedef struct {
	u32 name;
	u32 type;
	u32 flags;
	u32 addr;
	u32 offset;
	u32 size;
	u32 link;
	u32 info;
	u32 addr_align;
	u32 entry_size;
} ELF32_Section_Header;

typedef struct {
	u32 name;
	u32 type;
	u64 flags;
	u64 addr;
	u64 offset;
	u64 size;
	u32 link;
	u32 info;
	u64 addr_align;
	u64 entry_size;
} ELF64_Section_Header;

typedef struct {
	u32 type;
	u32 offset;
	u32 virtual_addr;
	u32 physical_addr;
	u32 file_size;
	u32 mem_size;
	u32 flags;
	u32 align;
} ELF32_Program_Header;

typedef struct {
	u32 type;
	u32 flags;
	u64 offset;
	u64 virtual_addr;
	u64 physical_addr;
	u64 file_size;
	u64 mem_size;
	u64 align;
} ELF64_Program_Header;

#pragma pack(pop)

typedef struct {
	u64 program_hdr_offset;
	u64 section_hdr_offset;
	u16 program_hdr_num;
	u16 program_hdr_entry_size;
	u16 section_entry_size;
	u16 section_hdr_num;
	u16 section_hdr_str_idx;
} ELF_Header;

typedef struct {
	u32 name;
	Section_Header_Type type;
	u64 flags;
	u64 addr;
	u64 offset;
	u64 size;
	u32 link;
	u32 info;
	u64 addr_align;
	u64 entry_size;
} ELF_Section_Header;

typedef struct {
	Segment_Type type;
	u32 flags;
	u64 offset;
	u64 virtual_addr;
	u64 physical_addr;
	u64 file_size;
	u64 mem_size;
	u64 align;
} ELF_Program_Header;

typedef struct {
	char *name;
	Slice data;
} Section;

typedef struct {
	bool           little_endian;
	bool           bits_64;
	Target_ABI     target_abi;
	File_Type      file_type;
	Processor_Type isa;
	u64            entrypoint;
	char 		  *linker_path;

	u64            num_sects;
	Section       *sections;

	u64                num_phdrs;
	ELF_Program_Header *phdrs;
} ELF_Context;

int parse_elf(uint8_t *bin, uint64_t length, ELF_Context *ctx);

#endif
