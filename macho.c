/*
 * Copyright (c) 2018 Brandon Azad
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "macho.h"

#include <assert.h>
#include <string.h>

#define MACHO_STRUCT_FIELD(macho, struct_type, object, field)		\
	(macho_is_64(macho) ? ((struct_type##_64 *)object)->field	\
	                    : ((struct_type *)object)->field)

#define MACHO_STRUCT_SIZE(macho, struct_type)				\
	(macho_is_64(macho) ? sizeof(struct_type##_64) : sizeof(struct_type))

bool
macho_is_32(const struct macho *macho) {
	return (macho->mh32->magic == MH_MAGIC);
}

bool
macho_is_64(const struct macho *macho) {
	return (macho->mh32->magic == MH_MAGIC_64);
}

size_t
macho_header_size(const struct macho *macho) {
	return MACHO_STRUCT_SIZE(macho, struct mach_header);
}

/*
 * macho_get_nlist
 */
static const void *
macho_get_nlist(const struct macho *macho, const struct symtab_command *symtab, uint32_t idx) {
	return (const void *)((uintptr_t)macho->mh + symtab->symoff
			+ idx * MACHO_STRUCT_SIZE(macho, struct nlist));
}

static size_t
guess_symbol_size(const struct macho *macho, uint64_t addr, uint64_t next) {
	size_t size = -1;
	// Limit the size to the next symbol.
	if (next != -1) {
		size = next - addr;
	}
	// See if any segment contains this address.
	const struct load_command *sc = macho_segment_containing_address(macho, addr);
	if (sc != NULL) {
		// Limit the size to the section.
		const void *sect = macho_section_containing_address(macho, sc, addr);
		if (sect != NULL) {
			uint64_t sect_addr = MACHO_STRUCT_FIELD(macho, struct section, sect, addr);
			size_t   sect_size = MACHO_STRUCT_FIELD(macho, struct section, sect, size);
			size_t sect_limited_size = sect_addr + sect_size - addr;
			if (sect_limited_size < size) {
				size = sect_limited_size;
			}
		}
		// Limit the size to the segment.
		uint64_t vmaddr = MACHO_STRUCT_FIELD(macho, struct segment_command, sc, vmaddr);
		size_t   vmsize = MACHO_STRUCT_FIELD(macho, struct segment_command, sc, vmsize);
		size_t segment_limited_size = vmaddr + vmsize - addr;
		if (segment_limited_size < size) {
			size = segment_limited_size;
		}
	}
	return (size == -1 ? 0 : size);
}

// TODO: Make this resilient to malformed images.
/*
 * macho_symtab_string
 *
 * Description:
 * 	Find the string at the given index in the symtab.
 */
static const char *
macho_symtab_string(const struct macho *macho, const struct symtab_command *symtab,
		uint32_t strx) {
	uintptr_t base = (uintptr_t)macho->mh + symtab->stroff;
	if (strx < 4 || strx >= symtab->strsize) {
		return NULL;
	}
	return (const char *)(base + strx);
}

// TODO: Make this resilient to malformed images.
/*
 * macho_symtab_string_index
 *
 * Description:
 * 	Find the index of the string in the string table.
 */
static uint32_t
macho_symtab_string_index(const struct macho *macho, const struct symtab_command *symtab,
		const char *name) {
	uintptr_t base = (uintptr_t)macho->mh + symtab->stroff;
	const char *str = (const char *)(base + 4);
	const char *end = (const char *)(base + symtab->strsize);
	uint32_t strx;
	for (;; str++) {
		strx = (uintptr_t)str - base;
		const char *p = name;
		for (;;) {
			if (str >= end) {
				return 0;
			}
			if (*p != *str) {
				while (str < end && *str != 0) {
					str++;
				}
				break;
			}
			if (*p == 0) {
				return strx;
			}
			p++;
			str++;
		}
	}
}

macho_result
macho_validate_32(const struct mach_header *mh, size_t size) {
	if (mh->magic != MH_MAGIC) {
		macho_error("32-bit Mach-O invalid magic: %x", mh->magic);
		return MACHO_ERROR;
	}
	if (size < sizeof(*mh)) {
		macho_error("32-bit Mach-O too small");
		return MACHO_ERROR;
	}
	if (mh->sizeofcmds > size) {
		macho_error("Mach-O sizeofcmds greater than file size");
		return MACHO_ERROR;
	}
	// TODO: Validate commands.
	return MACHO_SUCCESS;
}

macho_result
macho_validate_64(const struct mach_header_64 *mh, size_t size) {
	if (mh->magic != MH_MAGIC_64) {
		macho_error("64-bit Mach-O invalid magic: %x", mh->magic);
		return MACHO_ERROR;
	}
	if (size < sizeof(*mh)) {
		macho_error("64-bit Mach-O too small");
		return MACHO_ERROR;
	}
	if (mh->sizeofcmds > size) {
		macho_error("Mach-O sizeofcmds greater than file size");
		return MACHO_ERROR;
	}
	// TODO: Validate commands.
	return MACHO_SUCCESS;
}

macho_result
macho_validate(const void *mh, size_t size) {
	const struct mach_header *mh32 = mh;
	if (size < sizeof(*mh32)) {
		macho_error("Mach-O too small");
		return MACHO_ERROR;
	}
	if (mh32->magic == MH_MAGIC) {
		return macho_validate_32(mh32, size);
	} else if (mh32->magic == MH_MAGIC_64) {
		return macho_validate_64((const struct mach_header_64 *)mh, size);
	} else {
		macho_error("Mach-O invalid magic: %x", mh32->magic);
		return MACHO_ERROR;
	}
}

const struct load_command *
macho_next_load_command(const struct macho *macho, const struct load_command *lc) {
	uintptr_t lc_start = (uintptr_t)macho->mh + macho_header_size(macho);
	if (lc == NULL) {
		lc = (const struct load_command *) lc_start;
	} else {
		lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize);
	}
	size_t sizeofcmds = MACHO_STRUCT_FIELD(macho, struct mach_header, macho->mh, sizeofcmds);
	if ((uintptr_t)lc >= lc_start + sizeofcmds) {
		lc = NULL;
	}
	return lc;
}

const struct load_command *
macho_find_load_command(const struct macho *macho, const struct load_command *lc, uint32_t cmd) {
	for (;;) {
		lc = macho_next_load_command(macho, lc);
		if (lc == NULL) {
			return NULL;
		}
		if (lc->cmd == cmd) {
			return lc;
		}
	}
}

const struct load_command *
macho_next_segment(const struct macho *macho, const struct load_command *sc) {
	const uint32_t cmd = (macho_is_64(macho) ? LC_SEGMENT_64 : LC_SEGMENT);
	return macho_find_load_command(macho, sc, cmd);
}

const struct load_command *
macho_find_segment(const struct macho *macho, const char *segname) {
	const struct load_command *lc = NULL;
	for (;;) {
		lc = macho_next_segment(macho, lc);
		if (lc == NULL) {
			return NULL;
		}
		const char *lc_segname = MACHO_STRUCT_FIELD(macho, struct segment_command, lc, segname);
		if (strcmp(lc_segname, segname) != 0) {
			continue;
		}
		return lc;
	}
}

const void *
macho_find_section(const struct macho *macho, const struct load_command *segment,
		const char *sectname) {
	const size_t segment_size = MACHO_STRUCT_SIZE(macho, struct segment_command);
	const size_t section_size = MACHO_STRUCT_SIZE(macho, struct section);
	uintptr_t sect = (uintptr_t)segment + segment_size;
	size_t nsects = MACHO_STRUCT_FIELD(macho, struct segment_command, segment, nsects);
	uintptr_t end  = sect + nsects * section_size;
	for (; sect < end; sect += section_size) {
		const char *name = MACHO_STRUCT_FIELD(macho, struct section, sect, sectname);
		if (strcmp(name, sectname) == 0) {
			return (const void *)sect;
		}
	}
	return NULL;
}

void
macho_segment_data(const struct macho *macho, const struct load_command *segment,
		const void **data, uint64_t *addr, size_t *size) {
	size_t   fileoff = MACHO_STRUCT_FIELD(macho, struct segment_command, segment, fileoff);
	uint64_t vmaddr  = MACHO_STRUCT_FIELD(macho, struct segment_command, segment, vmaddr);
	size_t   vmsize  = MACHO_STRUCT_FIELD(macho, struct segment_command, segment, vmsize);
	if (data != NULL) {
		*data = (const void *)((uintptr_t)macho->mh + fileoff);
	}
	*addr = vmaddr;
	*size = vmsize;
}

void
macho_section_data(const struct macho *macho, const struct load_command *segment,
		const void *section, const void **data, uint64_t *addr, size_t *size) {
	uint64_t section_addr = MACHO_STRUCT_FIELD(macho, struct section, section, addr);
	size_t   section_size = MACHO_STRUCT_FIELD(macho, struct section, section, size);
	if (data != NULL) {
		uint64_t segment_addr = MACHO_STRUCT_FIELD(macho, struct segment_command, segment, vmaddr);
		size_t fileoff = MACHO_STRUCT_FIELD(macho, struct segment_command, segment, fileoff);
		uint64_t vmoff = section_addr - segment_addr;
		*data = (const void *)((uintptr_t)macho->mh + fileoff + vmoff);
	}
	*addr = section_addr;
	*size = section_size;
}

macho_result
macho_find_base(const struct macho *macho, uint64_t *base) {
	const struct load_command *lc = NULL;
	for (;;) {
		lc = macho_next_segment(macho, lc);
		if (lc == NULL) {
			return MACHO_NOT_FOUND;
		}
		size_t fileoff  = MACHO_STRUCT_FIELD(macho, struct segment_command, lc, fileoff);
		size_t filesize = MACHO_STRUCT_FIELD(macho, struct segment_command, lc, filesize);
		uint64_t vmaddr = MACHO_STRUCT_FIELD(macho, struct segment_command, lc, vmaddr);
		if (fileoff != 0 || filesize == 0) {
			continue;
		}
		*base = vmaddr;
		return MACHO_SUCCESS;
	}
}

void
macho_for_each_symbol(const struct macho *macho, const struct symtab_command *symtab,
		macho_for_each_symbol_fn callback, void *context) {
	bool stop = false;
	for (uint32_t i = 0; !stop && i < symtab->nsyms; i++) {
		const void *nl_i = macho_get_nlist(macho, symtab, i);
		uint32_t n_strx = MACHO_STRUCT_FIELD(macho, struct nlist, nl_i, n_un.n_strx);
		uint8_t n_type = MACHO_STRUCT_FIELD(macho, struct nlist, nl_i, n_type);
		// We can't currently handle STAB entries or non-section symbol types.
		if ((n_type & N_STAB) != 0 || (n_type & N_TYPE) != N_SECT) {
			continue;
		}
		const char *symbol = macho_symtab_string(macho, symtab, n_strx);
		if (symbol == NULL) {
			continue;
		}
		uint64_t address = MACHO_STRUCT_FIELD(macho, struct nlist, nl_i, n_value);
		stop = callback(context, symbol, address);
	}
}

/*
 * macho_next_symbol
 *
 * Description:
 * 	Returns the address of the next symbol following addr.
 */
static uint64_t
macho_next_symbol(const struct macho *macho, const struct symtab_command *symtab, uint64_t addr) {
	uint64_t next = -1;
	for (uint32_t i = 0; i < symtab->nsyms; i++) {
		const void *nl_i = macho_get_nlist(macho, symtab, i);
		uint64_t n_value = MACHO_STRUCT_FIELD(macho, struct nlist, nl_i, n_value);
		if (n_value > addr && n_value < next) {
			next = n_value;
		}
	}
	return next;
}

// TODO: Make this resilient to malformed images.
macho_result
macho_resolve_symbol(const struct macho *macho, const struct symtab_command *symtab,
		const char *symbol, uint64_t *addr, size_t *size) {
	uint32_t strx = macho_symtab_string_index(macho, symtab, symbol);
	if (strx == 0) {
		return MACHO_NOT_FOUND;
	}
	uint64_t addr0 = 0;
	uint32_t symidx = -1;
	for (uint32_t i = 0; i < symtab->nsyms; i++) {
		const void *nl_i = macho_get_nlist(macho, symtab, i);
		uint32_t n_strx = MACHO_STRUCT_FIELD(macho, struct nlist, nl_i, n_un.n_strx);
		if (n_strx == strx) {
			uint8_t n_type = MACHO_STRUCT_FIELD(macho, struct nlist, nl_i, n_type);
			if ((n_type & N_TYPE) == N_UNDF) {
				return MACHO_NOT_FOUND;
			}
			if ((n_type & N_TYPE) != N_SECT) {
				macho_error("unexpected Mach-O symbol type %x for symbol %s",
						n_type & N_TYPE, symbol);
				return MACHO_ERROR;
			}
			addr0 = MACHO_STRUCT_FIELD(macho, struct nlist, nl_i, n_value);
			symidx = i;
			break;
		}
	}
	if (symidx == -1) {
		return MACHO_NOT_FOUND;
	}
	if (addr != NULL) {
		*addr = addr0;
	}
	if (size != NULL) {
		uint64_t next = macho_next_symbol(macho, symtab, addr0);
		*size = guess_symbol_size(macho, addr0, next);
	}
	return MACHO_SUCCESS;
}

size_t
macho_guess_symbol_size(const struct macho *macho, const struct symtab_command *symtab,
		uint64_t addr) {
	uint64_t next = -1;
	if (symtab != NULL) {
		next = macho_next_symbol(macho, symtab, addr);
	}
	return guess_symbol_size(macho, addr, next);
}

macho_result
macho_resolve_address(const struct macho *macho, const struct symtab_command *symtab,
		uint64_t addr, const char **name, size_t *size, size_t *offset) {
	const void *sym = NULL;
	uint32_t symidx;
	uint64_t sym_addr;
	for (uint32_t i = 0; i < symtab->nsyms; i++) {
		const void *nl_i = macho_get_nlist(macho, symtab, i);
		uint8_t n_type = MACHO_STRUCT_FIELD(macho, struct nlist, nl_i, n_type);
		if ((n_type & N_TYPE) != N_SECT) {
			continue; // TODO: Handle other symbol types.
		}
		uint64_t n_value = MACHO_STRUCT_FIELD(macho, struct nlist, nl_i, n_value);
		if ((sym == NULL || sym_addr < n_value) && n_value <= addr) {
			sym = nl_i;
			symidx = i;
			sym_addr = n_value;
		}
	}
	if (sym == NULL) {
		return MACHO_NOT_FOUND;
	}
	uint32_t sym_sect = MACHO_STRUCT_FIELD(macho, struct nlist, sym, n_sect);
	if (sym_sect == NO_SECT) {
		macho_error("symbol index %d has no section", symidx);
		return MACHO_ERROR;
	}
	if (name != NULL) {
		uint32_t sym_strx = MACHO_STRUCT_FIELD(macho, struct nlist, sym, n_un.n_strx);
		*name = macho_symtab_string(macho, symtab, sym_strx);
	}
	if (size != NULL) {
		uint64_t next_addr = macho_next_symbol(macho, symtab, sym_addr);
		*size = guess_symbol_size(macho, sym_addr, next_addr);
	}
	if (offset != NULL) {
		*offset = addr - sym_addr;
	}
	return MACHO_SUCCESS;
}

// TODO: Make this resilient to malformed images.
macho_result
macho_search_data(const struct macho *macho, const void *data, size_t size, int minprot,
		uint64_t *addr) {
	const struct load_command *lc = NULL;
	for (;;) {
		lc = macho_next_segment(macho, lc);
		if (lc == NULL) {
			return MACHO_NOT_FOUND;
		}
		int initprot = MACHO_STRUCT_FIELD(macho, struct segment_command, lc, initprot);
		if ((initprot & minprot) != minprot) {
			continue;
		}
		size_t fileoff  = MACHO_STRUCT_FIELD(macho, struct segment_command, lc, fileoff);
		size_t filesize = MACHO_STRUCT_FIELD(macho, struct segment_command, lc, filesize);
		const void *base = (const void *)((uintptr_t)macho->mh + fileoff);
		const void *found = memmem(base, filesize, data, size);
		if (found == NULL) {
			continue;
		}
		size_t offset = (uintptr_t)found - (uintptr_t)base;
		uint64_t vmaddr = MACHO_STRUCT_FIELD(macho, struct segment_command, lc, vmaddr);
		*addr = vmaddr + offset;
		return MACHO_SUCCESS;
	}
}

const void *
macho_section_by_index(const struct macho *macho, uint32_t sect) {
	if (sect < 1) {
		return NULL;
	}
	const struct load_command *lc = NULL;
	uint32_t idx = 1;
	uintptr_t sectcmd = 0;
	for (;;) {
		lc = macho_next_segment(macho, lc);
		if (lc == NULL) {
			break;
		}
		uint32_t nsects = MACHO_STRUCT_FIELD(macho, struct segment_command, lc, nsects);
		if (sect < idx + nsects) {
			size_t lc_size = MACHO_STRUCT_SIZE(macho, struct segment_command);
			sectcmd = (uintptr_t)lc + lc_size;
			sectcmd += (sect - idx) * MACHO_STRUCT_SIZE(macho, struct section);
			break;
		}
		idx += nsects;
	}
	return (const void *)sectcmd;
}

const struct load_command *
macho_segment_containing_address(const struct macho *macho, uint64_t addr) {
	const struct load_command *lc = NULL;
	for (;;) {
		lc = macho_next_segment(macho, lc);
		if (lc == NULL) {
			return NULL;
		}
		uint64_t vmaddr = MACHO_STRUCT_FIELD(macho, struct segment_command, lc, vmaddr);
		size_t   vmsize = MACHO_STRUCT_FIELD(macho, struct segment_command, lc, vmsize);
		if (vmaddr <= addr && addr < vmaddr + vmsize) {
			return lc;
		}
	}
}

const void *
macho_section_containing_address(const struct macho *macho, const struct load_command *lc,
		uint64_t addr) {
	uint32_t nsects = MACHO_STRUCT_FIELD(macho, struct segment_command, lc, nsects);
	const size_t lc_size = MACHO_STRUCT_SIZE(macho, struct segment_command);
	const size_t sect_size = MACHO_STRUCT_SIZE(macho, struct section);
	const void *sect = (const void *)((uintptr_t)lc + lc_size);
	for (size_t i = 0; i < nsects; i++) {
		uint64_t sectaddr = MACHO_STRUCT_FIELD(macho, struct section, sect, addr);
		size_t   sectsize = MACHO_STRUCT_FIELD(macho, struct section, sect, size);
		if (sectaddr <= addr && addr < sectaddr + sectsize) {
			return sect;
		}
		sect = (const void *)((uintptr_t)sect + sect_size);
	}
	return NULL;
}
