#include "macho.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void _Noreturn verror(const char *fmt, va_list ap) {
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	exit(2);
}

static void _Noreturn error(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	verror(fmt, ap);
}

void macho_error(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	verror(fmt, ap);
}

void open_macho(struct macho *macho, const char *path) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		error("Could not open '%s'", path);
	}
	struct stat st;
	int err = fstat(fd, &st);
	if (err != 0) {
		error("Could not stat '%s'", path);
	}
	macho->size = st.st_size;
	macho->mh = mmap(NULL, macho->size, PROT_READ, MAP_SHARED, fd, 0);
	if (macho->mh == MAP_FAILED) {
		error("Could not mmap '%s'", path);
	}
	close(fd);
}

struct gadget {
	const char *name;
	void *data;
	size_t size;
	uint64_t address;
};

static int hexdigit(int ch) {
	if ('0' <= ch && ch <= '9') {
		return ch - '0';
	} else if ('A' <= ch && ch <= 'F') {
		return ch - 'A' + 0xa;
	} else if ('a' <= ch && ch <= 'f') {
		return ch - 'a' + 0xa;
	} else {
		return -1;
	}
}

/* Gadget string format:
 *
 * 	<GADGET_STRING> = <GADGET_NAME>:<GADGET_DATA>
 * 	<GADGET_DATA> = <GADGET_BYTES>{,<GADGET_BYTES>}*
 * 	<GADGET_BYTES> = <BIG_ENDIAN_HEX>|0x<LITTLE_ENDIAN_HEX>
 * 	<GADGET_NAME> = [identifier]
 * 	<BIG_ENDIAN_HEX> = [hexadecimal;big endian]
 * 	<LITTLE_ENDIAN_HEX> = [hexadecimal;little endian]
 */

void decode_gadget(struct gadget *gadget, const char *string) {
	char *colon = strchr(string, ':');
	if (colon == NULL) {
		error("Bad format gadget string '%s'", string);
	}
	gadget->name = strndup(string, colon - string);
	string = colon + 1;
	size_t len = strlen(string);
	if (len == 0) {
		error("Missing gadget data for gadget '%s'", gadget->name);
	}
	size_t alloc_size = len / 2; // A rough guess, guaranteed to be an overestimate.
	uint8_t *data = malloc(alloc_size);
	gadget->data = data;
	const char *chr = string;
	size_t size = 0;
	for (;;) {
		bool little_endian = (strncmp(chr, "0x", 2) == 0);
		if (little_endian) {
			chr += 2;
		}
		uint8_t *start = data;
		for (;;) {
			if (*chr == 0 || *chr == ',') {
				break;
			}
			int b_hi = hexdigit(*chr++);
			if (*chr == 0 || *chr == ',') {
				error("Odd-length hex in gadget data '%s' for gadget '%s'", string, gadget->name);
			}
			int b_lo = hexdigit(*chr++);
			if (b_hi < 0 || b_lo < 0) {
				error("Invalid hex in gadget data '%s' for gadget '%s'", string, gadget->name);
			}
			*data++ = (b_hi << 4) | b_lo;
		}
		size_t length = data - start;
		if (length == 0) {
			error("Zero-length component in gadget data '%s' for gadget '%s'", string, gadget->name);
		}
		if (little_endian) {
			for (size_t i = 0; i < length / 2; i++) {
				uint8_t byte_i = start[i];
				start[i] = start[length - i - 1];
				start[length - i - 1] = byte_i;
			}
		}
		size += length;
		if (*chr == ',') {
			chr++;
		} else {
			break;
		}
	}
	gadget->size = size;
}

void find_gadgets_in_data(const void *data, uint64_t address, size_t size,
		struct gadget *gadgets, size_t count) {
	const uint8_t *ins = data;
	const uint8_t *end = ins + size;
	for (; ins < end; ins++) {
		for (size_t i = 0; i < count; i++) {
			struct gadget *g = &gadgets[i];
			// Skip this gadget if we've already found it or if there's not enough
			// space left for the gadget.
			if (g->address != 0 || (end - ins) < g->size) {
				continue;
			}
			// Skip this gadget if it's not a match.
			if (memcmp(g->data, ins, g->size) != 0) {
				continue;
			}
			// Found a gadget! Set the address.
			g->address = address + (ins - (uint8_t *)data);
		}
	}
}

void find_gadgets(const struct macho *macho, struct gadget *gadgets, size_t count) {
	const struct load_command *lc = NULL;
	for (;;) {
		lc = macho_next_segment(macho, lc);
		if (lc == NULL) {
			break;
		}
		const int prot = VM_PROT_READ | VM_PROT_EXECUTE;
		const struct segment_command_64 *sc = (const struct segment_command_64 *)lc;
		if ((sc->initprot & prot) != prot || (sc->maxprot & prot) != prot) {
			continue;
		}
		const void *data;
		uint64_t address;
		size_t size;
		macho_segment_data(macho, lc, &data, &address, &size);
		find_gadgets_in_data(data, address, size, gadgets, count);
	}
}

int main(int argc, const char *argv[]) {
	if (argc < 2 || argc > 256) {
		error("Bad argument count. Run: %s /path/to/mach-o $(cat /path/to/gadgets-file)", argv[0]);
	}
	struct macho macho;
	open_macho(&macho, argv[1]);
	size_t count = argc - 2;
	struct gadget gadgets[count];
	for (size_t i = 0; i < count; i++) {
		gadgets[i].address = 0;
		decode_gadget(&gadgets[i], argv[2 + i]);
	}
	find_gadgets(&macho, gadgets, count);
	for (size_t i = 0; i < count; i++) {
		if (gadgets[i].address == 0) {
			printf("%-32s = 0\n", gadgets[i].name);
		} else {
			printf("%-32s = 0x%llx\n", gadgets[i].name, gadgets[i].address);
		}
	}
	return 0;
}
