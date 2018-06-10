# macho_gadgets

<!-- Brandon Azad -->

macho_gadgets is a small utility to help find gadgets in a Mach-O file, specifically the iOS
kernelcache.

## Gadget descriptions

Gadgets are described using the following format:

	<gadget-name>:<gadget-data>

The `<gadget-data>` parameter specifies the binary contents of the gadget. It consists of
hexadecimal byte sequences separated by commas. If the sequence starts with `0x`, then the bytes
are flipped (so that gadgets can be specified as little-endian integers). For example, the
following definitions are equivalent:

	GADGET_1:0011223344556677
	GADGET_1:0x33221100,0x77665544

## Building

Run `make` to build `macho_gadgets`.

## Running

Run `macho_gadgets` as follows:

	$ ./macho_gadgets /path/to/mach-o <gadget-description>...

For example, to use gadgets specified in a file:

	$ ./macho_gadgets kernelcache.release.iphone9.decompressed $(cat gadgets.txt)

This will print out a list of the static addresses of the gadgets.

## License

The files `macho.h` and `macho.c` are part of memctl and are released under the MIT license. The
remaining files are placed in the public domain.


---------------------------------------------------------------------------------------------------
Brandon Azad
