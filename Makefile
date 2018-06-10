TARGET = macho_gadgets

all: $(TARGET)

SOURCES = macho_gadgets.c macho.c

HEADERS = macho.h

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) -o $@

clean:
	rm -f -- $(TARGET)
