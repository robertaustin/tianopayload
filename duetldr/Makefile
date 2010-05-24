LIBPAYLOAD_DIR := ../filo/build/libpayload
CC := $(LIBPAYLOAD_DIR)/bin/lpgcc
CFLAGS := -Wall -Werror -Os
TARGET := tiano
OBJS := efildr.o Efildr32.o

all: $(TARGET).elf

debug: CFLAGS += -DDEBUG
debug: all

$(TARGET).elf: $(OBJS)
	CC=i386-elf-gcc $(CC) -o $@ $(OBJS)

Efildr32.c: Efildr32
	xxd -i $< > $@

%.o: %.c
	CC=i386-elf-gcc $(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET).elf *.o Efildr32.c

