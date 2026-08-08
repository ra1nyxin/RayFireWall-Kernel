CPPFLAGS ?= -I../include
CFLAGS ?= -O2 -pipe
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow

.PHONY: all clean

all: rayfwctl

rayfwctl: rayfwctl.c ../include/uapi/rayfw.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	$(RM) rayfwctl
