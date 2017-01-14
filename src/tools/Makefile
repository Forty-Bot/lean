CC=gcc
RM=rm -f
CFLAGS=-pedantic -Wall -Wno-pointer-sign -Wno-pointer-arith -g -I../../include
LDFLAGS=
LDLIBS=-luuid

SRCS:=$(wildcard *.c)
OBJS:=$(SRCS:.c=.o)

all: mkfs.lean

mkfs.lean: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

depend: .depend

.depend: $(SRCS)
	$(RM) $@
	$(CC) $(CFLAGS) -MM $^ -MF $@

.PHONY: clean
clean:
	$(RM) $(OBJS) mkfs.lean

include .depend
