CC ?= gcc
RM ?= rm -f
CFLAGS += -pedantic -Wall -Wextra -Wno-pointer-sign -Wno-pointer-arith -g -I../include
LDFLAGS +=
LDLIBS += -luuid -lrt -lbsd

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)

all: mkfs.lean

mkfs.lean: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c -o $@ $<

.PHONY: clean
clean:
	$(RM) $(OBJS) $(DEPS) mkfs.lean

-include $(DEPS)
