CC      ?= gcc
CFLAGS  ?= -m32 -O0 -fno-stack-protector -fno-omit-frame-pointer -fno-pie -U_FORTIFY_SOURCE
TASK    ?= 1

ifeq ($(TASK),2)
LDFLAGS ?= -m32 -no-pie -z execstack
else
LDFLAGS ?= -m32 -no-pie -z noexecstack
endif

BIN := overflow

all: $(BIN)

$(BIN): overflow.c
	$(CC) $(CFLAGS) overflow.c -o $@ $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean
