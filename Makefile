ifeq ($(origin CC), default)
	CC = gcc
endif

CFLAGS ?= -O2
OUT_O_DIR = build
LIBS = -lcjson

CSRS = dns_proxy.c
COBJ = $(addprefix $(OUT_O_DIR)/,$(CSRS:.c=.o))
DEPS = $(COBJ:.o=.d)

.PHONY: all
all: $(OUT_O_DIR)/dns-proxy

$(OUT_O_DIR)/dns-proxy: $(COBJ)
	$(CC) $^ -o $@ $(LIBS)
	
$(COBJ): $(OUT_O_DIR)/%.o : %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(DEPS): $(OUT_O_DIR)/%.d :%.c
	@mkdir -p $(@D)
	$(CC) -E $(CFLAGS) $< -MM -MT $(@:.d=.o) > $@

include $(DEPS)

