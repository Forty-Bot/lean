SRCDIRS = src src/tools
CLEANDIRS := $(SRCDIRS:=/clean)

all: $(SRCDIRS)

.PHONY: $(SRCDIRS)
$(SRCDIRS):
	$(MAKE) -C $@

.PHONY: clean $(CLEANDIRS)
clean: $(CLEANDIRS)

$(CLEANDIRS):
	$(MAKE) -C $(@D) clean
