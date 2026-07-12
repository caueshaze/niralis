POLICY := niralis
SELINUX_DEVEL ?= /usr/share/selinux/devel/Makefile
.PHONY: all clean

all: $(POLICY).pp

$(POLICY).pp: $(POLICY).te $(POLICY).fc
	$(MAKE) -f $(SELINUX_DEVEL) $@

clean:
	rm -f $(POLICY).pp $(POLICY).mod $(POLICY).tmp
