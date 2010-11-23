ifdef HELLO
obj-m += hello.o
GCOV_PROFILE := y
MODPATH = $(PWD)
MODNAME = hello.ko
else
MODPATH = net/bluetooth
MODNAME = l2cap.ko
endif

VALGRIND = ~/workspace/valgrind/valgrind-3.6.0/vg-in-place
KSRC ?= $(HOME)/trees/linux.git
KCONFIG ?= kernel.config

OUTDIR = $(PWD)/kbuild

define _cflags
-D__KERNEL__ $(filter-out -pg,\
	$(shell make -n -p -C $(KSRC) O=$(OUTDIR) M=$(MODPATH) modules | \
	sed -nr 's/^(KBUILD_CFLAGS|LINUXINCLUDE) = (.*)/\2/p' | sort -u | \
	sed -r 's,(-include |-I)include,\1$(OUTDIR)/include,g'))
endef

all: test_kmod

$(MODNAME):
	mkdir -p $(OUTDIR)
	cp kernel.config $(OUTDIR)/.config
	make -C $(KSRC) O=$(OUTDIR) modules_prepare
	make -C $(KSRC) O=$(OUTDIR) M=$(MODPATH) modules
ifndef HELLO
	cp $(OUTDIR)/$(MODPATH)/$(MODNAME) $(MODNAME)
endif

test_kmod: test_kmod.o load_kmod.o stubs.o test_stub.o
	gcc --coverage -o $@ $^ -lcheck

stubs.o: stubs.c $(MODNAME) stubs.h symtable.h test_stub.h
	gcc $(_cflags) -c -o $@ $<

%.o: %.c load_kmod.h test_stub.h
	gcc -Wall -O2 -g -ffreestanding -c -o $@ $<

symtable.h: stubs.c
	echo '/* Generated by Makefile */' > $@
	echo -e '#undef DECL_FUNC\n#undef DECL_FUNC2\n#undef DECL_DATA' >> $@
	echo '#define DECL_FUNC(n) { #n, n }' >> $@
	echo '#define DECL_FUNC2(n) { #n, _ ## n }' >> $@
	echo '#define DECL_DATA(n) { #n, &n }' >> $@
	echo -e '\nstruct symbol_table symtable[] = {' >> $@
	grep '^DECL_FUNC(' $< | tr ';' ',' >> $@
	grep '^DECL_FUNC2(' $< | tr ';' ',' >> $@
	grep '^DECL_DATA(' $< | tr ';' ',' >> $@
	echo -e '{ NULL, NULL },\n};' >> $@

test_stub.h: stubs.c
	echo '/* Generated by Makefile */' > $@
	echo '#define ENABLE_STUB(fn) __ret_##fn' >> $@
	echo '#define STUB_RETURN(fn, val) if (ENABLE_STUB(fn)) return val' >> $@
	egrep '^DECL_FUNC2?\(' $< | sed -r 's/DECL_FUNC2?/extern int ENABLE_STUB/' >> $@

test_stub.c: stubs.c
	echo '/* Generated by Makefile */' > $@
	echo '#define ENABLE_STUB(fn) __ret_##fn' >> $@
	egrep '^DECL_FUNC2?\(' $< | sed -r 's/DECL_FUNC2?/int ENABLE_STUB/' >> $@

clean:
	mkdir -p $(OUTDIR)
	make -C $(KSRC) O=$(OUTDIR) M=$(MODPATH) clean
	make -C $(KSRC) O=$(OUTDIR) mrproper
	rm -f $(OUTDIR)/Makefile $(OUTDIR)/source
	find \( -name "*.gcda" -or -name "*.gcov" -or -name "*.gcno" \) -exec rm '{}' \;
	rm -f $(OUTDIR)/scripts/basic/hash
	find $(OUTDIR) -depth -type d -exec rmdir '{}' \;
	rm -f test_kmod symtable.h test_stub.[ch] *.o *.ko
	rm -rf lcov lcov.info
ifndef HELLO
	$(MAKE) HELLO=1 clean
endif

valgrind: test_kmod
	CK_FORK=no $(VALGRIND) --leak-check=full --show-reachable=yes ./test_kmod $(MODNAME)

lcov: test_kmod
	lcov --zerocounters --directory .
	./test_kmod $(MODNAME)
	lcov --capture --directory . --output-file lcov.info --test-name $(MODNAME)
	genhtml lcov.info --output-directory lcov --title "$(MODNAME) coverage" --show-details --legend --prefix $(KSRC)
