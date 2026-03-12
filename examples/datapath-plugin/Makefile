# Copyright Authors of Cilium
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

include ../../Makefile.defs

TARGET=datapath-plugin

.PHONY: all generate $(TARGET) install clean

PREFIX=/usr/local

all: image

generate:
	BPF2GO_CC="clang" BPF2GO_CFLAGS="-O2 -g -Wall -Werror -mcpu=v2" go generate ./

$(TARGET):
	$(GO_BUILD) -o $(@) .

install: $(TARGET)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	rm -f $(TARGET)
