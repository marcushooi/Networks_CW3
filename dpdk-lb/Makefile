.PHONY: build

ROOTDIR=$(shell git rev-parse --show-toplevel)
DPDK_DIR=$(ROOTDIR)/external/dpdk

dpdk:
	cd ../external/dpdk && meson --prefix $(DPDK_DIR)/install-dir -Dplatform=generic build && cd build && ninja && ninja install

build:
	make -C build

style:
	find src -name "*.c" | xargs clang-format -i -style=file
	find inc -name "*.h" | xargs clang-format -i -style=file
