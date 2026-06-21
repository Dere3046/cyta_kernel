NDK_CC ?= aarch64-linux-android26-clang

all: init_wrapper

init_wrapper: wrapper.c
	$(NDK_CC) -static -Wl,-z,max-page-size=65536 -o $@ $<

clean:
	rm -f init_wrapper
