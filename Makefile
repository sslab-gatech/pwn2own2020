all: stage0.bin
	make -C payload/loader
	make -C payload/sbx
	./make.py

stage0.bin: payload/stage0.asm
	nasm -o $@ $<

clean:
	rm -f stage0.bin payload.js
	make clean -C payload/loader
	make clean -C payload/sbx

.PHONY: all clean
