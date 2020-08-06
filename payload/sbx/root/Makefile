CFLAGS := -DCURRENT_DIR=\"$(CURDIR)\"
TARGET := app/Contents/MacOS/popcalc

all: $(TARGET)

$(TARGET): main.c getroot.c
	./build-unrootless.sh
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: all clean
