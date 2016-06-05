CC = xtensa-lx106-elf-gcc
CFLAGS = -I. -mlongcalls -O3
LDLIBS = -nostdlib -Wl,--start-group -lmain -lnet80211 -lwpa -llwip -lpp -lphy -Wl,--end-group -lgcc
LDFLAGS = -Teagle.app.v6.ld

%.o: %.c
	$(CC) -Iinclude/ $(CFLAGS)  -c $< -o $@

esp8266_upc_keys-0x00000.bin: esp8266_upc_keys
	esptool.py elf2image $^

esp8266_upc_keys: esp8266_upc_keys.o driver/uart.o

esp8266_upc_keys.o: esp8266_upc_keys.c

flash: esp8266_upc_keys-0x00000.bin
	esptool.py write_flash 0 esp8266_upc_keys-0x00000.bin 0x40000 esp8266_upc_keys-0x40000.bin

clean:
	rm -f esp8266_upc_keys esp8266_upc_keys.o esp8266_upc_keys-0x00000.bin esp8266_upc_keys-0x40000.bin
