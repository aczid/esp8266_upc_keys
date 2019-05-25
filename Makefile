CC = xtensa-lx106-elf-gcc
CFLAGS = -I. -DICACHE_FLASH -mlongcalls -Os -std=c99
LDLIBS = -nostdlib -Wl,--start-group -lmain -lnet80211 -lwpa -llwip -lpp -lphy -lc -Wl,--end-group -lgcc
LDFLAGS = -Teagle.app.v6.ld #-flto 

esp8266_upc_keys-0x00000.bin: esp8266_upc_keys
	esptool.py elf2image $^

esp8266_upc_keys: esp8266_upc_keys.o driver/uart.o
esp8266_upc_keys.o: esp8266_upc_keys.c
driver/uart.o: driver/uart.c

flash: esp8266_upc_keys-0x00000.bin
	esptool.py read_flash 0x5c000 0x4000 saved_passwords.bin
	esptool.py write_flash 0 esp8266_upc_keys-0x00000.bin 0x10000 esp8266_upc_keys-0x10000.bin 0x5c000 saved_passwords.bin

get_saved_passwords:
	esptool.py read_flash 0x5c000 0x4000 saved_passwords.bin

clean:
	rm -f esp8266_upc_keys esp8266_upc_keys.o esp8266_upc_keys-0x00000.bin esp8266_upc_keys-0x40000.bin
