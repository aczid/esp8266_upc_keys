// the size of the buffer for scanning AP metadata
#define MAX_APS           512
// the number of targets cracked in parallel
#define MAX_CRACK_JOBS    64
// the max number of targets with cached passwords
#define MAX_SAVED_RESULTS 64
// the max tries to connect to the AP
#define MAX_TRIES         1
// the minimum signal quality
#define MIN_STRENGTH      -95
// how often to check for wifi APs (in seconds)
//#define SCAN_INTERVAL     5

// user flash area to store cracked AP data
#define USER_FLASH_START 0x5c000
// this (fixed) size allows for 1024 stored essids/passwords on the flash
#define USER_FLASH_SIZE  0x4000

// randomize MAC at every connection attempt
#define SPOOF_MAC

// doesn't use UART but just enables/disables the LED (probably faster too)
#define MODE_HEADLESS
// which GPIO pin goes to the LED to blink
#define LED_PIN 2
// LED state has inverted logic
#define LED_ON 0
#define LED_OFF 1

// task priorities
#define PRIO_CRACK USER_TASK_PRIO_1
#define PRIO_WIFI  USER_TASK_PRIO_2
