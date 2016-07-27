#define MAX_APS           256
#define MAX_CRACK_JOBS    16
#define MAX_SAVED_RESULTS 128
#define MAX_TRIES         1
#define MIN_STRENGTH      -99

#define PRIO_WIFI  USER_TASK_PRIO_2
#define PRIO_CRACK USER_TASK_PRIO_1

#define USER_FLASH_START 0x3c000
#define USER_FLASH_SIZE  0x4000

#define SPOOF_MAC

// doesn't use UART but just enables/disables the LED (probably faster too)
#define MODE_HEADLESS
#define LED_PIN 2

