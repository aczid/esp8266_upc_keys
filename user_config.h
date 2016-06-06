#define MAX_APS                 512
#define MAX_CANDIDATE_PASSWORDS 32
#define MAX_TRIES               2

#define PRIO_SCAN  USER_TASK_PRIO_2
#define PRIO_CRACK USER_TASK_PRIO_0
#define PRIO_TEST  USER_TASK_PRIO_1

#define USER_FLASH_START 0x3c000
#define USER_FLASH_SIZE  0x4000

// doesn't use UART but just enables/disables the LED
// #define MODE_HEADLESS
#define LED_PIN 2

