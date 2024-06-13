#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#define SNAP_LEN 1518
#define TIMEOUT 1000
#define BEACON_PORT 54321 // The port you used for broadcasting
#define ETHERTYPE_IP 0x0800
#define MAX_BEACON_FRAMES 10000 // Adjust size as needed

typedef struct {
    uint16_t seq_num;
    int64_t mac_timestamp;
} BeaconFrameInfo;



BeaconFrameInfo beacon_frames[MAX_BEACON_FRAMES];
int beacon_frame_count = 0;
void update_system_clock(int64_t offset);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void handle_beacon_frame(const u_char *packet, size_t rt_header_len);
void handle_udp_packet(const u_char *packet, size_t rt_header_len, const struct ip *ip_header);
struct ieee80211_radiotap_header {
    uint8_t it_version;     /* set to 0 */
    uint8_t it_pad;
    uint16_t it_len;        /* entire length */
    uint32_t it_present;    /* fields present */
} __attribute__((__packed__));

struct ieee80211_header {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} __attribute__((__packed__));

struct llc_header {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t ctrl;
    uint8_t org_code[3];
    uint16_t ether_type;
} __attribute__((__packed__));




int main(int argc, char *argv[]) {
    char *iface = "wlp0s20f3mon";
    char filter_exp[] = "udp dst port 54321 or type mgt subtype beacon";
     struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    system("sudo airmon-ng start wlp0s20f3");
    // Open the device for packet capturing
    handle = pcap_open_live(iface, SNAP_LEN, 1, TIMEOUT, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
        return 1;
    }

    // Set a filter to capture UDP packets on the specified port and beacon frames
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

   
    // Capture packets
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ieee80211_radiotap_header *rt_header;
    struct ieee80211_header *wifi_header;
    struct ip *ip_header;
    uint8_t subtype;
    struct VirtualClock *vc = (struct VirtualClock *)user_data;
    // Process Radiotap header
    rt_header = (struct ieee80211_radiotap_header *) packet;
    size_t rt_header_len = rt_header->it_len;

    // Process IEEE 802.11 header
    wifi_header = (struct ieee80211_header *) (packet + rt_header_len);
    subtype = (wifi_header->frame_control >> 4) & 0xF;

    if (subtype == 8) { // Beacon frame
        handle_beacon_frame(packet, rt_header_len);
    } else if (subtype == 0) { // Data frame
        struct llc_header *llc = (struct llc_header *)(packet + rt_header_len + sizeof(struct ieee80211_header));
        if (ntohs(llc->ether_type) == ETHERTYPE_IP) {
            ip_header = (struct ip *)(packet + rt_header_len + sizeof(struct ieee80211_header) + sizeof(struct llc_header));
            handle_udp_packet(packet, rt_header_len, ip_header);
        }
    }
}

void handle_beacon_frame(const u_char *packet, size_t rt_header_len) {
    struct ieee80211_header *wifi_header = (struct ieee80211_header *)(packet + rt_header_len);
    uint16_t seq_ctrl = wifi_header->seq_ctrl;
    uint16_t seq_num = (seq_ctrl >> 4) & 0xFFF;

    // MAC timestamp is at an offset of 24 bytes from the start of the IEEE 802.11 header
    int64_t mac_timestamp;
    const u_char *timestamp_ptr = packet + 16;

    // Print raw bytes for debugging
   /* printf("Raw timestamp bytes: ");
    for (int i = 0; i < sizeof(mac_timestamp); i++) {
        printf("%02x ", timestamp_ptr[i]);
    }
    printf("\n");*/

    memcpy(&mac_timestamp, timestamp_ptr, sizeof(mac_timestamp));

    // Convert the timestamp to host byte order if necessary
    mac_timestamp = le64toh(mac_timestamp);

    if (beacon_frame_count < MAX_BEACON_FRAMES) {
        beacon_frames[beacon_frame_count].seq_num = seq_num;
        beacon_frames[beacon_frame_count].mac_timestamp = mac_timestamp;
        beacon_frame_count++;
    } else {
        printf("Beacon frame buffer is full.\n");
    }

    printf("Beacon frame received with Seq Num: %u and MAC Timestamp: %" PRIu64 "\n", seq_num, mac_timestamp);
}

void handle_udp_packet(const u_char *packet, size_t rt_header_len, const struct ip *ip_header) {
    struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_header->ip_hl * 4);
    char *payload = (char *)((u_char *)udp_header + sizeof(struct udphdr));
    uint16_t udp_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);

    uint16_t seq_num;
    int64_t mac_timestamp;
    uint64_t ap_timestamp;
    sscanf(payload, "AP Timestamp: %" SCNu64 ", MAC Timestamp: %" SCNu64 ", SN: %" SCNu16,&ap_timestamp, &mac_timestamp, &seq_num);

    printf("UDP packet received with Seq Num: %u and MAC Timestamp: %" PRIu64 "\n", seq_num, mac_timestamp);

    // Open the file for appending
    FILE *file = fopen("offsets.txt", "a");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }

    // Find the matching beacon frame and calculate the offset
    for (int i = 0; i < beacon_frame_count; i++) {
        if (beacon_frames[i].seq_num == seq_num) {
            int64_t offset = beacon_frames[i].mac_timestamp -mac_timestamp;  //abs()
            printf("Offset for Seq Num %d: %" PRId64 " microseconds\n", seq_num, offset);       
            fprintf(file, "Offset for Seq Num %d: %" PRId64 " microseconds, mac_timestamp of master: %" PRIu64 ", mac_timestamp of slave: %" PRIu64 "\n", 
                seq_num, offset, mac_timestamp, beacon_frames[i].mac_timestamp);
           // update_system_clock(offset);
         
            break;
        }
    }

    // Close the file
    fclose(file);
}
   

void update_system_clock(int64_t offset){
     struct timespec ts;
    /* if(clock_gettime(CLOCK_REALTIME,&ts)!=0){
        perror("clock_gettime");
        return;
     }*/
     ts.tv_sec += offset/1000000;
     ts.tv_nsec += (offset % 1000000) * 1000;

     // Normalize the timespec structure
   while (ts.tv_nsec >= 1000000000) {
        ts.tv_sec += ts.tv_nsec / 1000000000;
        ts.tv_nsec %= 1000000000;
    }
    while (ts.tv_nsec < 0) {
        ts.tv_sec -= 1;
        ts.tv_nsec += 1000000000;
    }

       printf("Updated timespec: Seconds: %ld, Nanoseconds: %ld\n", ts.tv_sec, ts.tv_nsec);

     if(clock_settime(CLOCK_REALTIME,&ts)!=0){
        perror("clock_setttime");
        return;
     }else {
        printf("System clock updated successfully.\n");
        printf("Updated timespec: Seconds: %ld, Nanoseconds: %ld\n", ts.tv_sec, ts.tv_nsec);
       // printf("System Clock Time seconds: %ld\n", ts.tv_sec);
       // printf("System Clock Time nano seconds: %ld\n", ts.tv_nsec);
     }
}


    
