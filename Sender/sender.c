#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>


pcap_t *handle; // Packet capture handle
uint64_t timestamps[2]; // Global array to store timestamps
uint16_t timestamps_SN;
uint64_t little_endian_to_decimal(const uint8_t *bytes, size_t size);
uint16_t little_endian_to_decimal_16u(const uint8_t *bytes);
void th_send_follow_up();
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


/*             for udp                       */
#define BROADCAST_IP "192.168.1.255" // Change this to match your network's broadcast address
#define DESTINATION_IP "192.168.1.2"
#define BROADCAST_PORT 54321 // Change this to match the port you want to use
#define SOURCE_PORT 12345
#define SNAP_LEN 1518
#define TIMEOUT 1000
#define PACKET_SIZE 512
#define ETHERTYPE_IP 0x0800

void build_udp_packet(uint8_t *packet, const char *src_mac, const char *dst_mac, const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, const char *data);
uint16_t checksum(uint16_t *buf, int nwords);

struct ieee80211_radiotap_header {
    uint8_t it_version;     /* set to 0 */
    uint8_t it_pad;
    uint16_t it_len;        /* entire length */
    uint32_t it_present;    /* fields present */
} __attribute((__packed__));

struct ieee80211_header {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} __attribute((__packed__));

struct llc_header {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t ctrl;
    uint8_t org_code[3];
    uint16_t ether_type;
} __attribute((__packed__));


/*                 end for udp                            */
 
int main() {
    char errbuf[PCAP_ERRBUF_SIZE]; // Error buffer
   
    struct bpf_program fp; // Compiled filter program
    char filter_exp[] = "type mgt subtype beacon"; // Filter expression for beacon frames
    bpf_u_int32 mask; // Netmask
    bpf_u_int32 net; // IP address of the network
    char device[13]="wlp0s20f3mon";
    char send_device[13] = "wlp0s20f3";
    system("sudo airmon-ng start wlp0s20f3");
    // Open the network device for packet capture
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf); // "wlp0s20f3mon" is the interface name for the monitoring mode
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    // Compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Apply the compiled filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

     
     // Create and start the thread
  /*  pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, th_send_follow_up, (u_char *)timestamps) != 0) {
        fprintf(stderr, "Failed to create thread\n");
        return 1;
    }*/
  
     // Capture packets
     
     pcap_loop(handle, 0, process_packet, (u_char *)timestamps);
     
    // Close the capture handle
    pcap_close(handle);

    return 0;
}

// Function to convert a little-endian 64-bit value to decimal
uint64_t little_endian_to_decimal(const uint8_t *bytes, size_t size) {
    uint64_t result = 0;
    for (size_t i = 0; i < size; ++i) {
        result |= (uint64_t)bytes[i] << (i * 8);
    }
    return result;
}
uint16_t little_endian_to_decimal_16u(const uint8_t *bytes) {
    // Combine the bytes into a 16-bit value
    uint16_t value = bytes[1] << 8 | bytes[0];
    // If the MSB is zero and the LSB is non-zero, consider only the LSB
    const uint16_t mask = 0x000f;
    if (!(value & mask)) 
        value = value >> 4;
    
    return value;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    uint64_t *timestamps = (uint64_t *)args;
    int len;
    len = 0;
    // Process the packet here
    printf("Packet captured!\n");
    printf("\n");

   
    // Display MAC timestamp (8 bytes)
    printf("MAC Timestamp: ");
    for (int i = 16; i <= 23; ++i) {
        printf("%02x ", packet[i]);
    }
    uint64_t mac_timestamp = little_endian_to_decimal(&packet[16], 8);
    timestamps[0] = mac_timestamp;
    printf("\nMAC Timestamp : %" PRIu64 "\n", mac_timestamp);
    printf("\n");
    

    // Display AP timestamp (8 bytes)
    printf("AP Timestamp: ");
    for (int i = 80; i <= 87; ++i) {
        printf("%02x ", packet[i]);
    }
    uint64_t ap_timestamp = little_endian_to_decimal(&packet[80], 8);
    timestamps[1] = ap_timestamp;
    printf("\nAP Timestamp : %" PRIu64 "\n", ap_timestamp);
    printf("\n");

    // Display Sequence Number (2 bytes)
    printf("Sequence Number: %02x%02x\n", packet[78], packet[79]);
    uint16_t sequence_number = little_endian_to_decimal_16u(&packet[78]);
    timestamps_SN = sequence_number;
    printf("Sequence Number : %" PRIu16 "\n", sequence_number);
    printf("\n");
    th_send_follow_up();
    // Display Beacon Frame
    while(len < header->len) {
        printf("%02x ", *(packet++));
        if(!(++len % 16))
            printf("\n");
    }
    printf("\n");

  
}

void th_send_follow_up() {
    
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t packet[PACKET_SIZE];

    const char *src_mac = "\xA0\xE7\x0B\xDF\x1D\x4A";
    const char *dst_mac = "\xff\xff\xff\xff\xff\xff";
    const char *src_ip = DESTINATION_IP;
    const char *dst_ip = BROADCAST_IP;
    uint16_t src_port = SOURCE_PORT;
    uint16_t dst_port = BROADCAST_PORT;
    char data[256];
    
  //  while (1) {
        memset(packet, 0, PACKET_SIZE);
        snprintf(data, sizeof(data), "AP Timestamp: %" PRIu64 ", MAC Timestamp: %" PRIu64 ", SN: %" PRIu16,timestamps[1], timestamps[0],timestamps_SN);
        build_udp_packet(packet, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, data);

        size_t packet_len = sizeof(struct ieee80211_radiotap_header) +
                            sizeof(struct ieee80211_header) +
                            sizeof(struct llc_header) +
                            sizeof(struct ip) +
                            sizeof(struct udphdr) +
                            strlen(data);

        if (pcap_sendpacket(handle, packet, packet_len) != 0) {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
            pcap_close(handle);
          //  return NULL;
        }

        printf("Follow-up message sent\n");
        usleep(100);
  //  }

    //pcap_close(handle);
   // pthread_exit(NULL);
}
/*                     for udp                      */
void build_udp_packet(uint8_t *packet, const char *src_mac, const char *dst_mac, const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, const char *data) {
    struct ieee80211_radiotap_header *rt_header;
    struct ieee80211_header *wifi_header;
    struct llc_header *llc;
    struct ip *ip_header;
    struct udphdr *udp_header;
    char *payload;

    // Radiotap header
    rt_header = (struct ieee80211_radiotap_header *) packet;
    rt_header->it_version = 0;
    rt_header->it_pad = 0;
    rt_header->it_len = sizeof(struct ieee80211_radiotap_header);
    rt_header->it_present = 0;

    // WiFi header
    wifi_header = (struct ieee80211_header *) (packet + sizeof(struct ieee80211_radiotap_header));
    wifi_header->frame_control = htons(0x0800); // Data frame
    wifi_header->duration = 0;
    memcpy(wifi_header->addr1, dst_mac, 6); // Destination MAC
    memcpy(wifi_header->addr2, src_mac, 6); // Source MAC
    memcpy(wifi_header->addr3, dst_mac, 6); // BSSID
    wifi_header->seq_ctrl = 0;

    // LLC header
    llc = (struct llc_header *) (packet + sizeof(struct ieee80211_radiotap_header) + sizeof(struct ieee80211_header));
    llc->dsap = 0xaa;
    llc->ssap = 0xaa;
    llc->ctrl = 0x03;
    llc->org_code[0] = 0x00;
    llc->org_code[1] = 0x00;
    llc->org_code[2] = 0x00;
    llc->ether_type = htons(ETHERTYPE_IP);

    // IP header
    ip_header = (struct ip *) (packet + sizeof(struct ieee80211_radiotap_header) + sizeof(struct ieee80211_header) + sizeof(struct llc_header));
    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + strlen(data));
    ip_header->ip_id = htons(54321);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_src.s_addr = inet_addr(src_ip);
    ip_header->ip_dst.s_addr = inet_addr(dst_ip);
    ip_header->ip_sum = 0;
    ip_header->ip_sum = checksum((uint16_t *)ip_header, sizeof(struct ip) / 2);

    // UDP header
    udp_header = (struct udphdr *) (packet + sizeof(struct ieee80211_radiotap_header) + sizeof(struct ieee80211_header) + sizeof(struct llc_header) + sizeof(struct ip));
    udp_header->uh_sport = htons(src_port);
    udp_header->uh_dport = htons(dst_port);
    udp_header->uh_ulen = htons(sizeof(struct udphdr) + strlen(data));
    udp_header->uh_sum = 0;

    // Payload
    payload = (char *) (packet + sizeof(struct ieee80211_radiotap_header) + sizeof(struct ieee80211_header) + sizeof(struct llc_header) + sizeof(struct ip) + sizeof(struct udphdr));
    strcpy(payload, data);
}

uint16_t checksum(uint16_t *buf, int nwords) {
    uint32_t sum = 0;
    for (; nwords > 0; nwords--) {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}
/*                  end for udp                         */