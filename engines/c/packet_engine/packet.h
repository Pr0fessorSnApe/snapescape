#ifndef SNAPESCAPE_PACKET_H
#define SNAPESCAPE_PACKET_H

#include <stdint.h>
#include <stddef.h>

#define SNAPESCAPE_MAX_PACKET 65535

typedef struct {
    char src_ip[46];
    char dst_ip[46];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint16_t payload_len;
    uint8_t payload[SNAPESCAPE_MAX_PACKET];
} snapescape_packet_t;

/* Native TCP SYN probe — no external tools */
int snapescape_tcp_probe(const char *host, uint16_t port, int timeout_ms);

/* ICMP echo for host discovery */
int snapescape_icmp_ping(const char *host, int timeout_ms);

/* Fast checksum — assembly-optimized on x86_64 */
uint16_t snapescape_checksum(const void *data, size_t len);

#endif
