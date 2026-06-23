#include "packet.h"
#include <string.h>
#include <stdio.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2tcpip.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

uint16_t snapescape_checksum(const void *data, size_t len) {
    const uint16_t *buf = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)buf;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

int snapescape_tcp_probe(const char *host, uint16_t port, int timeout_ms) {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;
    int sock = (int)socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return -1; }
#ifndef _WIN32
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
    int r = connect(sock, res->ai_addr, (int)res->ai_addrlen);
#ifdef _WIN32
    closesocket(sock); WSACleanup();
#else
    close(sock);
#endif
    freeaddrinfo(res);
    return (r == 0 || errno == EINPROGRESS) ? 0 : -1;
}

int snapescape_icmp_ping(const char *host, int timeout_ms) {
    (void)timeout_ms;
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return -1;
    freeaddrinfo(res);
    return 0;
}

#ifdef SNAPESCAPE_BUILD_CLI
int main(int argc, char **argv) {
    if (argc < 3) { printf("Usage: %s <host> <port>\n", argv[0]); return 1; }
    int port = atoi(argv[2]);
    int r = snapescape_tcp_probe(argv[1], (uint16_t)port, 2000);
    printf(r == 0 ? "OPEN\n" : "CLOSED\n");
    return r == 0 ? 0 : 1;
}
#endif
