#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 8089;

    struct addrinfo hints;
    struct addrinfo *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_buf[16];
    snprintf(port_buf, sizeof(port_buf), "%d", port);

    if (getaddrinfo(host, port_buf, &hints, &result) != 0) {
        fprintf(stderr, "getaddrinfo failed for %s:%d\n", host, port);
        return 1;
    }

    int sock = -1;
    for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) {
            continue;
        }
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(sock);
        sock = -1;
    }

    if (sock < 0) {
        fprintf(stderr, "failed to connect to %s:%d\n", host, port);
        freeaddrinfo(result);
        return 1;
    }

    freeaddrinfo(result);

    const char *request =
        "GET /?PASSKEY=734F2DDA57080BEE5D968901653F7821&stationtype=AMBWeatherPro_V5.2.2&dateutc=2026-08-02%2019%3A59%3A29&ID=demo&tempf=91.2&humidity=32&windspeedmph=0.67&windgustmph=1.12&maxdailygust=6.93&winddir=132&uv=10&solarradiation=1054.03&hourlyrainin=0.000&eventrainin=0.000&dailyrainin=0.000&weeklyrainin=0.000&monthlyrainin=0.000&yearlyrainin=8.220&totalrainin=18.039&battout=1&tempinf=74.8&humidityin=51&baromrelin=29.707&baromabsin=29.500 HTTP/1.1\r\n"
        "Host: example\r\n"
        "Connection: close\r\n"
        "\r\n";

    if (send(sock, request, strlen(request), 0) < 0) {
        perror("send");
        close(sock);
        return 1;
    }

    char buffer[4096];
    ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (n > 0) {
        buffer[n] = '\0';
        printf("%s", buffer);
    }

    close(sock);
    return 0;
}
