#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auth.h"

int main(int argc, char **argv) {
    struct authstate state = {0};
    struct auth auth = {0};
    auth.options = DHCPCD_AUTH_REQUIRE;
    TAILQ_INIT(&auth.tokens);
    for (int n = 1; n < argc; n++) {
        unsigned char packet[8192];
        FILE *file = fopen(argv[n] + 1, "rb");
        if (!file) return 2;
        size_t length = fread(packet, 1, sizeof(packet), file);
        fclose(file);
        size_t pos = 4, authpos = 0, authlen = 0;
        while (pos + 4 <= length) {
            size_t code = packet[pos] * 256 + packet[pos+1];
            size_t len = packet[pos+2] * 256 + packet[pos+3];
            if (pos + 4 + len > length) return 3;
            if (code == 11) { authpos = pos + 4; authlen = len; }
            pos += 4 + len;
        }
        if (!authpos) return 4;
        int accepted = dhcp_auth_validate(&state, &auth, packet, length, 6,
            packet[0], packet + authpos, authlen) != NULL;
        if (accepted != (argv[n][0] == '+')) {
            fprintf(stderr, "Unexpected authentication result for case %d\n", n);
            return 5;
        }
        printf("case %d: %s as expected\n", n, accepted ? "accepted" : "rejected");
    }
    dhcp_auth_reset(&state);
    return 0;
}
