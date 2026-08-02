#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define DEFAULT_SUMMARY_PATH "scan_exit_db_summary.txt"

static void trim_newline(char *text) {
    if (!text) {
        return;
    }

    size_t n = strlen(text);
    while (n > 0 && (text[n - 1] == '\n' || text[n - 1] == '\r')) {
        text[n - 1] = '\0';
        n--;
    }
}

static void print_pretty_row(const char *line, int row_number) {
    const char *prefix = "[scan-ui] db row: ";
    const char *body = strstr(line, prefix);
    if (!body) {
        printf("%s\n", line);
        return;
    }

    body += strlen(prefix);

    char copy[8192];
    snprintf(copy, sizeof(copy), "%s", body);
    trim_newline(copy);

    char *raw = strstr(copy, " raw=");
    if (raw) {
        *raw = '\0';
        raw += 5;
    }

    printf("Packet %d\n", row_number);
    printf("  %s\n", copy);

    if (!raw || strcmp(raw, "-") == 0 || raw[0] == '\0') {
        printf("  Raw fields: (none)\n\n");
        return;
    }

    printf("  Raw fields:\n");
    char *cursor = raw;
    while (cursor && cursor[0]) {
        char *next = strchr(cursor, '&');
        if (next) {
            *next = '\0';
            next++;
        }

        char *eq = strchr(cursor, '=');
        if (eq) {
            *eq = '\0';
            eq++;
            printf("    - %s: %s\n", cursor, eq);
        } else {
            printf("    - %s\n", cursor);
        }

        cursor = next;
    }
    printf("\n");
}

int main(int argc, char **argv) {
    int pretty = 0;
    const char *path = DEFAULT_SUMMARY_PATH;

    for (int i = 1; i < argc; ++i) {
        if (!argv[i] || !argv[i][0]) {
            continue;
        }
        if (strcmp(argv[i], "--pretty") == 0 || strcmp(argv[i], "-p") == 0) {
            pretty = 1;
            continue;
        }
        path = argv[i];
    }

    FILE *in = fopen(path, "r");
    if (!in) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return 1;
    }

    printf("Scan summary file: %s\n", path);
    printf("Mode: %s\n\n", pretty ? "pretty" : "plain");

    char line[8192];
    int line_number = 1;
    int packet_number = 1;
    while (fgets(line, sizeof(line), in)) {
        if (!pretty) {
            printf("%3d | %s", line_number, line);
        } else if (strstr(line, "[scan-ui] db row:") != NULL) {
            print_pretty_row(line, packet_number);
            packet_number++;
        } else {
            trim_newline(line);
            printf("%s\n", line);
        }
        line_number++;
    }

    if (ferror(in)) {
        fprintf(stderr, "Read error while processing %s\n", path);
        fclose(in);
        return 1;
    }

    fclose(in);

    if (line_number == 1) {
        printf("(file is empty)\n");
    }

    return 0;
}
