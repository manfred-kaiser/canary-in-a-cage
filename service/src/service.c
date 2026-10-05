/*
 * user_registration_service.c
 *
 * TCP service with two commands:
 *   - CMD_REGISTER: registers a username
 *   - CMD_STATUS:   returns a status message of variable length
 *
 * Wire protocol (network byte order, big-endian):
 *   Byte 0:        command (uint8_t), see protocol.h
 *   CMD_REGISTER:  uint32_t name_len, followed by name_len bytes of name
 *   CMD_STATUS:    uint32_t requested_len
 *
 * A child process is forked for each incoming connection; it handles
 * exactly one command and then terminates.
 *
 * See README.md for the full build and protocol documentation.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "protocol.h"

/** Status text returned by CMD_STATUS. */
#define STATUS_TEXT "OK: service healthy"

/**
 * In-memory representation of a registered user.
 *
 * @var name        Username, see MAX_NAME_LEN for the documented upper
 *                   bound.
 * @var is_verified  Verification status; always 0 in this version, since
 *                   there is (as yet) no verification workflow.
 */
typedef struct {
    char name[MAX_NAME_LEN];
    int is_verified;
} user_profile_t;

/**
 * Reads exactly @p n bytes from @p fd into @p buf, even if that requires
 * multiple read() calls.
 *
 * @param fd   Connection descriptor.
 * @param buf  Destination buffer, must have room for at least @p n bytes.
 * @param n    Number of bytes to read.
 * @return     @p n on success, -1 if the connection was closed before all
 *             bytes were received or a read error occurred.
 */
static ssize_t read_all(int fd, void *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, (char *)buf + total, n - total);
        if (r <= 0) {
            return -1;
        }
        total += (size_t)r;
    }
    return (ssize_t)total;
}

/**
 * Handles CMD_REGISTER: reads a 4-byte length field (uint32, network
 * byte order) followed by exactly that many bytes of username, stores
 * the name in the local profile, and sends back a confirmation.
 *
 * Protocol response on success: text line "Registered user: <name>\n".
 *
 * @param client_fd  Connection descriptor of the client.
 */
static void register_user(int client_fd) {
    uint32_t name_len_net;
    if (read_all(client_fd, &name_len_net, sizeof(name_len_net)) < 0) {
        return;
    }
    uint32_t name_len = ntohl(name_len_net);

    user_profile_t profile;
    profile.is_verified = 0;

    read_all(client_fd, profile.name, name_len);

    dprintf(client_fd, "Registered user: %.*s\n", (int)name_len, profile.name);
}

/**
 * Handles CMD_STATUS: reads a 4-byte length field (uint32, network byte
 * order) that specifies how many bytes the client expects in the
 * response, and sends back that many bytes, starting with the status
 * text STATUS_TEXT.
 *
 * Per the protocol specification, the requested length must not exceed
 * STATUS_MSG_CAPACITY; larger values are capped to that value.
 *
 * @param client_fd  Connection descriptor of the client.
 */
static void handle_status(int client_fd) {
    uint32_t requested_len_net;
    if (read_all(client_fd, &requested_len_net, sizeof(requested_len_net)) < 0) {
        return;
    }
    uint32_t requested_len = ntohl(requested_len_net);

    if (requested_len > STATUS_MSG_CAPACITY) {
        requested_len = STATUS_MSG_CAPACITY;
    }

    char response[64];
    size_t text_len = strlen(STATUS_TEXT);
    memcpy(response, STATUS_TEXT, text_len);

    write(client_fd, response, requested_len);
}

/**
 * Reads the command byte of a new connection and dispatches to the
 * matching handler (register_user() or handle_status()). Unknown
 * commands are silently ignored; the caller closes the connection
 * afterwards.
 *
 * @param client_fd  Connection descriptor of the client.
 */
static void handle_client(int client_fd) {
    uint8_t cmd;
    if (read_all(client_fd, &cmd, sizeof(cmd)) < 0) {
        return;
    }
    switch (cmd) {
        case CMD_REGISTER:
            register_user(client_fd);
            break;
        case CMD_STATUS:
            handle_status(client_fd);
            break;
        default:
            break;
    }
}

/**
 * Entry point: opens the listening socket on SERVICE_PORT and accepts
 * new connections in a loop. Each connection is handled in its own
 * child process (handle_client()); the parent process immediately
 * closes its copy of the connection descriptor and waits for the next
 * connection.
 *
 * @return 1 on setup errors (bind()/listen()), otherwise runs
 *         indefinitely inside the accept() loop.
 */
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGCHLD, SIG_IGN);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(SERVICE_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(server_fd, 16) < 0) {
        perror("listen");
        return 1;
    }

    printf("user_registration_service listening on port %d\n", SERVICE_PORT);

    for (;;) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            continue;
        }

        pid_t pid = fork();
        if (pid == 0) {
            /* Child process: handle exactly one connection, then exit. */
            close(server_fd);
            handle_client(client_fd);
            close(client_fd);
            return 0;
        }
        close(client_fd);
    }

    return 0;
}
