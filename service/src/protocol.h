/**
 * protocol.h
 *
 * Wire protocol constants for user_registration_service. See README.md
 * for the full protocol description including request/response format.
 */
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

/** TCP port the service listens on. */
#define SERVICE_PORT 4444

/** Documented upper bound for a username's length in CMD_REGISTER. */
#define MAX_NAME_LEN 64

/** Documented upper bound for the response length requested by CMD_STATUS. */
#define STATUS_MSG_CAPACITY 256

/**
 * Command byte values. Every request starts with exactly one of these
 * values, see the wire protocol in service.c / README.md.
 */
typedef enum {
    CMD_REGISTER = 1, /**< Register a user. */
    CMD_STATUS = 2,   /**< Query service status. */
} command_t;

#endif
