/**
 * @file util.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief Some helpful utilities.
 * @version 0.1
 * @date 2022-10-05
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "libsftp/util.h"

#include <ctype.h>
#include <pwd.h>
#include <unistd.h>
#ifdef LINUX
#include <sys/types.h>
#endif
#include "libsftp/logger.h"

char *ssh_get_local_username(void) {
    struct passwd *pw;
    uid_t uid;
    int c;

    uid = geteuid();
    pw = getpwuid(uid);
    if (pw) {
        return strdup(pw->pw_name);
    } else {
        return NULL;
    }
}

char *ssh_get_home_dir(void) {
    struct passwd *pw;
    uid_t uid;
    int c;

    uid = geteuid();
    pw = getpwuid(uid);
    if (pw) {
        return strdup(pw->pw_dir);
    } else {
        return NULL;
    }
}

void explicit_bzero(void *s, size_t n) {
#ifdef MACOS
    memset_s(s, n, '\0', n);
#endif
#ifdef LINUX
    memset(s, '\0', n);
#endif
}

/**
 * @brief Log the content of a buffer in hexadecimal format, similar to the
 * output of 'hexdump -C' command.
 *
 * The first logged line is the given description followed by the length.
 * Then the content of the buffer is logged 16 bytes per line in the following
 * format:
 *
 * (offset) (first 8 bytes) (last 8 bytes) (the 16 bytes as ASCII char values)
 *
 * The output for a 16 bytes array containing values from 0x00 to 0x0f would be:
 *
 * "Example (16 bytes):"
 * "  00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f
 * ................"
 *
 * The value for each byte as corresponding ASCII character is printed at the
 * end if the value is printable. Otherwise it is replace with '.'.
 *
 * @param[in] descr A description for the content to be logged
 * @param[in] what  The buffer to be logged
 * @param[in] len   The length of the buffer given in what
 *
 * @note If a too long description is provided (which would result in a first
 * line longer than 80 bytes), the function will fail.
 */
void ssh_log_hexdump(const char *descr, const unsigned char *what, size_t len) {
    size_t i;
    char ascii[17];
    const unsigned char *pc = NULL;
    size_t count = 0;
    ssize_t printed = 0;

    /* The required buffer size is calculated from:
     *
     *  2 bytes for spaces at the beginning
     *  8 bytes for the offset
     *  2 bytes for spaces
     * 24 bytes to print the first 8 bytes + spaces
     *  1 byte for an extra space
     * 24 bytes to print next 8 bytes + spaces
     *  2 bytes for extra spaces
     * 16 bytes for the content as ASCII characters at the end
     *  1 byte for the ending '\0'
     *
     * Resulting in 80 bytes.
     *
     * Except for the first line (description + size), all lines have fixed
     * length. If a too long description is used, the function will fail.
     * */
    char buffer[80];

    /* Print description */
    if (descr != NULL) {
        printed = snprintf(buffer, sizeof(buffer), "%s ", descr);
        if (printed < 0) {
            goto error;
        }
        count += printed;
    } else {
        printed = snprintf(buffer, sizeof(buffer), "(NULL description) ");
        if (printed < 0) {
            goto error;
        }
        count += printed;
    }

    if (len == 0) {
        printed =
            snprintf(buffer + count, sizeof(buffer) - count, "(zero length):");
        if (printed < 0) {
            goto error;
        }
        LOG_DEBUG("%s", buffer);
        return;
    } else {
        printed = snprintf(buffer + count, sizeof(buffer) - count,
                           "(%zu bytes):", len);
        if (printed < 0) {
            goto error;
        }
        count += printed;
    }

    if (what == NULL) {
        printed = snprintf(buffer + count, sizeof(buffer) - count, "(NULL)");
        if (printed < 0) {
            goto error;
        }
        LOG_DEBUG("%s", buffer);
        return;
    }

    LOG_DEBUG("%s", buffer);

    /* Reset state */
    count = 0;
    pc = what;

    for (i = 0; i < len; i++) {
        /* Add one space after printing 8 bytes */
        if ((i % 8) == 0) {
            if (i != 0) {
                printed = snprintf(buffer + count, sizeof(buffer) - count, " ");
                if (printed < 0) {
                    goto error;
                }
                count += printed;
            }
        }

        /* Log previous line and reset state for new line */
        if ((i % 16) == 0) {
            if (i != 0) {
                printed = snprintf(buffer + count, sizeof(buffer) - count,
                                   "  %s", ascii);
                if (printed < 0) {
                    goto error;
                }
                LOG_DEBUG("%s", buffer);
                count = 0;
            }

            /* Start a new line with the offset */
            printed = snprintf(buffer, sizeof(buffer), "  %08zx ", i);
            if (printed < 0) {
                goto error;
            }
            count += printed;
        }

        /* Print the current byte hexadecimal representation */
        printed =
            snprintf(buffer + count, sizeof(buffer) - count, " %02x", pc[i]);
        if (printed < 0) {
            goto error;
        }
        count += printed;

        /* If printable, store the ASCII character */
        if (isprint(pc[i])) {
            ascii[i % 16] = pc[i];
        } else {
            ascii[i % 16] = '.';
        }
        ascii[(i % 16) + 1] = '\0';
    }

    /* Add padding if not exactly 16 characters */
    while ((i % 16) != 0) {
        /* Add one space after printing 8 bytes */
        if ((i % 8) == 0) {
            if (i != 0) {
                printed = snprintf(buffer + count, sizeof(buffer) - count, " ");
                if (printed < 0) {
                    goto error;
                }
                count += printed;
            }
        }

        printed = snprintf(buffer + count, sizeof(buffer) - count, "   ");
        if (printed < 0) {
            goto error;
        }
        count += printed;
        i++;
    }

    /* Print the last printable part */
    printed = snprintf(buffer + count, sizeof(buffer) - count, "   %s", ascii);
    if (printed < 0) {
        goto error;
    }

    LOG_DEBUG("%s", buffer);

    return;

error:
    LOG_WARNING("Could not print to buffer");
    return;
}