/**
 * @file session.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH session abstraciton.
 * An ssh session is a secure connection between the client and the server,
 * user authentication, channel virtualization, etc. are built on a session.
 * @version 0.1
 * @date 2022-10-05
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "libsftp/session.h"

#include <string.h>

#include "libsftp/auth.h"
#include "libsftp/dh.h"
#include "libsftp/error.h"
#include "libsftp/kex.h"
#include "libsftp/knownhosts.h"
#include "libsftp/logger.h"

/* We name the client identification string as the following in our
 * implementation */
#define CLIENT_ID_STR "SSH-2.0-minissh_0.1.0"

ssh_session ssh_new(void) {
    ssh_session session;
    int rc;

    session = calloc(1, sizeof(struct ssh_session_struct));
    if (session == NULL) {
        return NULL;
    }

    session->next_crypto = crypto_new();
    if (session->next_crypto == NULL) {
        goto err;
    }

    session->socket = ssh_socket_new();
    if (session->socket == NULL) {
        goto err;
    }

    session->out_buffer = ssh_buffer_new();
    if (session->out_buffer == NULL) {
        goto err;
    }

    session->in_buffer = ssh_buffer_new();
    if (session->in_buffer == NULL) {
        goto err;
    }

    /* OPTIONS */
    session->opts.username = ssh_get_local_username();
    session->opts.port = 22;
    session->opts.sshdir = ssh_get_home_dir();
    session->opts.knownhosts = ssh_get_known_hosts();

    return session;

err:
    ssh_free(session);
    return NULL;
}

void ssh_free(ssh_session session) {
    if (session == NULL) return;

    ssh_socket_free(session->socket);
    session->socket = NULL;

    ssh_buffer_free(session->in_buffer);
    ssh_buffer_free(session->out_buffer);

    crypto_free(session->next_crypto);
}

int ssh_options_set(ssh_session session, enum ssh_options_e type,
                    const void *value) {
    const char *v;
    char *p, *q;

    if (session == NULL) return SSH_ERROR;

    switch (type) {
        case SSH_OPTIONS_HOST:
            v = value;
            if (v == NULL || v[0] == '\0') {
                return SSH_ERROR;
            } else {
                q = strdup(value);
                if (q == NULL) {
                    return SSH_ERROR;
                }
                p = strchr(q, '@');

                SAFE_FREE(session->opts.host);

                if (p) {
                    *p = '\0';
                    session->opts.host = strdup(p + 1);
                    if (session->opts.host == NULL) {
                        SAFE_FREE(q);
                        return SSH_ERROR;
                    }

                    SAFE_FREE(session->opts.username);
                    session->opts.username = strdup(q);
                    SAFE_FREE(q);
                    if (session->opts.username == NULL) {
                        return SSH_ERROR;
                    }
                } else {
                    session->opts.host = q;
                }
            }
            break;
        case SSH_OPTIONS_PORT:
            if (value == NULL) {
                return SSH_ERROR;
            } else {
                int *x = (int *)value;
                if (*x <= 0) {
                    SSH_ERROR;
                }
                session->opts.port = *x & 0xffffU;
            }
            break;
        case SSH_OPTIONS_USER:
            v = value;
            if (v == NULL || v[0] == '\0') {
                return SSH_ERROR;
            } else { /* username provided */
                SAFE_FREE(session->opts.username);
                session->opts.username = strdup(value);
                if (session->opts.username == NULL) {
                    return SSH_ERROR;
                }
            }
            break;
        default:
            ssh_set_error(SSH_REQUEST_DENIED, "unknown option %d", type);
            return SSH_ERROR;
            break;
    }

    return SSH_OK;
}

/**
 * @brief Send client identification string.
 *
 * @param session
 * @return int
 */
int send_id_str(ssh_session session) {
    const char *id_str = CLIENT_ID_STR;
    const char *terminator = "\r\n";
    /* The maximum banner length is 255 for SSH2 */
    char buffer[256] = {0};
    size_t len;
    int rc = SSH_ERROR;

    session->client_id_str = strdup(id_str);
    snprintf(buffer, sizeof(buffer), "%s%s", session->client_id_str,
             terminator);

    rc = ssh_socket_write(session->socket, buffer, strlen(buffer));
    return rc;
}

/**
 * @brief Check if the line received is the version string.
 *
 * @param buffer
 * @param len
 * @return 1 for true, 0 for false.
 */
static int is_version_str_line(char *buffer, int len) {
    if (len < 4) return 0;
    if (buffer[0] != 'S' ||
        buffer[1] != 'S' ||
        buffer[2] != 'H' ||
        buffer[3] != '-') return 0;
    return 1;
}

/**
 * @brief Wait for server identification string and store it.
 *
 * @param session
 * @return int
 */
int receive_id_str(ssh_session session) {
    char buffer[256] = {0};
    char *ptr = buffer;

    /**
     * The server MAY send other lines of data before sending the version
     * string.  Each line SHOULD be terminated by a Carriage Return and Line
     * Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
     * in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
     * MUST be able to process such lines.  Such lines MAY be silently
     * ignored, or MAY be displayed to the client user.
     */

    /* according to RFC 4253 the max banner length is 255 */
    for (int i = 0; i < 256; ++i) {
        ssh_socket_read(session->socket, &buffer[i], 1);

        // receive new line
        if (i > 0 && buffer[i - 1] == 0x0D && buffer[i] == 0x0A) {
            int ok = is_version_str_line(buffer, i + 1);

            if (ok == 0) { // if not the version string
                // silently ignored
                // clear buffer
                while (i >= 0) buffer[i--] = 0;
            } else {
                buffer[i - 1] = 0;
                session->server_id_str = calloc(i, sizeof (char));
                strncpy(session->server_id_str, buffer, i - 1);
                return SSH_OK;
            }
        }
    }

    /* this line should not be reached */
    return SSH_ERROR;
}

/**
 * @brief Set up an SSH connection. This function performs transport layer (TCP)
 * and SSH transport layer functionalities, including TCP connection, version
 * exchange, algorithm negotiation, key exchange, and service request.
 *
 * @param session
 * @return SSH_OK on success, SSH_ERR on error.
 */
int ssh_connect(ssh_session session) {
    int rc;

    if (session == NULL) return SSH_ERROR;
    if (session->opts.host == NULL) {
        LOG_ERROR("host name required");
        goto error;
    }

    /**
     * 1. TCP Layer
     * connect to server and set up a TCP connection
     */
    rc = ssh_socket_connect(session->socket, session->opts.host,
                            session->opts.port, NULL);
    if (rc == SSH_ERROR) {
        LOG_ERROR("socket error, can not connect to server");
        goto error;
    }

    LOG_DEBUG("connected to server by fd %d", session->socket->fd);

    /**
     * 2. SSH Transport Layer
     *
     * 2.1 version exchange
     * RFC4253 section 4.2 identification string format
     * SSH-protoversion-softwareversion SP comments CR LF
     */
    rc = send_id_str(session);
    LOG_DEBUG("client id sent");
    if (rc == SSH_ERROR) {
        LOG_ERROR("can not send client id string");
        goto error;
    }

    rc = receive_id_str(session);
    if (rc == SSH_ERROR) {
        LOG_ERROR("failed to receive server id str");
        goto error;
    }

    LOG_INFO("Server ID string: %s", session->server_id_str);

    /**
     * 2.2 algorithm negotiation
     *
     */
    rc = ssh_set_client_kex(session);
    if (rc == SSH_ERROR) {
        LOG_ERROR("can not initialize client kex methods");
        goto error;
    }

    rc = ssh_send_kex(session);
    if (rc == SSH_ERROR) {
        LOG_ERROR("can not send client kex init message");
        goto error;
    }

    rc = ssh_receive_kex(session);
    if (rc == SSH_ERROR) {
        LOG_ERROR("can not receive server kex init message");
        goto error;
    }

    rc = ssh_select_kex(session);
    if (rc == SSH_ERROR) {
        LOG_ERROR("can not select an agreed cipher suite");
        goto error;
    }

    LOG_NOTICE("kex negotiation succeed");

    /**
     * 2.3 Diffie-Hellman key exchange
     *
     */
    rc = ssh_dh_handshake(session);
    if (rc == SSH_ERROR) {
        LOG_ERROR("can not perform DH handshake");
        goto error;
    }

    /**
     * 2.4 Send user authentication request
     *
     */
    rc = ssh_request_auth(session);
    if (rc == SSH_ERROR) {
        LOG_ERROR("can not request user authentication");
        goto error;
    }

    return SSH_OK;
error:
    ssh_socket_close(session->socket);
    ssh_set_error(SSH_REQUEST_DENIED, "ssh connection failed");
    return SSH_ERROR;
}