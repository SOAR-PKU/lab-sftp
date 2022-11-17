/**
 * @file auth.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH authentication layer functionalities.
 * @version 0.1
 * @date 2022-10-05
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "libsftp/auth.h"

#include <stdio.h>
#include <termios.h>
#include <unistd.h>

#include "libsftp/buffer.h"
#include "libsftp/error.h"
#include "libsftp/libssh.h"
#include "libsftp/logger.h"
#include "libsftp/packet.h"
#include "libsftp/session.h"

/**
 * @brief Request server for user authentication service.
 *
 * @param session
 * @return SSH_OK on success, SSH_ERR on error.
 */
int ssh_request_auth(ssh_session session) {
    int rc;
    uint8_t type;
    char *service;

    rc = ssh_buffer_pack(session->out_buffer, "bs", SSH_MSG_SERVICE_REQUEST,
                         "ssh-userauth");
    rc |= ssh_packet_send(session);
    if (rc != SSH_OK) return rc;

    rc = ssh_packet_receive(session);
    if (rc != SSH_OK) return rc;

    rc = ssh_buffer_unpack(session->in_buffer, "bs", &type, &service);
    if (rc != SSH_OK || type != SSH_MSG_SERVICE_ACCEPT ||
        strcmp(service, "ssh-userauth") != 0) {
        SAFE_FREE(service);
        return SSH_ERROR;
    }

    SAFE_FREE(service);
    return SSH_OK;
}

/**
 * @brief Get password from terminal.
 *
 * @param password
 */
void ssh_get_password(char *password) {
    static struct termios oldt, newt;
    int max_len = 100;
    int i = 0;
    uint8_t c;

    fprintf(stdout, "password: ");
    fflush(stdout);

    /*saving the old settings of STDIN_FILENO and copy settings for resetting*/
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;

    /*setting the approriate bit in the termios struct*/
    newt.c_lflag &= ~(ECHO);

    /*setting the new bits*/
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    /*reading the password from the console*/
    while ((c = getchar()) != '\n' && c != EOF && i < max_len) {
        password[i++] = c;
    }
    password[i] = '\0';

    /*resetting our old STDIN_FILENO*/
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

/**
 * @brief Send password authentication requests and wait for response.
 * Can only try up to 3 times on wrong password.
 *
 * @param session
 * @param password
 * @return SSH_OK on success, SSH_ERROR on error, SSH_AGAIN on wrong password
 */
int ssh_userauth_password(ssh_session session, const char *password) {
    int rc;
    uint8_t type;
    static int cnt = 0;

    rc = ssh_buffer_pack(session->out_buffer, "bsssbs",
                         SSH_MSG_USERAUTH_REQUEST, session->opts.username,
                         "ssh-connection", "password", 0, password);
    if (rc != SSH_OK) goto error;

    rc = ssh_packet_send(session);
    if (rc != SSH_OK) goto error;

    /**
     * RFC 4252 5.4
     * The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any
     * time after this authentication protocol starts and before
     * authentication is successful.  This message contains text to be
     * displayed to the client user before authentication is attempted.
     *
     */

    while (rc != SSH_ERROR) {
        rc = ssh_packet_receive(session);
        if (rc != SSH_OK) goto error;
        ssh_buffer_get_u8(session->in_buffer, &type);
        switch (type) {
            case SSH_MSG_USERAUTH_BANNER:
                // LAB: insert your code here.
                ssh_string msg = ssh_buffer_get_ssh_string(session->in_buffer);
                ssh_string lang = ssh_buffer_get_ssh_string(session->in_buffer);
                if (!msg || !lang)
                    goto error;
                uint32_t len = ntohl(msg->size);
                for (int i = 0; i < len; i++) {
                    char ch = msg->data[i];
                    if (ch != '\e')
                        putchar(ch);
                    else
                        printf("^[");
                }
                ssh_string_free(msg);
                ssh_string_free(lang);
                break;


            case SSH_MSG_USERAUTH_SUCCESS:
                // LAB: insert your code here.
                LOG_NOTICE("password authentication succeeded");
                return SSH_OK;

            case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
            case SSH_MSG_USERAUTH_FAILURE:
                // LAB: insert your code here.
                if (++cnt < 3) {
                    ssh_buffer_reinit(session->out_buffer);
                    ssh_buffer_reinit(session->in_buffer);
                    LOG_NOTICE("password authentication failed, please try again");
                    return SSH_AGAIN;
                }
                LOG_NOTICE("password authentication failed for 3 times");
                goto error;

            default:
                // LAB: insert your code here.
                LOG_ERROR("unknown type: %d", type);
                goto error;

        }
    }

error:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}