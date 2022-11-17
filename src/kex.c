/**
 * @file kex.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH transport layer key exchange functionalities.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "libsftp/kex.h"

#include "libsftp/error.h"
#include "libsftp/libcrypto.h"
#include "libsftp/libssh.h"
#include "libsftp/logger.h"
#include "libsftp/packet.h"
#include "libsftp/session.h"

/**
 * We only support one specific cipher suite,
 *
 */
const char *supported_methods[] = {
    "diffie-hellman-group14-sha256", /* key exchange */
    "ssh-rsa",                       /* public key algorithm */
    "aes256-ctr",                    /* cipher algorithm client to server */
    "aes256-ctr",                    /* cipher algorithm server to client */
    "hmac-sha1",                     /* MAC algorithm client to server */
    "hmac-sha1",                     /* MAC algorithm server to client */
    "none", /* compression algorithm client to server */
    "none", /* compression algorithm client to server */
    "",     /* languages client to server */
    ""};    /* languages server to client */

static int hashbufout_add_cookie(ssh_session session) {
    int rc;

    session->out_hashbuf = ssh_buffer_new();
    if (session->out_hashbuf == NULL) {
        return SSH_ERROR;
    }

    rc = ssh_buffer_allocate_size(session->out_hashbuf, sizeof(uint8_t) + 16);
    if (rc < 0) {
        ssh_buffer_reinit(session->out_hashbuf);
        return SSH_ERROR;
    }

    if (ssh_buffer_add_u8(session->out_hashbuf, SSH_MSG_KEXINIT) < 0) {
        ssh_buffer_reinit(session->out_hashbuf);
        return SSH_ERROR;
    }

    if (ssh_buffer_add_data(session->out_hashbuf,
                            session->next_crypto->client_kex.cookie, 16) < 0) {
        ssh_buffer_reinit(session->out_hashbuf);
        return SSH_ERROR;
    }

    return SSH_OK;
}

static int hashbufin_add_cookie(ssh_session session, unsigned char *cookie) {
    int rc;

    session->in_hashbuf = ssh_buffer_new();
    if (session->in_hashbuf == NULL) {
        return SSH_ERROR;
    }

    rc = ssh_buffer_allocate_size(session->in_hashbuf,
                                  sizeof(uint8_t) + 20 + 16);
    if (rc < 0) {
        ssh_buffer_reinit(session->in_hashbuf);
        return SSH_ERROR;
    }

    if (ssh_buffer_add_u8(session->in_hashbuf, SSH_MSG_KEXINIT) < 0) {
        ssh_buffer_reinit(session->in_hashbuf);
        return SSH_ERROR;
    }
    if (ssh_buffer_add_data(session->in_hashbuf, cookie, 16) < 0) {
        ssh_buffer_reinit(session->in_hashbuf);
        return SSH_ERROR;
    }

    return SSH_OK;
}

int ssh_set_client_kex(ssh_session session) {
    struct ssh_kex_struct *client = &session->next_crypto->client_kex;
    int rc;

    rc = ssh_get_random(client->cookie, 16, 0);
    if (!rc) {
        LOG_ERROR("PRNG error");
        return SSH_ERROR;
    }

    memset(client->methods, 0, SSH_KEX_METHODS * sizeof(char **));

    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        client->methods[i] = strdup(supported_methods[i]);
    }
    return SSH_OK;
}

/**
 * @brief Send supported cipher suites for algorithm negotiation.
 * 
 * @param session 
 * @return int 
 */
int ssh_send_kex(ssh_session session) {
    struct ssh_kex_struct *kex = &session->next_crypto->client_kex;
    ssh_string str = NULL;
    int rc;

    rc = ssh_buffer_pack(session->out_buffer, "bP", SSH_MSG_KEXINIT, 16,
                         kex->cookie);
    if (rc != SSH_OK) goto error;

    if (hashbufout_add_cookie(session) < 0) goto error;

    for (int i = 0; i < SSH_KEX_METHODS; ++i) {
        str = ssh_string_from_char(kex->methods[i]);
        if (ssh_buffer_add_ssh_string(session->out_hashbuf, str) < 0) {
            goto error;
        }
        if (ssh_buffer_add_ssh_string(session->out_buffer, str) < 0) {
            goto error;
        }
        ssh_string_free(str);
    }

    rc = ssh_buffer_pack(session->out_buffer, "bd", 0, 0);
    rc |= ssh_buffer_pack(session->out_hashbuf, "bd", 0, 0);
    if (rc != SSH_OK) goto error;

    if (ssh_packet_send(session) != SSH_OK)
        return SSH_ERROR;  // TODO: or goto error
    return SSH_OK;

error:
    ssh_buffer_reinit(session->out_buffer);
    ssh_buffer_reinit(session->out_hashbuf);
    ssh_string_free(str);
    return SSH_ERROR;
}

/**
 * @brief Wait for algorithm negotiation reply.
 * 
 * @param session 
 * @return int 
 */
int ssh_receive_kex(ssh_session session) {
    uint8_t msg_type = 0;
    ssh_string str = NULL;
    char *strings[SSH_KEX_METHODS] = {0};
    int rc = SSH_ERROR;
    bool first_kex_follows;
    uint32_t reserved;
    size_t len;

    rc = ssh_packet_receive(session);
    if (rc != SSH_OK) goto error;

    ssh_buffer_get_u8(session->in_buffer, &msg_type);
    if (msg_type != SSH_MSG_KEXINIT) {
        LOG_ERROR("wrong msg type: received %d expected %d", msg_type,
                  SSH_MSG_KEXINIT);
        goto error;
    }

    len = ssh_buffer_get_data(session->in_buffer,
                              session->next_crypto->server_kex.cookie, 16);
    if (len != 16) goto error;

    rc = hashbufin_add_cookie(session, session->next_crypto->server_kex.cookie);
    if (rc != SSH_OK) goto error;

    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        /* parse name-lists, don't forget to add `in_hashbuf` */
        // LAB: insert your code here.
        str = ssh_buffer_get_ssh_string(session->in_buffer);
        if (!str) goto error;
        rc = ssh_buffer_add_ssh_string(session->in_hashbuf,str);
        if (rc != SSH_OK) goto error;
        strings[i] = strndup(str->data, ntohl(str->size));
        ssh_string_free(str);

    }

    rc = ssh_buffer_unpack(session->in_buffer, "bd", &first_kex_follows,
                           &reserved);
    rc |=
        ssh_buffer_pack(session->in_hashbuf, "bd", first_kex_follows, reserved);
    if (rc != SSH_OK) goto error;

    if (first_kex_follows) {
        /* If server guesses Diffie Hellman Kex, this could block forever.
         * But if it guesses DH, it shouldn't set `first_kex_follows` to 1
         */
        ssh_packet_receive(session);
    }

    /* copy the server kex info into the array of strings */
    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        session->next_crypto->server_kex.methods[i] = strings[i];
    }

    return SSH_OK;

error:
    ssh_string_free(str);
    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        session->next_crypto->server_kex.methods[i] = NULL;
        SAFE_FREE(strings[i]);
    }
    return SSH_ERROR;
}

/**
 * @brief Select an agreed cipher suite based on both ends' negotiation messages.
 * 
 * @param session 
 * @return int 
 */
int ssh_select_kex(ssh_session session) {
    struct ssh_kex_struct *server = &session->next_crypto->server_kex;
    struct ssh_kex_struct *client = &session->next_crypto->client_kex;

    for (int i = 0; i < SSH_KEX_METHODS; ++i) {
        /* select negotiated algorithms and store them in `next_crypto->kex_methods` */
        // LAB: insert your code here.
        char *scli = session->next_crypto->client_kex.methods[i];
        char *sser = session->next_crypto->server_kex.methods[i];
        if (!strstr(sser, scli)) goto error;
        session->next_crypto->kex_methods[i] = strdup(scli);

    }
    session->next_crypto->kex_type = SSH_KEX_DH_GROUP14_SHA256;
    return SSH_OK;

error:
    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        SAFE_FREE(session->next_crypto->kex_methods[i]);
    }
    return SSH_ERROR;
}