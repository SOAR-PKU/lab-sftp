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

/**
 * Name of each item in the cipher suite.
 */
const char *name_of_kex_methods[] = {
    "Key Algorithms",
    "Server Host Key Algorithms",
    "Encryption Algorithms Client to Server",
    "Encryption Algorithms Server to Client",
    "MAC Algorithms Client to Server",
    "MAC Algorithms Server to Client",
    "Compression Algorithms Client to Server",
    "Compression Algorithms Server to Client",
    "Languages Client to Server",
    "Languages Server to Client"};

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
    struct ssh_kex_struct *kex = &session->next_crypto->server_kex;

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
        strings[i] = ssh_string_to_char(str);

        if (strings[i] == NULL) {
            goto error;
        }

        kex->methods[i] = strings[i];

        if (ssh_buffer_add_ssh_string(session->in_hashbuf, str) < 0) {
            goto error;
        }

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
 * @brief Negotiate the algorithms supported by both ends.
 *
 * @param pdest Reference of dest string.
 * @param server Algorithms supported by server host.
 * @param client Algorithms supported by client host.
 * @return 0 on success, -1 on error.
 *
 * @note As mentioned in the document that our client only needs to support
 *   one specific cipher suite, there should be no comma in `client`.
 *   If comma is found in `client`, this function will return an error.
 *   Otherwise, the client string will be searched in the server string. If the
 *   string is not found, this function will return an error as well.
 */
static int select_common_algorithm(char **pdest, char *server, char *client) {
    if (server == NULL) {
        LOG_ERROR("Server string not found.");
        return -1;
    }
    if (client == NULL) {
        LOG_ERROR("Client string not found.");
        return -1;
    }

    size_t server_len = strlen(server);
    size_t client_len = strlen(client);
    int found;
    int server_algo, next_comma, algo_len;
    char *dest;

    for (int i = 0; i < client_len; ++i) {
        if (client[i] == ',') {
            LOG_ERROR("Comma found in client string.");
            return -1;
        }
    }

    if (client_len == 0) {
        dest = calloc(1, sizeof (char));
    } else {
        found = 0;

        server_algo = 0;
        while (server_algo < server_len) {
            next_comma = server_algo;
            while (next_comma < server_len && server[next_comma] != ',')
                next_comma++;

            algo_len = next_comma - server_algo;
            if (algo_len == client_len && strncmp(server + server_algo, client, algo_len) == 0) {
                found = 1;
                break;
            }

            server_algo = next_comma + (next_comma < server_len);
        }

        if (found == 1) {
            dest = calloc(client_len + 1, sizeof (char));
            strncpy(dest, client, client_len);
        } else {
            LOG_ERROR("Client string not match the server string.");
            return -1;
        }
    }

    *pdest = dest;
    return 0;
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
    char *result = &session->next_crypto->kex_methods;
    int rc;

    for (int i = 0; i < SSH_KEX_METHODS; ++i) {
        /* select negotiated algorithms and store them in `next_crypto->kex_methods` */
        // LAB: insert your code here.
        LOG_INFO("Choosing for %s", name_of_kex_methods[i]);

        rc = select_common_algorithm(&session->next_crypto->kex_methods[i],
            server->methods[i], client->methods[i]);

        if (rc < 0) {
            goto error;
        }

        LOG_INFO(" - Server End: %s", server->methods[i]);
        LOG_INFO(" - Client End: %s", client->methods[i]);
        LOG_INFO(" - Negotiated Algorithm: %s", session->next_crypto->kex_methods[i]);
    }

    session->next_crypto->kex_type = SSH_KEX_DH_GROUP14_SHA256;
    return SSH_OK;

error:
    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        SAFE_FREE(session->next_crypto->kex_methods[i]);
    }
    return SSH_ERROR;
}