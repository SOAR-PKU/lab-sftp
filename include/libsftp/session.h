/**
 * @file session.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH session abstraction.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef SESSION_H
#define SESSION_H

#include <stdbool.h>
#include "libssh.h"
#include "socket.h"
#include "string.h"
#include "buffer.h"
#include "pki.h"
#include "crypto.h"
#include "channel.h"

struct ssh_session_struct {
    ssh_socket socket;
    char *server_id_str;
    char *client_id_str;
    int protoversion;
    int server;
    int client;
    uint32_t send_seq;
    uint32_t recv_seq;

    ssh_string banner; /* that's the issue banner from
                       the server */
    /* IO buffer */
    ssh_buffer in_buffer;
    ssh_buffer out_buffer;

    /*
     * RFC 4253, 7.1: if the first_kex_packet_follows flag was set in
     * the received SSH_MSG_KEXINIT, but the guess was wrong, this
     * field will be set such that the following guessed packet will
     * be ignored.  Once that packet has been received and ignored,
     * this field is cleared.
     */
    int first_kex_follows_guess_wrong;

    /* used by transport layer to store key exchange messages */
    ssh_buffer in_hashbuf;
    ssh_buffer out_hashbuf;
    struct ssh_crypto_struct *current_crypto; /* currently used crypto */
    struct ssh_crypto_struct *next_crypto;  /* next_crypto is going to be used after a SSH_MSG_NEWKEYS */

    /* we only support one channel per session now */
    ssh_channel channel;

    /* Some options set by user */
    struct {
        char *username;
        char *host;
        char *sshdir;
        char *knownhosts;
        char *pubkey_accepted_types;
        char *custombanner;
        unsigned int port;
    } opts;
};




#endif /* SESSION_H */