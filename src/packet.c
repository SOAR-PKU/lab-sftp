/**
 * @file packet.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH packet IO functionalities.
 * This file handles packet encryption and decryption, as well as MAC
 * verification.
 * @version 0.1
 * @date 2022-10-05
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "libsftp/packet.h"

#include "libsftp/crypto.h"
#include "libsftp/error.h"
#include "libsftp/logger.h"
#include "libsftp/session.h"
#include "libsftp/socket.h"

/**
 * RFC 4253 section 6 SSH packet format
 *
 * uint32    packet_length
 * byte      padding_length
 * byte[n1]  payload; n1 = packet_length - padding_length - 1
 * byte[n2]  random padding; n2 = padding_length
 * byte[m]   mac (Message Authentication Code - MAC); m = mac_length
 */

/**
 * @brief Encrypt a packet.
 *
 * @param session
 * @param data
 * @param len
 * @return unsigned char* computed MAC
 */
static unsigned char *packet_encrypt(ssh_session session, void *data,
                                     uint32_t len) {
    struct ssh_crypto_struct *crypto = NULL;
    struct ssh_cipher_struct *cipher = NULL;
    HMACCTX ctx = NULL;
    char *out = NULL;
    unsigned int finallen, blocksize;
    uint32_t seq, lenfield_blocksize;
    enum ssh_hmac_e type;

    crypto = ssh_get_crypto(session, SSH_DIRECTION_OUT);
    if (crypto == NULL) {
        return NULL; /* nothing to do here */
    }

    blocksize = crypto->out_cipher->blocksize;
    lenfield_blocksize = crypto->out_cipher->lenfield_blocksize;
    type = crypto->out_hmac;

    if ((len - lenfield_blocksize) % blocksize != 0) {
        ssh_set_error(SSH_FATAL,
                      "Cryptographic functions must be set"
                      " on at least one blocksize (received %d)",
                      len);
        return NULL;
    }
    out = calloc(1, len);
    if (out == NULL) {
        return NULL;
    }

    seq = ntohl(session->send_seq);
    cipher = crypto->out_cipher;

    ctx = hmac_init(crypto->encryptMAC, hmac_digest_len(type), type);
    if (ctx == NULL) {
        SAFE_FREE(out);
        return NULL;
    }

    hmac_update(ctx, (unsigned char *)&seq, sizeof(uint32_t));
    hmac_update(ctx, data, len);
    hmac_final(ctx, crypto->hmacbuf, &finallen);

    cipher->encrypt(cipher, (uint8_t *)data, out, len);
    memcpy((uint8_t *)data, out, len);

    explicit_bzero(out, len);
    SAFE_FREE(out);

    return crypto->hmacbuf;
}

/**
 * @brief Decrypt a packet.
 *
 * @param session
 * @param destination
 * @param source
 * @param start
 * @param encrypted_size
 * @return int
 */
static int packet_decrypt(ssh_session session, uint8_t *destination,
                          uint8_t *source, size_t start,
                          size_t encrypted_size) {
    struct ssh_crypto_struct *crypto = NULL;
    struct ssh_cipher_struct *cipher = NULL;

    if (encrypted_size < 0) {
        return SSH_ERROR;
    }

    crypto = ssh_get_crypto(session, SSH_DIRECTION_IN);
    if (crypto == NULL) {
        return SSH_ERROR;
    }
    cipher = crypto->in_cipher;

    if (encrypted_size % cipher->blocksize != 0) {
        LOG_ERROR(
            "Cryptographic functions must be used on multiple of "
            "blocksize %d (received %ld)",
            cipher->blocksize, encrypted_size);
        return SSH_ERROR;
    }

    cipher->decrypt(cipher, source + start, destination, encrypted_size);

    return SSH_OK;
}

/**
 * @brief Decrypt the first block of a packet to get the packet length since
 * packet length is also encrypted.
 *
 * @param session
 * @param destination
 * @param source
 * @return uint32_t
 */
static uint32_t packet_decrypt_len(ssh_session session, uint8_t *destination,
                                   uint8_t *source) {
    struct ssh_crypto_struct *crypto = NULL;
    uint32_t packet_len;
    int rc;

    crypto = ssh_get_crypto(session, SSH_DIRECTION_IN);
    if (crypto != NULL) {
        rc = packet_decrypt(session, destination, source, 0,
                            crypto->in_cipher->blocksize);
        if (rc != SSH_OK) {
            return 0;
        }
    } else {
        memcpy(destination, source, 8);
    }
    memcpy(&packet_len, destination, sizeof(packet_len));

    return ntohl(packet_len);
}

/**
 * @brief Integrity check.
 *
 * @param session
 * @param data
 * @param len
 * @param mac
 * @param type
 * @return int
 */
static int packet_hmac_verify(ssh_session session, const void *data, size_t len,
                              uint8_t *mac, enum ssh_hmac_e type) {
    struct ssh_crypto_struct *crypto = NULL;
    unsigned char hmacbuf[DIGEST_MAX_LEN] = {0};
    HMACCTX ctx;
    unsigned int hmaclen;
    uint32_t seq;

    crypto = ssh_get_crypto(session, SSH_DIRECTION_IN);
    if (crypto == NULL) {
        return SSH_ERROR;
    }

    ctx = hmac_init(crypto->decryptMAC, hmac_digest_len(type), type);
    if (ctx == NULL) {
        return SSH_ERROR;
    }

    seq = htonl(session->recv_seq);

    hmac_update(ctx, (unsigned char *)&seq, sizeof(uint32_t));
    hmac_update(ctx, data, len);
    hmac_final(ctx, hmacbuf, &hmaclen);

    // ssh_log_hexdump("received mac", mac, hmaclen);
    // ssh_log_hexdump("Computed mac", hmacbuf, hmaclen);
    // ssh_log_hexdump("seq", (unsigned char *)&seq, sizeof(uint32_t));

    if (memcmp(mac, hmacbuf, hmaclen) == 0) {
        return SSH_OK;
    }

    return SSH_ERROR;
}

/**
 * @brief Read a binary packet from socket and decrypt it if key exchange is
 * completed. Extract the SSH message packet and store it in the session's
 * in_buffer
 * @param session
 * @return success or not
 */
int ssh_packet_receive(ssh_session session) {
    uint8_t *data = NULL;
    uint32_t blocksize = 8;
    uint32_t lenfield_blocksize = 8;
    size_t current_macsize = 0;
    uint8_t *ptr = NULL;
    int to_be_read;
    int rc;
    uint8_t *cleartext_packet = NULL;
    uint8_t *packet_second_block = NULL;
    uint8_t *mac = NULL;
    size_t packet_remaining;
    uint32_t packet_len;
    uint8_t padding;
    size_t processed = 0; /* number of byte processed from the callback */
    struct ssh_crypto_struct *crypto = NULL;
    bool ok;

    crypto = ssh_get_crypto(session, SSH_DIRECTION_IN);
    if (crypto != NULL) {
        current_macsize = hmac_digest_len(crypto->in_hmac);
        blocksize = crypto->in_cipher->blocksize;
        lenfield_blocksize = crypto->in_cipher->lenfield_blocksize;
    }

    if (lenfield_blocksize == 0) {
        lenfield_blocksize = blocksize;
    }

    data = calloc(lenfield_blocksize, sizeof(uint8_t));

    ssh_socket_read(session->socket, data, lenfield_blocksize);

    if (session->in_buffer) {
        rc = ssh_buffer_reinit(session->in_buffer);
        if (rc < 0) {
            goto error;
        }
    } else {
        session->in_buffer = ssh_buffer_new();
        if (session->in_buffer == NULL) {
            goto error;
        }
    }

    ptr = ssh_buffer_allocate(session->in_buffer, lenfield_blocksize);
    if (ptr == NULL) {
        goto error;
    }
    packet_len = packet_decrypt_len(session, ptr, data);
    to_be_read =
        packet_len - lenfield_blocksize + sizeof(uint32_t) + current_macsize;

    data = realloc(data, to_be_read * sizeof(uint8_t) + 1);
    ssh_socket_read(session->socket, data, to_be_read);

    ptr = ssh_buffer_allocate(session->in_buffer, to_be_read - current_macsize);
    if (ptr == NULL) goto error;

    if (crypto != NULL) {
        mac = data + to_be_read - current_macsize;
        rc =
            packet_decrypt(session, ptr, data, 0, to_be_read - current_macsize);
        if (rc != SSH_OK) {
            ssh_set_error(SSH_FATAL, "decryption error");
            goto error;
        }
        /* verify MAC, see `packet_hmac_verify` */
        // LAB: insert your code here. (finished)
        rc = packet_hmac_verify(session, ssh_buffer_get(session->in_buffer),
                             packet_len + sizeof(uint32_t), mac, crypto->in_hmac);

        if (rc != SSH_OK) {
            ssh_set_error(SSH_FATAL, "hmac error");
            goto error;
        }
    } else {
        memcpy(ptr, data, to_be_read - current_macsize);
    }

    SAFE_FREE(data);
    /* decryption completed */
    /* now decrypted packet is in in_buffer, extract payload and discard others
     */

    /* skip the size field which has been processed before */
    ssh_buffer_pass_bytes(session->in_buffer, sizeof(uint32_t));

    rc = ssh_buffer_get_u8(session->in_buffer, &padding);

    /* There MUST be at least four bytes of padding.  The
     padding SHOULD consist of random bytes.  The maximum amount of
     padding is 255 bytes. */
    if (padding < 4 || padding > 255 ||
        padding > ssh_buffer_get_len(session->in_buffer)) {
        ssh_set_error(SSH_FATAL, "Invalid padding: %d (%d left)", padding,
                      ssh_buffer_get_len(session->in_buffer));
        goto error;
    }
    ssh_buffer_pass_bytes_end(session->in_buffer, padding);

    session->recv_seq++;

    LOG_DEBUG(
        "packet: received [type=%u, len=%u, padding_size=%hhd,"
        "payload=%u]",
        ((uint8_t *)ssh_buffer_get(session->in_buffer))[0], packet_len, padding,
        ssh_buffer_get_len(session->in_buffer));

    return SSH_OK;

error:
    SAFE_FREE(data);
    LOG_ERROR("packet receive error");
    return SSH_ERROR;
}

/**
 * @brief Encapsulate a binary packet from payload and encrypt it if key
 * exchange is completed. Send the encrypted packet to the socket.
 *
 * @param session
 * @return int
 */
int ssh_packet_send(ssh_session session) {
    unsigned int blocksize = 8;
    unsigned int lenfield_blocksize = 0;
    enum ssh_hmac_e hmac_type = SSH_HMAC_NONE;
    struct ssh_crypto_struct *crypto = NULL;
    unsigned char *hmac = NULL;
    uint8_t padding_data[32] = {0};
    uint8_t padding_size;
    uint32_t finallen, payload_size;
    uint8_t header[5] = {0};
    uint8_t type, *payload;
    int rc;

    crypto = ssh_get_crypto(session, SSH_DIRECTION_OUT);
    if (crypto) {
        blocksize = crypto->out_cipher->blocksize;
        lenfield_blocksize = crypto->out_cipher->lenfield_blocksize;
        hmac_type = crypto->out_hmac;
    }

    payload_size = ssh_buffer_get_len(session->out_buffer);
    if (payload_size < 1) {
        return SSH_ERROR;
    }

    payload = (uint8_t *)ssh_buffer_get(session->out_buffer);
    type = payload[0]; /* type is the first byte of the packet now */

    padding_size =
        (blocksize -
         ((blocksize - lenfield_blocksize + payload_size + 5) % blocksize));
    if (padding_size < 4) {
        /* why? */
        padding_size += blocksize;
    }

    if (crypto != NULL) {
        if (!ssh_get_random(padding_data, padding_size, 0)) {
            ssh_set_error(SSH_FATAL, "PRNG error");
            return SSH_ERROR;
        }
    }

    finallen = payload_size + padding_size + 1;

    *((uint32_t *)&header[0]) = htonl(finallen);
    header[4] = padding_size;

    rc = ssh_buffer_prepend_data(session->out_buffer, header, sizeof(header));
    if (rc < 0) return SSH_ERROR;
    rc = ssh_buffer_add_data(session->out_buffer, padding_data, padding_size);
    if (rc < 0) return SSH_ERROR;

    hmac = packet_encrypt(session, ssh_buffer_get(session->out_buffer),
                          ssh_buffer_get_len(session->out_buffer));
    if (hmac != NULL) {
        rc = ssh_buffer_add_data(session->out_buffer, hmac,
                                 hmac_digest_len(hmac_type));
        if (rc < 0) return SSH_ERROR;
    }

    rc = ssh_socket_write(session->socket, ssh_buffer_get(session->out_buffer),
                          ssh_buffer_get_len(session->out_buffer));
    if (rc < 0) return SSH_ERROR;

    session->send_seq++;

    LOG_DEBUG(
        "packet: wrote [type=%u, len=%u, padding_size=%hhd,"
        "payload=%u]",
        type, finallen, padding_size, payload_size);

    /* be ready for next packet */
    rc = ssh_buffer_reinit(session->out_buffer);
    if (rc < 0) {
        ssh_set_error(SSH_FATAL, "buffer error");
        return SSH_ERROR;
    }

    return SSH_OK;
}