/**
 * @file dh.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief Diffie-Hellman key exchange functionalities.
 * @version 0.1
 * @date 2022-10-06
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "libsftp/dh.h"

#include "libsftp/bignum.h"
#include "libsftp/buffer.h"
#include "libsftp/crypto.h"
#include "libsftp/logger.h"
#include "libsftp/packet.h"
#include "libsftp/pki.h"
#include "libsftp/session.h"
#include "libsftp/util.h"

/*
 * How many bits of security we want for fast DH. DH private key size must be
 * twice that size.
 */
#define DH_SECURITY_BITS 512

struct dh_keypair {
    bignum priv_key;
    bignum pub_key;
};

struct dh_ctx {
    /* 0 is client, 1 is server */
    struct dh_keypair keypair[2];
    bignum generator;
    bignum modulus;
};

static bignum ssh_dh_generator;
static bignum ssh_dh_group14;

static unsigned char p_group14_value[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
    0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
    0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF};

#define P_GROUP14_LEN 256 /* Size in bytes of the p number for group 14 */

static int dh_keypair_gen_keys(struct dh_ctx *ctx, int peer);
static int dh_keypair_get_keys(struct dh_ctx *ctx, int peer, const_bignum *priv,
                               const_bignum *pub);
static int dh_keypair_set_keys(struct dh_ctx *ctx, int peer, bignum priv,
                               bignum pub);
static int dh_set_parameters(struct dh_ctx *ctx, bignum modulus,
                             bignum generator);
static int dh_get_parameters(struct dh_ctx *ctx, const_bignum *modulus,
                             const_bignum *generator);
static void dh_free_modulus(struct dh_ctx *ctx);
static void dh_free_generator(struct dh_ctx *ctx);
static int dh_init_keypair(struct dh_keypair *keypair);
static void dh_free_keypair(struct dh_keypair *keypair);

static void ssh_dh_debug_crypto(struct ssh_crypto_struct *c) {
#ifdef DEBUG_CRYPTO
    const_bignum x = NULL, y = NULL, e = NULL, f = NULL;

    ssh_dh_keypair_get_keys(c->dh_ctx, DH_CLIENT_KEYPAIR, &x, &e);
    ssh_dh_keypair_get_keys(c->dh_ctx, DH_SERVER_KEYPAIR, &y, &f);
    ssh_print_bignum("p", c->dh_ctx->modulus);
    ssh_print_bignum("g", c->dh_ctx->generator);
    ssh_print_bignum("x", x);
    ssh_print_bignum("y", y);
    ssh_print_bignum("e", e);
    ssh_print_bignum("f", f);

    ssh_log_hexdump("Session server cookie", c->server_kex.cookie, 16);
    ssh_log_hexdump("Session client cookie", c->client_kex.cookie, 16);
    ssh_print_bignum("k", c->shared_secret);
#else
    (void)c; /* UNUSED_PARAM */
#endif
}

static int dh_init(ssh_session session) {
    struct ssh_crypto_struct *crypto = session->next_crypto;
    const_bignum pubkey;
    struct dh_ctx *ctx = NULL;
    int rc;

    ssh_dh_generator = bignum_new();
    rc = bignum_set_word(ssh_dh_generator, 2);
    if (rc != 1) return SSH_ERROR;

    bignum_bin2bn(p_group14_value, P_GROUP14_LEN, &ssh_dh_group14);
    if (ssh_dh_group14 == NULL) return SSH_ERROR;

    /* DH context initialization */
    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) return SSH_ERROR;

    rc = dh_set_parameters(ctx, ssh_dh_group14, ssh_dh_generator);
    crypto->dh_ctx = ctx;
    if (rc != SSH_OK) {
        dh_cleanup(crypto);
        return SSH_ERROR;
    }

    return SSH_OK;
}

static int dh_set_parameters(struct dh_ctx *ctx, bignum modulus,
                             bignum generator) {
    int rc;

    if ((ctx == NULL) || ((modulus == NULL) && (generator == NULL))) {
        return SSH_ERROR;
    }

    rc = dh_init_keypair(&ctx->keypair[DH_CLIENT_KEYPAIR]);
    if (rc != SSH_OK) {
        return SSH_ERROR;
    }
    rc = dh_init_keypair(&ctx->keypair[DH_SERVER_KEYPAIR]);
    if (rc != SSH_OK) {
        return SSH_ERROR;
    }

    if (modulus) {
        dh_free_modulus(ctx);
        ctx->modulus = modulus;
    }
    if (generator) {
        dh_free_generator(ctx);
        ctx->generator = generator;
    }

    return SSH_OK;
}

static int dh_get_parameters(struct dh_ctx *ctx, const_bignum *modulus,
                             const_bignum *generator) {
    if (ctx == NULL) {
        return SSH_ERROR;
    }
    if (modulus) {
        *modulus = ctx->modulus;
    }
    if (generator) {
        *generator = ctx->generator;
    }

    return SSH_OK;
}

void dh_cleanup(struct ssh_crypto_struct *crypto) {
    struct dh_ctx *ctx = crypto->dh_ctx;

    if (ctx == NULL) {
        return;
    }

    dh_free_keypair(&ctx->keypair[DH_CLIENT_KEYPAIR]);
    dh_free_keypair(&ctx->keypair[DH_SERVER_KEYPAIR]);

    dh_free_modulus(ctx);
    dh_free_generator(ctx);
    SAFE_FREE(ctx);
    crypto->dh_ctx = NULL;

    bignum_safe_free(ssh_dh_generator);
    bignum_safe_free(ssh_dh_group14);
}

static int dh_keypair_gen_keys(struct dh_ctx *dh_ctx, int peer) {
    bignum tmp = NULL;
    bignum_CTX ctx = NULL;
    int rc = 0;
    int bits = 0;
    int p_bits = 0;

    ctx = bignum_ctx_new();
    if (bignum_ctx_invalid(ctx)) {
        goto error;
    }
    tmp = bignum_new();
    if (tmp == NULL) {
        goto error;
    }
    p_bits = bignum_num_bits(dh_ctx->modulus);
    /* we need at most DH_SECURITY_BITS */
    bits = MIN(DH_SECURITY_BITS * 2, p_bits);
    /* ensure we're not too close of p so rnd()%p stays uniform */
    if (bits <= p_bits && bits + 64 > p_bits) {
        bits += 64;
    }
    rc = bignum_rand(tmp, bits);
    if (rc != 1) {
        goto error;
    }
    rc = bignum_mod(dh_ctx->keypair[peer].priv_key, tmp, dh_ctx->modulus, ctx);
    if (rc != 1) {
        goto error;
    }
    /* Now compute the corresponding public key */
    rc = bignum_mod_exp(dh_ctx->keypair[peer].pub_key, dh_ctx->generator,
                        dh_ctx->keypair[peer].priv_key, dh_ctx->modulus, ctx);
    if (rc != 1) {
        goto error;
    }
    bignum_safe_free(tmp);
    bignum_ctx_free(ctx);
    return SSH_OK;
error:
    bignum_safe_free(tmp);
    bignum_ctx_free(ctx);
    return SSH_ERROR;
}

static int dh_keypair_get_keys(struct dh_ctx *ctx, int peer, const_bignum *priv,
                               const_bignum *pub) {
    if (((peer != DH_CLIENT_KEYPAIR) && (peer != DH_SERVER_KEYPAIR)) ||
        ((priv == NULL) && (pub == NULL)) || (ctx == NULL)) {
        return SSH_ERROR;
    }

    if (priv) {
        /* check that we have something in it */
        if (bignum_num_bits(ctx->keypair[peer].priv_key)) {
            *priv = ctx->keypair[peer].priv_key;
        } else {
            return SSH_ERROR;
        }
    }

    if (pub) {
        /* check that we have something in it */
        if (bignum_num_bits(ctx->keypair[peer].pub_key)) {
            *pub = ctx->keypair[peer].pub_key;
        } else {
            return SSH_ERROR;
        }
    }

    return SSH_OK;
}

static int dh_keypair_set_keys(struct dh_ctx *ctx, int peer, bignum priv,
                               bignum pub) {
    if (((peer != DH_CLIENT_KEYPAIR) && (peer != DH_SERVER_KEYPAIR)) ||
        ((priv == NULL) && (pub == NULL)) || (ctx == NULL)) {
        return SSH_ERROR;
    }

    if (priv) {
        bignum_safe_free(ctx->keypair[peer].priv_key);
        ctx->keypair[peer].priv_key = priv;
    }
    if (pub) {
        bignum_safe_free(ctx->keypair[peer].pub_key);
        ctx->keypair[peer].pub_key = pub;
    }
    return SSH_OK;
}

static void dh_free_modulus(struct dh_ctx *ctx) {
    bignum_safe_free(ctx->modulus);
    ctx->modulus = NULL;
}

static void dh_free_generator(struct dh_ctx *ctx) {
    if (ctx->generator != ssh_dh_generator) {
        bignum_safe_free(ctx->generator);
    }
}

static void dh_free_keypair(struct dh_keypair *keypair) {
    bignum_safe_free(keypair->priv_key);
    bignum_safe_free(keypair->pub_key);
}

static int dh_init_keypair(struct dh_keypair *keypair) {
    keypair->priv_key = bignum_new();
    if (keypair->priv_key == NULL) goto error;

    keypair->pub_key = bignum_new();
    if (keypair->pub_key == NULL) goto error;

    return SSH_OK;

error:
    dh_free_keypair(keypair);
    return SSH_ERROR;
}

/**
 * @brief Compute shared secret K in key exchange procedure.
 *
 * @param dh_ctx
 * @param local
 * @param remote
 * @param dest
 * @return int
 */
static int dh_compute_shared_secret(struct dh_ctx *dh_ctx, int local,
                                    int remote, bignum *dest) {
    int rc;
    bignum_CTX ctx = bignum_ctx_new();
    if (bignum_ctx_invalid(ctx)) {
        return SSH_ERROR;
    }

    if (*dest == NULL) {
        *dest = bignum_new();
        if (*dest == NULL) {
            rc = 0;
            goto done;
        }
    }

    rc = bignum_mod_exp(*dest, dh_ctx->keypair[remote].pub_key,
                        dh_ctx->keypair[local].priv_key, dh_ctx->modulus, ctx);

done:
    bignum_ctx_free(ctx);
    if (rc != 1) {
        return SSH_ERROR;
    }
    return SSH_OK;
}

/**
 * @brief Compute session identifier H in key exchange procedure.
 *
 * @param session
 * @return int
 */
static int dh_compute_session_id(ssh_session session) {
    ssh_buffer server_hash = NULL;
    ssh_buffer client_hash = NULL;
    ssh_buffer buf = NULL;
    const_bignum client_pubkey, server_pubkey;
    int rc;

    buf = ssh_buffer_new();
    if (buf == NULL) return SSH_ERROR;

    rc = ssh_buffer_pack(buf, "ss", session->client_id_str,
                         session->server_id_str);
    if (rc != SSH_OK) goto error;

    server_hash = session->in_hashbuf;
    client_hash = session->out_hashbuf;

    rc = ssh_buffer_pack(
        buf, "dPdPS", ssh_buffer_get_len(client_hash),
        ssh_buffer_get_len(client_hash), ssh_buffer_get(client_hash),
        ssh_buffer_get_len(server_hash), ssh_buffer_get_len(server_hash),
        ssh_buffer_get(server_hash), session->next_crypto->server_pubkey_blob);
    if (rc != SSH_OK) goto error;

    rc = dh_keypair_get_keys(session->next_crypto->dh_ctx, DH_CLIENT_KEYPAIR,
                             NULL, &client_pubkey);
    rc |= dh_keypair_get_keys(session->next_crypto->dh_ctx, DH_SERVER_KEYPAIR,
                              NULL, &server_pubkey);
    if (rc != SSH_OK) goto error;

    rc = ssh_buffer_pack(buf, "BBB", client_pubkey, server_pubkey,
                         session->next_crypto->shared_secret);
    if (rc != SSH_OK) goto error;

    if (session->next_crypto->kex_type != SSH_KEX_DH_GROUP14_SHA256) goto error;
    session->next_crypto->digest_len = SHA256_DIGEST_LENGTH;
    session->next_crypto->digest_type = SSH_KDF_SHA256;
    session->next_crypto->secret_hash =
        malloc(session->next_crypto->digest_len);
    if (session->next_crypto->secret_hash == NULL) goto error;
    sha256(ssh_buffer_get(buf), ssh_buffer_get_len(buf),
           session->next_crypto->secret_hash);

    if (session->next_crypto->session_id == NULL) {
        session->next_crypto->session_id_len = session->next_crypto->digest_len;
        session->next_crypto->session_id =
            malloc(session->next_crypto->session_id_len);
        memcpy(session->next_crypto->session_id,
               session->next_crypto->secret_hash,
               session->next_crypto->session_id_len);
    }

    return SSH_OK;
error:
    ssh_buffer_free(buf);
    return SSH_ERROR;
}

/**
 * @brief Derive and set session keys from shared secret K and session
 * identifier H.
 * @see RFC4253 section 7.1
 * @param session
 * @return int
 */
static int dh_gen_session_keys(ssh_session session) {
    ssh_string k_string = NULL;
    struct ssh_crypto_struct *crypto = session->next_crypto;
    unsigned char *key = NULL;
    unsigned char *IV_cli_to_srv = NULL;
    unsigned char *IV_srv_to_cli = NULL;
    unsigned char *enckey_cli_to_srv = NULL;
    unsigned char *enckey_srv_to_cli = NULL;
    unsigned char *intkey_cli_to_srv = NULL;
    unsigned char *intkey_srv_to_cli = NULL;
    size_t key_len = 0;
    size_t IV_len = 0;
    size_t enckey_cli_to_srv_len = 0;
    size_t enckey_srv_to_cli_len = 0;
    size_t intkey_cli_to_srv_len = 0;
    size_t intkey_srv_to_cli_len = 0;
    int rc = -1;

    k_string = ssh_make_bignum_string(crypto->shared_secret);
    if (k_string == NULL) goto error;
    /* See RFC4251 Section 5 for the definition of mpint which is the
     * encoding we need to use for key in the SSH KDF */
    key = (unsigned char *)k_string;
    key_len = ssh_string_len(k_string) + 4;

    IV_len = crypto->digest_len;

    enckey_cli_to_srv_len = crypto->out_cipher->keysize / 8;
    enckey_srv_to_cli_len = crypto->in_cipher->keysize / 8;
    intkey_cli_to_srv_len = hmac_digest_len(crypto->out_hmac);
    intkey_srv_to_cli_len = hmac_digest_len(crypto->in_hmac);

    IV_cli_to_srv = malloc(IV_len);
    IV_srv_to_cli = malloc(IV_len);
    enckey_cli_to_srv = malloc(enckey_cli_to_srv_len);
    enckey_srv_to_cli = malloc(enckey_srv_to_cli_len);
    intkey_cli_to_srv = malloc(intkey_cli_to_srv_len);
    intkey_srv_to_cli = malloc(intkey_srv_to_cli_len);
    if (IV_cli_to_srv == NULL || IV_srv_to_cli == NULL ||
        enckey_cli_to_srv == NULL || enckey_srv_to_cli == NULL ||
        intkey_cli_to_srv == NULL || intkey_srv_to_cli == NULL) {
        goto error;
    }

    /* IV */
    rc = ssh_kdf(crypto, key, key_len, 'A', IV_cli_to_srv, IV_len);
    if (rc < 0) {
        goto error;
    }
    rc = ssh_kdf(crypto, key, key_len, 'B', IV_srv_to_cli, IV_len);
    if (rc < 0) {
        goto error;
    }
    /* Encryption Key */
    rc = ssh_kdf(crypto, key, key_len, 'C', enckey_cli_to_srv,
                 enckey_cli_to_srv_len);
    if (rc < 0) {
        goto error;
    }
    rc = ssh_kdf(crypto, key, key_len, 'D', enckey_srv_to_cli,
                 enckey_srv_to_cli_len);
    if (rc < 0) {
        goto error;
    }
    /* Integrity Key */
    rc = ssh_kdf(crypto, key, key_len, 'E', intkey_cli_to_srv,
                 intkey_cli_to_srv_len);
    if (rc < 0) {
        goto error;
    }
    rc = ssh_kdf(crypto, key, key_len, 'F', intkey_srv_to_cli,
                 intkey_srv_to_cli_len);
    if (rc < 0) {
        goto error;
    }

    crypto->encryptIV = IV_cli_to_srv;
    crypto->decryptIV = IV_srv_to_cli;
    crypto->encryptkey = enckey_cli_to_srv;
    crypto->decryptkey = enckey_srv_to_cli;
    crypto->encryptMAC = intkey_cli_to_srv;
    crypto->decryptMAC = intkey_srv_to_cli;

    /* Initialize the encryption and decryption keys in next_crypto */
    rc = session->next_crypto->in_cipher->set_decrypt_key(
        session->next_crypto->in_cipher, session->next_crypto->decryptkey,
        session->next_crypto->decryptIV);
    if (rc != SSH_OK) {
        /* On error, make sure it is not used */
        session->next_crypto->used = 0;
        return SSH_ERROR;
    }

    rc = session->next_crypto->out_cipher->set_encrypt_key(
        session->next_crypto->out_cipher, session->next_crypto->encryptkey,
        session->next_crypto->encryptIV);
    if (rc != SSH_OK) {
        /* On error, make sure it is not used */
        session->next_crypto->used = 0;
        return SSH_ERROR;
    }

    return SSH_OK;

error:
    ssh_string_free(k_string);
    SAFE_FREE(IV_cli_to_srv);
    SAFE_FREE(IV_srv_to_cli);
    SAFE_FREE(enckey_cli_to_srv);
    SAFE_FREE(enckey_srv_to_cli);
    SAFE_FREE(intkey_cli_to_srv);
    SAFE_FREE(intkey_srv_to_cli);

    return SSH_ERROR;
}

/**
 * @brief Send client DH initialization message.
 *  byte      SSH_MSG_KEXDH_INIT
 *  mpint     e
 *
 * @see RFC 4253 section 8
 *
 * @param session
 * @return int
 */
static int dh_send_init(ssh_session session) {
    struct ssh_crypto_struct *crypto = session->next_crypto;
    const_bignum pubkey;
    int rc;

    rc = dh_keypair_gen_keys(crypto->dh_ctx, DH_CLIENT_KEYPAIR);
    if (rc != SSH_OK) return rc;

    rc = dh_keypair_get_keys(crypto->dh_ctx, DH_CLIENT_KEYPAIR, NULL, &pubkey);
    if (rc != SSH_OK) return rc;

    rc = ssh_buffer_pack(session->out_buffer, "bB", SSH_MSG_KEXDH_INIT, pubkey);
    if (rc != SSH_OK) return rc;

    rc = ssh_packet_send(session);
    if (rc != SSH_OK) return rc;

    return SSH_OK;
}

/**
 * @brief Wait for DH server reply and get session keys.
 * @see RFC 4253 section 8
 * @param session
 * @return int
 */
static int dh_receive_reply(ssh_session session) {
    struct ssh_crypto_struct *crypto = session->next_crypto;
    bignum server_pubkey;
    uint8_t type;
    int rc;

    rc = ssh_packet_receive(session);
    if (rc != SSH_OK) return rc;

    ssh_buffer_get_u8(session->in_buffer, &type);
    if (type != SSH_MSG_KEXDH_REPLY) return SSH_ERROR;

    rc = ssh_buffer_unpack(session->in_buffer, "SBS",
                           &crypto->server_pubkey_blob, &server_pubkey,
                           &crypto->dh_server_signature);
    if (rc != SSH_OK) return rc;

    rc = dh_keypair_set_keys(crypto->dh_ctx, DH_SERVER_KEYPAIR, NULL,
                             server_pubkey);
    if (rc != SSH_OK) {
        bignum_safe_free(server_pubkey);
        return rc;
    }

    /* Skip: check server public key */
    /* Waht should we do next? */
    // LAB: insert your code here.
    dh_compute_shared_secret(crypto->dh_ctx, DH_CLIENT_KEYPAIR,
                             DH_SERVER_KEYPAIR, &crypto->shared_secret);
    
    dh_compute_session_id(session);


    /* Skip: verifies signature on H (session id) */

    rc = ssh_crypto_set_algo(session);
    if (rc != SSH_OK) return rc;

    rc = dh_gen_session_keys(session);
    if (rc != SSH_OK) return rc;

    rc = ssh_buffer_add_u8(session->out_buffer, SSH_MSG_NEWKEYS);
    rc |= ssh_packet_send(session);
    if (rc != SSH_OK) return rc;

    return SSH_OK;
}

/**
 * @brief Wait for SSH_MSG_NEWKEYS from server and put newly generated session
 * keys into use.
 * @see RFC 4253 section 8
 * @param session
 * @return int
 */
static int dh_set_new_keys(ssh_session session) {
    struct ssh_crypto_struct *crypto = session->next_crypto;
    uint8_t type;
    int rc;

    rc = ssh_packet_receive(session);
    if (rc != SSH_OK) return rc;

    ssh_buffer_get_u8(session->in_buffer, &type);
    if (type != SSH_MSG_NEWKEYS) return SSH_ERROR;

    /* NEWKEYS received, now its time to activate encryption */
    // LAB: insert your code here.

    session->current_crypto = session->next_crypto;
    session->current_crypto->used = SSH_DIRECTION_BOTH;

    /* next_crypto should be deprecated from now if re-kex is not supportes */
    session->next_crypto = NULL;

    return SSH_OK;
}

/**
 * @brief Perform Diffie-Hellman key exchange procedure. 
 * 
 * @param session 
 * @return int 
 */
int ssh_dh_handshake(ssh_session session) {
    struct ssh_crypto_struct *crypto = session->next_crypto;
    int rc;

    rc = dh_init(session);
    if (rc != SSH_OK) goto error;

    /* send KEXDH_INIT */
    rc = dh_send_init(session);
    if (rc != SSH_OK) goto error;

    /* receive KEXDH_REPLY */
    rc = dh_receive_reply(session);
    if (rc != SSH_OK) goto error;

    /* recive NEWKEYS */
    rc = dh_set_new_keys(session);
    if (rc != SSH_OK) goto error;

    return SSH_OK;
error:
    dh_cleanup(crypto);
    return SSH_ERROR;
}