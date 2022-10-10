/**
 * @file crypto.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH cryptography library.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

/* DO NOT modify this file unless you know what you are doing */

#include "libsftp/crypto.h"
#include "libsftp/dh.h"
#include "libsftp/libssh.h"
#include "libsftp/session.h"
#include "libsftp/util.h"

static struct ssh_hmac_struct ssh_hmac_tab[] = {
    {"hmac-sha1", SSH_HMAC_SHA1, false},
    {"hmac-sha2-256", SSH_HMAC_SHA256, false},
    {"hmac-sha2-512", SSH_HMAC_SHA512, false},
    {"hmac-md5", SSH_HMAC_MD5, false},
    {"aead-poly1305", SSH_HMAC_AEAD_POLY1305, false},
    {"aead-gcm", SSH_HMAC_AEAD_GCM, false},
    {"hmac-sha1-etm@openssh.com", SSH_HMAC_SHA1, true},
    {"hmac-sha2-256-etm@openssh.com", SSH_HMAC_SHA256, true},
    {"hmac-sha2-512-etm@openssh.com", SSH_HMAC_SHA512, true},
    {"hmac-md5-etm@openssh.com", SSH_HMAC_MD5, true},
    {NULL, 0, false}};

struct ssh_hmac_struct *ssh_get_hmactab(void) {
    return ssh_hmac_tab;
}

size_t hmac_digest_len(enum ssh_hmac_e type) {
    switch (type) {
        case SSH_HMAC_SHA1:
            return SHA_DIGEST_LEN;
        case SSH_HMAC_SHA256:
            return SHA256_DIGEST_LEN;
        case SSH_HMAC_SHA512:
            return SHA512_DIGEST_LEN;
        case SSH_HMAC_MD5:
            return MD5_DIGEST_LEN;
        // case SSH_HMAC_AEAD_POLY1305:
        //   return POLY1305_TAGLEN;
        case SSH_HMAC_AEAD_GCM:
            return AES_GCM_TAGLEN;
        default:
            return 0;
    }
}

const char *ssh_hmac_type_to_string(enum ssh_hmac_e hmac_type, bool etm) {
    int i = 0;
    struct ssh_hmac_struct *ssh_hmactab = ssh_get_hmactab();
    while (ssh_hmactab[i].name && ((ssh_hmactab[i].hmac_type != hmac_type) ||
                                   (ssh_hmactab[i].etm != etm))) {
        i++;
    }
    return ssh_hmactab[i].name;
}

/* it allocates a new cipher structure based on its offset into the global table
 */
static struct ssh_cipher_struct *cipher_new(int offset) {
    struct ssh_cipher_struct *cipher = NULL;

    cipher = malloc(sizeof(struct ssh_cipher_struct));
    if (cipher == NULL) {
        return NULL;
    }

    /* note the memcpy will copy the pointers : so, you shouldn't free them */
    memcpy(cipher, &ssh_get_ciphertab()[offset], sizeof(*cipher));

    return cipher;
}

void ssh_cipher_clear(struct ssh_cipher_struct *cipher) {
    if (cipher == NULL) {
        return;
    }

    if (cipher->cleanup != NULL) {
        cipher->cleanup(cipher);
    }
}

static void cipher_free(struct ssh_cipher_struct *cipher) {
    ssh_cipher_clear(cipher);
    SAFE_FREE(cipher);
}

struct ssh_crypto_struct *crypto_new(void) {
    struct ssh_crypto_struct *crypto;

    crypto = malloc(sizeof(struct ssh_crypto_struct));
    if (crypto == NULL) {
        return NULL;
    }
    ZERO_STRUCTP(crypto);
    return crypto;
}

struct ssh_crypto_struct *ssh_get_crypto(
    ssh_session session, enum ssh_crypto_direction_e direction) {
    if (session == NULL) return NULL;

    if (session->current_crypto == NULL ||
        !(session->current_crypto->used & direction)) {
        return NULL;
    }

    switch (direction) {
        case SSH_DIRECTION_IN:
            if (session->current_crypto->in_cipher != NULL) {
                return session->current_crypto;
            }
            break;
        case SSH_DIRECTION_OUT:
            if (session->current_crypto->out_cipher != NULL) {
                return session->current_crypto;
            }
            break;
        case SSH_DIRECTION_BOTH:
            if (session->current_crypto->in_cipher != NULL &&
                session->current_crypto->out_cipher != NULL) {
                return session->current_crypto;
            }
    }

    return NULL;
}

int ssh_crypto_set_algo(ssh_session session) {
    const char *wanted = NULL;
    struct ssh_cipher_struct *ssh_ciphertab = ssh_get_ciphertab();
    struct ssh_hmac_struct *ssh_hmactab = ssh_get_hmactab();
    size_t i = 0;
    int cmp;

    /* out cipher*/
    wanted = session->next_crypto->kex_methods[SSH_CRYPT_C_S];
    for (i = 0; ssh_ciphertab[i].name != NULL; ++i) {
        cmp = strcmp(wanted, ssh_ciphertab[i].name);
        if (cmp == 0) {
            break;
        }
    }
    if (ssh_ciphertab[i].name == NULL) goto error;
    session->next_crypto->out_cipher = cipher_new(i);

    /* out mac */
    wanted = session->next_crypto->kex_methods[SSH_MAC_C_S];
    for (i = 0; ssh_hmactab[i].name != NULL; i++) {
        cmp = strcmp(wanted, ssh_hmactab[i].name);
        if (cmp == 0) {
            break;
        }
    }
    if (ssh_hmactab[i].name == NULL) goto error;
    session->next_crypto->out_hmac = ssh_hmactab[i].hmac_type;

    /* in cipher */
    wanted = session->next_crypto->kex_methods[SSH_CRYPT_S_C];
    for (i = 0; ssh_ciphertab[i].name != NULL; ++i) {
        cmp = strcmp(wanted, ssh_ciphertab[i].name);
        if (cmp == 0) {
            break;
        }
    }
    if (ssh_ciphertab[i].name == NULL) goto error;
    session->next_crypto->in_cipher = cipher_new(i);

    /* in mac */
    wanted = session->next_crypto->kex_methods[SSH_MAC_S_C];
    for (i = 0; ssh_hmactab[i].name != NULL; i++) {
        cmp = strcmp(wanted, ssh_hmactab[i].name);
        if (cmp == 0) {
            break;
        }
    }
    if (ssh_hmactab[i].name == NULL) goto error;
    session->next_crypto->in_hmac = ssh_hmactab[i].hmac_type;

    return SSH_OK;

error:
    cipher_free(session->next_crypto->in_cipher);
    cipher_free(session->next_crypto->out_cipher);
    return SSH_ERROR;
}

void crypto_free(struct ssh_crypto_struct *crypto) {
    size_t i;

    if (crypto == NULL) {
        return;
    }

    dh_cleanup(crypto);
    bignum_safe_free(crypto->shared_secret);
    ssh_string_free(crypto->dh_server_signature);
    ssh_string_free(crypto->server_pubkey_blob);

    if (crypto->session_id != NULL) {
        explicit_bzero(crypto->session_id, crypto->session_id_len);
        SAFE_FREE(crypto->session_id);
    }
    if (crypto->secret_hash != NULL) {
        explicit_bzero(crypto->secret_hash, crypto->digest_len);
        SAFE_FREE(crypto->secret_hash);
    }
    SAFE_FREE(crypto->encryptIV);
    SAFE_FREE(crypto->decryptIV);
    SAFE_FREE(crypto->encryptMAC);
    SAFE_FREE(crypto->decryptMAC);
    if (crypto->encryptkey != NULL) {
        explicit_bzero(crypto->encryptkey, crypto->out_cipher->keysize / 8);
        SAFE_FREE(crypto->encryptkey);
    }
    if (crypto->decryptkey != NULL) {
        explicit_bzero(crypto->decryptkey, crypto->in_cipher->keysize / 8);
        SAFE_FREE(crypto->decryptkey);
    }

    cipher_free(crypto->in_cipher);
    cipher_free(crypto->out_cipher);

    for (i = 0; i < SSH_KEX_METHODS; i++) {
        SAFE_FREE(crypto->client_kex.methods[i]);
        SAFE_FREE(crypto->server_kex.methods[i]);
        SAFE_FREE(crypto->kex_methods[i]);
    }

    explicit_bzero(crypto, sizeof(struct ssh_crypto_struct));

    SAFE_FREE(crypto);
}
