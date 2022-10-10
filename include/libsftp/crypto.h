/**
 * @file crypto.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH cryptography functionalities.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdbool.h>

#include "kex.h"
#include "libcrypto.h"
#include "libssh.h"

#define DIGEST_MAX_LEN 64
#define AES_GCM_TAGLEN 16
#define AES_GCM_IVLEN 12

enum ssh_kdf_digest {
    SSH_KDF_SHA1 = 1,
    SSH_KDF_SHA256,
    SSH_KDF_SHA384,
    SSH_KDF_SHA512
};

enum ssh_hmac_e {
    SSH_HMAC_NONE = 0,
    SSH_HMAC_SHA1 = 1,
    SSH_HMAC_SHA256,
    SSH_HMAC_SHA512,
    SSH_HMAC_MD5,
    SSH_HMAC_AEAD_POLY1305,
    SSH_HMAC_AEAD_GCM
};

enum ssh_des_e { SSH_3DES, SSH_DES };

enum ssh_crypto_direction_e {
    SSH_DIRECTION_IN = 1,
    SSH_DIRECTION_OUT = 2,
    SSH_DIRECTION_BOTH = 3,
};

enum ssh_digest_e {
    SSH_DIGEST_AUTO = 0,
    SSH_DIGEST_SHA1 = 1,
    SSH_DIGEST_SHA256,
    SSH_DIGEST_SHA384,
    SSH_DIGEST_SHA512,
};

enum ssh_key_exchange_e {
    SSH_KEX_DH_GROUP14_SHA1 = 0,
    SSH_KEX_DH_GROUP1_SHA1,
    SSH_KEX_ECDH_SHA2_NISTP256,
    SSH_KEX_ECDH_SHA2_NISTP384,
    SSH_KEX_ECDH_SHA2_NISTP521,
    SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG,
    SSH_KEX_CURVE25519_SHA256,
    SSH_KEX_DH_GROUP16_SHA512,
    SSH_KEX_DH_GROUP18_SHA512,
    SSH_KEX_DH_GROUP14_SHA256,
};

enum ssh_keytypes_e {
    SSH_KEYTYPE_UNKNOWN = 0,
    SSH_KEYTYPE_DSS = 1,
    SSH_KEYTYPE_RSA,
    SSH_KEYTYPE_RSA1,
    SSH_KEYTYPE_ECDSA,
    SSH_KEYTYPE_ED25519,
    SSH_KEYTYPE_DSS_CERT01,
    SSH_KEYTYPE_RSA_CERT01,
    SSH_KEYTYPE_ECDSA_P256,
    SSH_KEYTYPE_ECDSA_P384,
    SSH_KEYTYPE_ECDSA_P521,
    SSH_KEYTYPE_ECDSA_P256_CERT01,
    SSH_KEYTYPE_ECDSA_P384_CERT01,
    SSH_KEYTYPE_ECDSA_P521_CERT01,
    SSH_KEYTYPE_ED25519_CERT01,
};

enum ssh_cipher_e {
    SSH_NO_CIPHER = 0,
    SSH_3DES_CBC,
    SSH_AES128_CBC,
    SSH_AES192_CBC,
    SSH_AES256_CBC,
    SSH_AES128_CTR,
    SSH_AES192_CTR,
    SSH_AES256_CTR,
    SSH_AEAD_AES128_GCM,
    SSH_AEAD_AES256_GCM,
    SSH_AEAD_CHACHA20_POLY1305
};

struct ssh_hmac_struct {
    const char *name;
    enum ssh_hmac_e hmac_type;
    bool etm;
};

struct ssh_crypto_struct {
    bignum shared_secret;
    struct dh_ctx *dh_ctx;
    ssh_string server_pubkey_blob;
    ssh_string dh_server_signature; /* information used by dh_handshake. */
    size_t session_id_len;
    unsigned char *session_id;
    size_t digest_len; /* len of the secret hash */
    unsigned char
        *secret_hash; /* Secret hash is same as session id until re-kex */
    unsigned char *encryptIV;
    unsigned char *decryptIV;
    unsigned char *decryptkey;
    unsigned char *encryptkey;
    unsigned char *encryptMAC;
    unsigned char *decryptMAC;
    unsigned char hmacbuf[DIGEST_MAX_LEN];
    struct ssh_cipher_struct *in_cipher,
        *out_cipher;                   /* the cipher structures/objects */
    enum ssh_hmac_e in_hmac, out_hmac; /* the MAC algorithms used */

    ssh_key server_pubkey;
    /* kex sent by server, client, and mutually elected methods */
    struct ssh_kex_struct server_kex;
    struct ssh_kex_struct client_kex;
    char *kex_methods[SSH_KEX_METHODS];
    enum ssh_key_exchange_e kex_type;
    enum ssh_kdf_digest
        digest_type; /* Digest type for session keys derivation */
    enum ssh_crypto_direction_e
        used; /* Is this crypto still used for either of directions? */
};

struct ssh_cipher_struct {
    const char *name;       /* ssh name of the algorithm */
    unsigned int blocksize; /* blocksize of the algo */
    enum ssh_cipher_e ciphertype;
    uint32_t lenfield_blocksize; /* blocksize of the packet length field */
    size_t keylen;               /* length of the key structure */

    struct ssh_aes_key_schedule *aes_key;
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx;

    unsigned int keysize; /* bits of key used. != keylen */
    size_t tag_size;      /* overhead required for tag */
    
    /* sets the new key for immediate use */
    int (*set_encrypt_key)(struct ssh_cipher_struct *cipher, void *key,
                           void *IV);
    int (*set_decrypt_key)(struct ssh_cipher_struct *cipher, void *key,
                           void *IV);
    void (*encrypt)(struct ssh_cipher_struct *cipher, void *in, void *out,
                    size_t len);
    void (*decrypt)(struct ssh_cipher_struct *cipher, void *in, void *out,
                    size_t len);
    void (*cleanup)(struct ssh_cipher_struct *cipher);
};

struct ssh_crypto_struct *crypto_new(void);
void crypto_free(struct ssh_crypto_struct *crypto);
struct ssh_crypto_struct *ssh_get_crypto(ssh_session session,
                                     enum ssh_crypto_direction_e direction);
int ssh_crypto_set_algo(ssh_session session);

void ssh_reseed(void);
int ssh_get_random(void *where, int len, int strong);

int ssh_crypto_init(void);
void ssh_crypto_finalize(void);

int ssh_kdf(struct ssh_crypto_struct *crypto, unsigned char *key,
            size_t key_len, int key_type, unsigned char *output,
            size_t requested_len);

void ssh_cipher_clear(struct ssh_cipher_struct *cipher);
struct ssh_hmac_struct *ssh_get_hmactab(void);
struct ssh_cipher_struct *ssh_get_ciphertab(void);
const char *ssh_hmac_type_to_string(enum ssh_hmac_e hmac_type, bool etm);

MD5CTX md5_init(void);
void md5_update(MD5CTX c, const void *data, unsigned long len);
void md5_final(unsigned char *md, MD5CTX c);

SHACTX sha1_init(void);
void sha1_update(SHACTX c, const void *data, unsigned long len);
void sha1_final(unsigned char *md, SHACTX c);
void sha1(const unsigned char *digest, int len, unsigned char *hash);

SHA256CTX sha256_init(void);
void sha256_update(SHA256CTX c, const void *data, unsigned long len);
void sha256_final(unsigned char *md, SHA256CTX c);
void sha256(const unsigned char *digest, int len, unsigned char *hash);

SHA384CTX sha384_init(void);
void sha384_update(SHA384CTX c, const void *data, unsigned long len);
void sha384_final(unsigned char *md, SHA384CTX c);
void sha384(const unsigned char *digest, int len, unsigned char *hash);

SHA512CTX sha512_init(void);
void sha512_update(SHA512CTX c, const void *data, unsigned long len);
void sha512_final(unsigned char *md, SHA512CTX c);
void sha512(const unsigned char *digest, int len, unsigned char *hash);

void evp(int nid, unsigned char *digest, int len, unsigned char *hash,
         unsigned int *hlen);
EVPCTX evp_init(int nid);
void evp_update(EVPCTX ctx, const void *data, unsigned long len);
void evp_final(EVPCTX ctx, unsigned char *md, unsigned int *mdlen);

HMACCTX hmac_init(const void *key, int len, enum ssh_hmac_e type);
void hmac_update(HMACCTX c, const void *data, unsigned long len);
void hmac_final(HMACCTX ctx, unsigned char *hashmacbuf, unsigned int *len);
size_t hmac_digest_len(enum ssh_hmac_e type);

#endif /* CRYPTO_H */