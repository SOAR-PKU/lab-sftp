/**
 * @file pki.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief Public key infrastructure functionalities.
 * This file is incomplete since we do NOT verify server public keys.
 * You can ignore this file at this moment and you are welcome to complete this module.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef PKI_H
#define PKI_H

#include "libcrypto.h"
#include "crypto.h"

struct ssh_key_struct {
    enum ssh_keytypes_e type;
    int flags;
    const char *type_c; /* Don't free it ! it is static */
    int ecdsa_nid;

    DSA *dsa;
    RSA *rsa;

    void *cert;
    enum ssh_keytypes_e cert_type;
};

struct ssh_signature_struct {
    enum ssh_keytypes_e type;
    enum ssh_digest_e hash_type;
    const char *type_c;
    ssh_string raw_sig;
};

typedef struct ssh_signature_struct *ssh_signature;

#endif /* PKI_H */