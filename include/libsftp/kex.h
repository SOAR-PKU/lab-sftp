/**
 * @file kex.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH key exchange functionalities.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef KEX_H
#define KEX_H

#include "libssh.h"

#define SSH_KEX_METHODS 10

/* the offsets of methods */
enum ssh_kex_types_e {
	SSH_KEX=0,
	SSH_HOSTKEYS,
	SSH_CRYPT_C_S,
	SSH_CRYPT_S_C,
	SSH_MAC_C_S,
	SSH_MAC_S_C,
	SSH_COMP_C_S,
	SSH_COMP_S_C,
	SSH_LANG_C_S,
	SSH_LANG_S_C
};

struct ssh_kex_struct {
    unsigned char cookie[16];
    char *methods[SSH_KEX_METHODS];
};

int ssh_set_client_kex(ssh_session session);
int ssh_send_kex(ssh_session session);
int ssh_receive_kex(ssh_session session);
int ssh_select_kex(ssh_session session);

#endif /* KEX_H */