/**
 * @file auth.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH authentication layer functionalities
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef AUTH_H
#define AUTH_H

#include "libssh.h"

int ssh_request_auth(ssh_session session);

#endif /* AUTH_H */