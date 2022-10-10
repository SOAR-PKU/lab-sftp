/**
 * @file bignum.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH multi-precision integer functionalities.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef BIGNUM_H_
#define BIGNUM_H_

#include "libsftp/libssh.h"
#include "libsftp/libcrypto.h"

bignum ssh_make_string_bn(ssh_string string);
ssh_string ssh_make_bignum_string(bignum num);
void ssh_print_bignum(const char *which, const_bignum num);


#endif /* BIGNUM_H_ */
