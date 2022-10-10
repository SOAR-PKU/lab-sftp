/**
 * @file error.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief Error feedback to users.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <sys/types.h>
#define ERR_BUF_MAX 1024

enum ssh_error_types_e {
    SSH_NO_ERROR = 0,
    SSH_REQUEST_DENIED,
    SSH_FATAL,
    SSH_EINTR
};

void ssh_set_error(uint8_t code, char* format, ...);