/**
 * @file error.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief Error feedbacks to users.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "libsftp/libssh.h"
#include "libsftp/error.h"
#include "libsftp/util.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

char err_msg[ERR_BUF_MAX];


char* ssh_error_names[] = {"NO ERROR", "REQUEST DENIED", "FATAL", "INTERRUPT"};

void ssh_set_error(uint8_t code, char* format, ...) {
    ZERO(err_msg, ERR_BUF_MAX);

    strcpy(err_msg, ssh_error_names[code]);
    strcat(err_msg, ": ");

    va_list args;
    va_start(args, format);
    vsprintf(&err_msg[strlen(err_msg)], format, args);
    va_end(args);
}

char* ssh_get_error(void) {
    return err_msg;
}

char* sftp_get_error(void) {
    return err_msg;
}