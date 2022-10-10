/**
 * @file string.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH string functionality.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef STRING_H
#define STRING_H

#include <sys/types.h>

struct ssh_string_struct {
    uint32_t size;
    unsigned char data[1];
} __attribute__((packed));

#endif /* STRING_H */
