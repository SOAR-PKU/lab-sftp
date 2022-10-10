/**
 * @file logger.h
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief A minimal logging framework
 * motivated by https://github.com/jnguyen1098/seethe/blob/master/seethe.h
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef LINUX
    #include <time.h>
#endif

/* Default level */
#ifndef LOG_LEVEL
#define LOG_LEVEL DEBUG
#endif

#define __FILENAME__                                                         \
    (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 \
                                      : __FILE__)

/* Colour customization */
#define DEBUG_COLOUR ""
#define INFO_COLOUR "\x1B[36m"
#define NOTICE_COLOUR "\x1B[32;1m"
#define WARNING_COLOUR "\x1B[33m"
#define ERROR_COLOUR "\x1B[31m"
#define CRITICAL_COLOUR "\x1B[41;1m"

/* Do not change this. */
#define RESET_COLOUR "\x1B[0m"

/* Formatting prefs. */
#define MSG_ENDING "\n"
#define TIME_FORMAT "%T"
#define BORDER "-"

/* Enabler flags */
#define DISPLAY_COLOUR 1
#define DISPLAY_TIME 1
#define DISPLAY_LEVEL 1
#define DISPLAY_FUNC 1
#define DISPLAY_FILE 1
#define DISPLAY_LINE 1
#define DISPLAY_BORDER 1
#define DISPLAY_MESSAGE 1
#define DISPLAY_ENDING 1
#define DISPLAY_RESET 1

/* Log to screen */
#define emit_log(colour, level, file, func, line, ...)                       \
    do {                                                                     \
        /* notate the time */                                                \
        struct timeval tv;                                                   \
        gettimeofday(&tv, NULL);                                             \
        time_t t = tv.tv_sec;                                                \
        char time_buffer[80];                                                \
        char time_sec[80];                                                   \
        strftime(time_sec, 80, TIME_FORMAT, localtime(&t));                  \
        sprintf(time_buffer, "%s:%ld", time_sec, tv.tv_usec);                 \
                                                                             \
        /* enable colour */                                                  \
        fprintf(stderr, "%s", DISPLAY_COLOUR ? colour : "");          \
                                                                             \
        /* display the time */                                               \
        fprintf(stderr, "%s%s", DISPLAY_TIME ? time_buffer : "",      \
                DISPLAY_TIME ? " " : "");                                    \
                                                                             \
        /* display the level */                                              \
        fprintf(stderr, "%10s%s", DISPLAY_LEVEL ? level : "",         \
                DISPLAY_LEVEL ? " " : "");                                   \
                                                                             \
        /* display the function doing the logging */                         \
        fprintf(stderr, "%s%s", DISPLAY_FUNC ? func : "",             \
                DISPLAY_FUNC ? " " : "");                                    \
                                                                             \
        /* display the file and/or the line number */                        \
        fprintf(stderr, "%s%s%s%.d%s%s",                              \
                DISPLAY_FUNC && (DISPLAY_FILE || DISPLAY_LINE) ? "(" : "",   \
                DISPLAY_FILE ? __FILENAME__ : "",                            \
                DISPLAY_FILE && DISPLAY_LINE ? ":" : "",                     \
                DISPLAY_LINE ? line : 0,                                     \
                DISPLAY_FUNC && (DISPLAY_FILE || DISPLAY_LINE) ? ") " : "",  \
                !DISPLAY_FUNC && (DISPLAY_FILE || DISPLAY_LINE) ? " " : ""); \
                                                                             \
        /* display message border */                                         \
        fprintf(stderr, "%s%s", DISPLAY_BORDER ? BORDER : "",         \
                DISPLAY_BORDER ? " " : "");                                  \
                                                                             \
        /* display the callee's message */                                   \
        if (DISPLAY_MESSAGE) fprintf(stderr, __VA_ARGS__);            \
                                                                             \
        /* add the message ending (usually '\n') */                          \
        fprintf(stderr, "%s", DISPLAY_ENDING ? MSG_ENDING : "");      \
                                                                             \
        /* reset the colour */                                               \
        fprintf(stderr, "%s", DISPLAY_RESET ? RESET_COLOUR : "");     \
                                                                             \
    } while (0)

/* Level enum */
#define DEBUG 0
#define INFO 1
#define NOTICE 2
#define WARNING 3
#define ERROR 4
#define CRITICAL 5
#define SILENT 6

/* DEBUG LOG */
#define LOG_DEBUG(...)                                                      \
    do {                                                                    \
        if (LOG_LEVEL == DEBUG) {                                           \
            emit_log(DEBUG_COLOUR, "[DEBUG]", __FILE__, __func__, __LINE__, \
                     __VA_ARGS__);                                          \
        }                                                                   \
    } while (0)

/* INFO LOG */
#define LOG_INFO(...)                                                     \
    do {                                                                  \
        if (LOG_LEVEL <= INFO) {                                          \
            emit_log(INFO_COLOUR, "[INFO]", __FILE__, __func__, __LINE__, \
                     __VA_ARGS__);                                        \
        }                                                                 \
    } while (0)

/* NOTICE LOG */
#define LOG_NOTICE(...)                                                       \
    do {                                                                      \
        if (LOG_LEVEL <= NOTICE) {                                            \
            emit_log(NOTICE_COLOUR, "[NOTICE]", __FILE__, __func__, __LINE__, \
                     __VA_ARGS__);                                            \
        }                                                                     \
    } while (0)

/* WARNING LOG */
#define LOG_WARNING(...)                                              \
    do {                                                              \
        if (LOG_LEVEL <= WARNING) {                                   \
            emit_log(WARNING_COLOUR, "[WARNING]", __FILE__, __func__, \
                     __LINE__, __VA_ARGS__);                          \
        }                                                             \
    } while (0)

/* ERROR LOG */
#define LOG_ERROR(...)                                                      \
    do {                                                                    \
        if (LOG_LEVEL <= ERROR) {                                           \
            emit_log(ERROR_COLOUR, "[ERROR]", __FILE__, __func__, __LINE__, \
                     __VA_ARGS__);                                          \
        }                                                                   \
    } while (0)

/* CRITICAL LOG */
#define LOG_CRITICAL(...)                                               \
    do {                                                                \
        if (LOG_LEVEL <= CRITICAL) {                                    \
            emit_log(CRITICAL_COLOUR, "[CRITICAL]", __FILE__, __func__, \
                     __LINE__, __VA_ARGS__);                            \
            exit(EXIT_FAILURE);                                         \
        }                                                               \
    } while (0)

#endif /* logger.h */