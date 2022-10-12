/**
 * @file client.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SFTP client, only supports uploading and downloading files.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libsftp/libsftp.h"

#define MAX_BUF_SIZE 16384

void prompt() {
    fprintf(stdout, "%s", "sftp> ");
    fflush(stdout);
}

char* strip_filename(char* filename) {
    char* pos;
    for(pos = filename + strlen(filename); pos != filename; pos--) {
        if(*pos == '/') return pos + 1;
    }
    return filename;
}

int get_file(sftp_session sftp) {
    char filename[51];
    char* stripped_name = NULL;
    sftp_file file = NULL;
    char buffer[MAX_BUF_SIZE];
    int nbytes, nwritten, rc;
    int fd;

    fprintf(stdout, "%s", "Enter filename: ");
    fflush(stdout);
    fscanf(stdin, "%50s", filename);
    stripped_name = strip_filename(filename);

    file = sftp_open(sftp, filename, O_RDONLY, 0);
    if (file == NULL) {
        fprintf(stderr, "Can not open remote file %s", filename);
        return -1;
    }


    fd = open(stripped_name, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd < 0) {
        sftp_close(file);
        fprintf(stderr, "Can't open file for writing: %s\n", strerror(errno));
        return -1;
    }

    while (1) {
        nbytes = sftp_read(file, buffer, sizeof(buffer));
        if (nbytes == 0) {
            break; /* EOF */
        } else if (nbytes < 0) {
            fprintf(stderr, "Error while reading file: %s\n", ssh_get_error());
            sftp_close(file);
            close(fd);
            return -1;
        }

        nwritten = write(fd, buffer, nbytes);
        if (nwritten != nbytes) {
            fprintf(stderr, "Error writing: %s\n", strerror(errno));
            sftp_close(file);
            close(fd);
            return -1;
        }
    }

    fprintf(stdout, "%s downloaded to the current working direcrtory\n", stripped_name);

    rc = sftp_close(file);
    if (rc != SSH_OK) {
        fprintf(stderr, "Can't close the remote file: %s\n", ssh_get_error());
        return -1;
    }
    close(fd);

    return 0;
}

int put_file(sftp_session sftp) {
    char filename[51];
    char* stripped_name = NULL;
    sftp_file file = NULL;
    char buffer[MAX_BUF_SIZE];
    int nbytes, nwritten, rc;
    int fd;

    fprintf(stdout, "%s", "Enter filename: ");
    fflush(stdout);
    fscanf(stdin, "%50s", filename);
    stripped_name = strip_filename(filename);

    file = sftp_open(sftp, stripped_name, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
    if (file == NULL) {
        fprintf(stderr, "Can not open remote file %s", stripped_name);
        return -1;
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Can't open file for reading: %s\n", strerror(errno));
        sftp_close(file);
        return -1;
    }

    while (1) {
        nbytes = read(fd, buffer, sizeof(buffer));
        if (nbytes == 0) {
            break; /* EOF */
        } else if (nbytes < 0) {
            fprintf(stderr, "Error while reading file: %s\n", strerror(errno));
            sftp_close(file);
            close(fd);
            return -1;
        }

        nwritten = sftp_write(file, buffer, nbytes);
        if (nwritten != nbytes) {
            fprintf(stderr, "Error writing: %s\n", ssh_get_error());
            sftp_close(file);
            close(fd);
            return -1;
        }
    }

    fprintf(stdout, "%s uploaded to the remote home directory\n", stripped_name);

    rc = sftp_close(file);
    if (rc != SSH_OK) {
        fprintf(stderr, "Can't close the remote file: %s\n", ssh_get_error());
        return -1;
    }
    close(fd);

    return 0;
}

int main(int argc, char** argv) {
    int rc;
    char password[100];
    char cmd[11] = {'\0'};
    char* host = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: ./client username@hostname\n");
        exit(1);
    } else {
        host = argv[1];
    }

    /* Transport Layer */
    ssh_session session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "%s", ssh_get_error());
        exit(1);
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, host);

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "%s", ssh_get_error());
        exit(1);
    }

    /* Authentication Layer */
    rc = SSH_ERROR;
    while (rc != SSH_OK) {
        ssh_get_password(password);
        rc = ssh_userauth_password(session, password);
        switch (rc) {
            case SSH_OK:
                break;
            case SSH_AGAIN:
                fprintf(stdout, "%s", ssh_get_error());
                break;
            case SSH_ERROR:
                fprintf(stdout, "%s", ssh_get_error());
                exit(1);
        }
    }

    /* Connection Layer & SFTP Layer */
    sftp_session sftp = sftp_new(session);
    if (sftp == NULL) {
        fprintf(stderr, "%s", ssh_get_error());
        exit(1);
    }

    rc = sftp_init(sftp);
    if (rc != SSH_OK) {
        fprintf(stderr, "%s", ssh_get_error());
        exit(1);
    }

    /* File manipulation: interactive shell */
    while (1) {
        prompt();
        fscanf(stdin, "%10s", cmd);
        if (strcmp(cmd, "get") == 0) {
            if (get_file(sftp) != 0) {
                fprintf(stderr, "%s", ssh_get_error());
                break;
            }
        } else if (strcmp(cmd, "put") == 0) {
            if (put_file(sftp) != 0) {
                fprintf(stderr, "%s", ssh_get_error());
                break;
            }
        } else if (strcmp(cmd, "bye") == 0) {
            fprintf(stdout, "%s", "Disconnect\n");
            break;
        } else {
            fprintf(stderr,
                    "Unsupported command: %s. Only supports 'get' and 'put'\n",
                    cmd);
        }
    }

    sftp_free(sftp);
    ssh_free(session);

    return 0;
}