/*
 *  Copyright (C) 2005 Eugene Kurmanin <smfs@users.sourceforge.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define QUIT_OK		1
#define QUIT_PERM	0
#define QUIT_FAIL	-1

#define CLAMD_PORT	3310
#define CLAMD_ADDRESS	"127.0.0.1"
#define CLAMD_TIMEOUT	60

#define MAXLINE		128

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

const char *eicar="X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

int scan(const char *);
int block_socket(int, int);
int clamd_connect(int, struct sockaddr *, int);
int clamd_send(int, char *);
int clamd_recv(int, char *, int);
void close_socket(int);
void usage(const char *);

int block_socket(int sock, int block) {
    int flags;
    
    if (sock < 0) return -1;
    if ((flags = fcntl(sock, F_GETFL)) < 0) return -1;
    if (block)
	flags &= ~O_NONBLOCK;
    else
	flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0) return -1;
    return 0;
}

int clamd_connect(int sock, struct sockaddr *address, int addrlen) {
    int optval, ret;
    fd_set wfds;
    struct timeval tv;
    socklen_t optlen = sizeof(optval);
    
    if (sock < 0) return -1;
    if (block_socket(sock, 0) < 0) return -1;
    if ((ret = connect(sock, address, addrlen)) < 0)
	if (errno != EINPROGRESS) return -1;
    if (ret == 0) goto done;
    do {
	FD_ZERO(&wfds);
	FD_SET(sock, &wfds);
	tv.tv_sec = CLAMD_TIMEOUT;
	tv.tv_usec = 0;
	ret = select(sock + 1, NULL, &wfds, NULL, &tv);
    } while (ret < 0 && errno == EINTR);
    if (ret <= 0) return -1;
    if (!FD_ISSET(sock, &wfds)) return -1;
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0) return -1;
    if (optval) return -1;
done:
    if (block_socket(sock, 1) < 0) return -1;
    return 0;
}

void close_socket(int sock) {
    int ret;
    
    if (sock < 0) return;
    shutdown(sock, SHUT_RDWR);
    do {
	ret = close(sock);
    } while (ret < 0 && errno == EINTR);
    return;
}

int clamd_send(int sock, char *buffer) {
    int ret;
    fd_set wfds;
    struct timeval tv;

    if (sock < 0) return -1;
    do {
	FD_ZERO(&wfds);
	FD_SET(sock, &wfds);
	tv.tv_sec = CLAMD_TIMEOUT;
	tv.tv_usec = 0;
	ret = select(sock + 1, NULL, &wfds, NULL, &tv);
    } while (ret < 0 && errno == EINTR);
    if (ret <= 0) return -1;
    if (!FD_ISSET(sock, &wfds)) return -1;
    do {
	ret = send(sock, buffer, strlen(buffer), MSG_NOSIGNAL);
    } while (ret < 0 && errno == EINTR);
    if (ret < strlen(buffer)) return -1;
    return 0;
}

int clamd_recv(int sock, char *buffer, int size) {
    int ret;
    fd_set rfds;
    struct timeval tv;

    if (sock < 0) return -1;
    do {
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	tv.tv_sec = CLAMD_TIMEOUT;
	tv.tv_usec = 0;
	ret = select(sock + 1, &rfds, NULL, NULL, &tv);
    } while (ret < 0 && errno == EINTR);
    if (ret <= 0) return -1;
    if (!FD_ISSET(sock, &rfds)) return -1;
    do {
	ret = recv(sock, buffer, size - 1, MSG_NOSIGNAL);
    } while (ret < 0 && errno == EINTR);
    if (ret <= 0) return -1;
    return 0;
}

int scan(const char *unixpath) {
    struct sockaddr_in address, streamaddress;
    struct sockaddr_un unixaddress;
    char buffer[MAXLINE];
    char cmd[MAXLINE];
    int sock, streamsock;
    int optval = 1;
    socklen_t optlen = sizeof(optval);
    unsigned int port;

    if (unixpath) {
	memset(&unixaddress, 0, sizeof(unixaddress));
	strncpy(unixaddress.sun_path, unixpath, sizeof(unixaddress.sun_path) - 1);
	unixaddress.sun_family = AF_UNIX;
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
    }
    else {
	memset(&address, 0, sizeof(address));
	address.sin_addr.s_addr = inet_addr(CLAMD_ADDRESS);
	address.sin_family = AF_INET;
	address.sin_port = htons(CLAMD_PORT);
	sock = socket(AF_INET, SOCK_STREAM, 0);
    }
    if (sock < 0) return QUIT_FAIL;
    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) goto quit_fail;
    if (unixpath) {
        if (clamd_connect(sock, (struct sockaddr *) &unixaddress, sizeof(unixaddress)) < 0) {
	    printf("Could not connect to ClamAV daemon: %s\n", strerror(errno));
	    goto quit_perm;
	}
    }
    else {
        if (clamd_connect(sock, (struct sockaddr *) &address, sizeof(address)) < 0) {
	    printf("Could not connect to ClamAV daemon: %s\n", strerror(errno));
	    goto quit_perm;
	}
    }
    strncpy(cmd, "STREAM\r\n", sizeof(cmd) - 1);
    if (clamd_send(sock, cmd) < 0) goto quit_perm;
    memset(&buffer, 0, sizeof(buffer));
    if (clamd_recv(sock, buffer, sizeof(buffer)) < 0) goto quit_perm;
    if (sscanf(buffer, "PORT %u", &port) == 0) goto quit_perm;
    memset(&streamaddress, 0, sizeof(streamaddress));
    streamaddress.sin_addr.s_addr = inet_addr(CLAMD_ADDRESS);
    streamaddress.sin_family = AF_INET;
    streamaddress.sin_port = htons(port);
    streamsock = socket(AF_INET, SOCK_STREAM, 0);
    if (streamsock < 0) goto quit_fail;
    if (setsockopt(streamsock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
	close_socket(streamsock);
	goto quit_fail;
    }
    if (clamd_connect(streamsock, (struct sockaddr *) &streamaddress, sizeof(streamaddress)) < 0) {
	printf("Could not connect to ClamAV stream service: %s\n", strerror(errno));
	close_socket(streamsock);
	goto quit_perm;
    }
    strncpy(cmd, eicar, sizeof(cmd) - 1);
    if (clamd_send(streamsock, cmd) < 0) {
	close_socket(streamsock);
	goto quit_perm;
    }
    close_socket(streamsock);
    memset(&buffer, 0, sizeof(buffer));
    if (clamd_recv(sock, buffer, sizeof(buffer)) < 0) goto quit_perm;
    if (!strstr(buffer, "Eicar-Test-Signature FOUND")) goto quit_perm;
    close_socket(sock);
    return QUIT_OK;
quit_fail:
    close_socket(sock);
    return QUIT_FAIL;
quit_perm:
    close_socket(sock);
    return QUIT_PERM;
}

void usage(const char *argv0) {
    printf("usage: %s [-p socket]\n", argv0);
    exit(1);
}

int main(int argc, char *argv[]) {
    int ret, ch;
    const char *oconn = NULL;

    while ((ch = getopt(argc, argv, "p:")) != -1) {
	switch (ch) {
	case 'p':
	    oconn = optarg;
	    break;
	default:
	    usage(argv[0]);
	}
    }
    if (argc != optind) usage(argv[0]);
    signal(SIGPIPE, SIG_IGN);
    ret = scan(oconn);
    switch (ret) {
    case 0:
	printf("Looks like ClamAV daemon is not OK. Check up database integrity and restart daemon\n");
	return 0;
    case -1:
	printf("Could not verify ClamAV daemon status: socket error\n");
	break;
    default:
	break;
    }
    return 1;
}

