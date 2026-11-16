#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *identity, *cipher_name;
static unsigned char key[32];
static unsigned int client_psk(WOLFSSL *ssl, const char *hint, char *id,
    unsigned int id_size, unsigned char *psk, unsigned int key_size,
    const char **cipher) {
    (void)ssl; (void)hint;
    if (strlen(identity) + 1 > id_size || key_size < sizeof(key)) return 0;
    strcpy(id, identity); memcpy(psk, key, sizeof(key)); *cipher = cipher_name;
    return sizeof(key);
}
static unsigned int server_psk(WOLFSSL *ssl, const char *id,
    unsigned char *psk, unsigned int key_size, const char **cipher) {
    (void)ssl;
    if (strcmp(id, identity) || key_size < sizeof(key)) return 0;
    memcpy(psk, key, sizeof(key)); *cipher = cipher_name;
    return sizeof(key);
}
static void fail(WOLFSSL *ssl, const char *step, int ret) {
    fprintf(stderr, "%s: ret=%d error=%d\n", step, ret, wolfSSL_get_error(ssl, ret));
    exit(1);
}
int main(int argc, char **argv) {
    if (argc != 7) return 2;
    int server = !strcmp(argv[1], "server");
    int port = atoi(argv[2]); identity = argv[3]; cipher_name = argv[5];
    if (strlen(argv[4]) != 64 || port < 1 || port > 65535) return 2;
    for (int i = 0; i < 32; ++i) { unsigned int v; if (sscanf(argv[4]+2*i, "%2x", &v)!=1) return 2; key[i]=(unsigned char)v; }
    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(server ? wolfDTLSv1_3_server_method() : wolfDTLSv1_3_client_method());
    if (!ctx || wolfSSL_CTX_set_cipher_list(ctx, cipher_name) != WOLFSSL_SUCCESS) return 3;
    if (server) wolfSSL_CTX_set_psk_server_tls13_callback(ctx, server_psk);
    else wolfSSL_CTX_set_psk_client_tls13_callback(ctx, client_psk);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct timeval timeout = {12, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in peer = {0}; peer.sin_family=AF_INET; peer.sin_addr.s_addr=htonl(INADDR_LOOPBACK); peer.sin_port=htons(port);
    if (server) {
        if (bind(fd, (struct sockaddr *)&peer, sizeof(peer))) return 4;
        puts("READY"); fflush(stdout);
        socklen_t len=sizeof(peer); unsigned char peek[1];
        if (recvfrom(fd, peek, sizeof(peek), MSG_PEEK, (struct sockaddr *)&peer, &len) < 0) return 5;
    }
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) return 6;
    WOLFSSL *ssl=wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, fd);
    wolfSSL_dtls_set_peer(ssl, &peer, sizeof(peer));
    int ret = server ? wolfSSL_accept(ssl) : wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS) fail(ssl, "handshake", ret);
    puts("HANDSHAKE"); fflush(stdout);
    unsigned char b[2048];
    for (int i=0; i<3; ++i) {
        int size = (i==0 ? 1 : i==1 ? 513 : 1200);
        if (!server) {
            for (int j=0; j<size; ++j) b[j]=(unsigned char)(j+i);
            ret=wolfSSL_write(ssl,b,size); if (ret!=size) fail(ssl,"write",ret);
        }
        ret=wolfSSL_read(ssl,b,sizeof(b));
        if (ret<=0) fail(ssl,"read",ret);
        if (server) {
            int n=ret; ret=wolfSSL_write(ssl,b,n); if(ret!=n) fail(ssl,"echo",ret);
        } else {
            if(ret!=size) return 7;
            for(int j=0;j<size;++j) if(b[j]!=(unsigned char)(j+i)) return 8;
        }
        if (i==0 && !strcmp(argv[6],"psk-dhe-ku")) {
            ret=wolfSSL_update_keys(ssl); if(ret!=WOLFSSL_SUCCESS) fail(ssl,"key update",ret);
        }
    }
    puts("PASS"); fflush(stdout);
    /* argv[6] keeps the reference invocation explicit about its PSK-DHE profile. */
    if (strcmp(argv[6],"psk-dhe") && strcmp(argv[6],"psk-dhe-ku")) return 9;
    wolfSSL_free(ssl); wolfSSL_CTX_free(ctx); close(fd); wolfSSL_Cleanup();
    return 0;
}
