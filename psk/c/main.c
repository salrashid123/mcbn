
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/*
Simple demo of TLS Preshared Keys using openssl and c

# apt-get install libcurl4-openssl-dev libssl-dev
gcc main.c -lcrypto -lssl -o main
./main

export PSK=6d1bbd1e6235c9d9ec8cdbdf9b32d4d08304a7f305f7c6c67775130d914f4dc4
export PSK_HEX=`echo  -n $PSK |   xxd -p -c 64`
openssl s_client -psk $PSK_HEX -psk_identity Client1 \
  -tls1_3 -connect localhost:8081 
*/

#define PSK_ID "Client1"
#define PSK_KEY "6d1bbd1e6235c9d9ec8cdbdf9b32d4d08304a7f305f7c6c67775130d914f4dc4"

unsigned int tls13_psk_out_of_bound_serv_cb(SSL *ssl, const char *id,
                                            unsigned char *psk,
                                            unsigned int max_psk_len)
{
    if (strcmp(PSK_ID, id) != 0) {
        printf("Unknown Client's PSK ID\n");
        goto err;
    }
    if (strlen(PSK_KEY) > max_psk_len) {
        printf("Insufficient buffer size to copy PSK_KEY\n");
        goto err;
    }
    memcpy(psk, PSK_KEY, strlen(PSK_KEY));
    return strlen(PSK_KEY);
err:
    return 0;
}

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}


SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main(int argc, char **argv)
{
    int sock;
    SSL_CTX *ctx;

    /* Ignore broken pipe signals */
    signal(SIGPIPE, SIG_IGN);

    ctx = create_context();
    sock = create_socket(8081);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "test\n";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        SSL_set_psk_server_callback(ssl, tls13_psk_out_of_bound_serv_cb);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            SSL_write(ssl, reply, strlen(reply));
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
}