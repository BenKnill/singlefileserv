// single_file_https_server.c
// Minimal single-file HTTPS server with a runtime self-signed certificate.
// Build: gcc -O2 -Wall -Wextra -o https_server single_file_https_server.c -lssl -lcrypto
// Usage: ./https_server --port 8443 --san 203.0.113.10
// Notes: single-threaded, blocking; for demos/dev. Browsers will warn on self-signed certs.

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

static volatile sig_atomic_t g_keep_running = 1;
static void handle_sigint(int signo) { (void)signo; g_keep_running = 0; }

static void die(const char *msg) { perror(msg); exit(EXIT_FAILURE); }

static void http_date(char *out, size_t n) {
    time_t t = time(NULL); struct tm gm;
    gmtime_r(&t, &gm);
    strftime(out, n, "%a, %d %b %Y %H:%M:%S GMT", &gm);
}

static int create_listen_socket(const char *bind_ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (!bind_ip || inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1)
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) die("bind");
    if (listen(fd, 64) < 0) die("listen");
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    return fd;
}

static X509_NAME *mk_name(const char *cn) {
    X509_NAME *name = X509_NAME_new();
    if (!name) return NULL;
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"SingleFileHTTPS", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 0);
    return name;
}

static int add_ext(X509 *cert, int nid, const char *value) {
    X509V3_CTX ctx; X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char*)value);
    if (!ex) return 0;
    int ok = X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return ok;
}

static bool is_ip(const char *s) {
    struct in6_addr a6; struct in_addr a4;
    return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1;
}

static char *build_sans(int n, char **vals) {
    const char *base = "DNS:localhost,IP:127.0.0.1,IP:::1";
    size_t cap = 256 + (size_t)n * 128;
    char *buf = (char*)malloc(cap);
    if (!buf) return NULL;
    snprintf(buf, cap, "%s", base);
    for (int i = 0; i < n; ++i) {
        const char *a = vals[i];
        strncat(buf, ",", cap - strlen(buf) - 1);
        strncat(buf, is_ip(a) ? "IP:" : "DNS:", cap - strlen(buf) - 1);
        strncat(buf, a, cap - strlen(buf) - 1);
    }
    return buf;
}

static int make_self_signed(EVP_PKEY **out_key, X509 **out_crt,
                            const char *cn, const char *sans, int valid_days) {
    int ok = 0;
    EVP_PKEY *pkey = EVP_PKEY_new(); X509 *crt = X509_new();
    RSA *rsa = RSA_new(); BIGNUM *e = BN_new();
    if (!pkey || !crt || !rsa || !e) goto done;
    if (!BN_set_word(e, RSA_F4)) goto done;
    if (!RSA_generate_key_ex(rsa, 2048, e, NULL)) goto done;
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) goto done; // pkey owns rsa now
    rsa = NULL;

    ASN1_INTEGER_set(X509_get_serialNumber(crt), (long)time(NULL));
    X509_gmtime_adj(X509_getm_notBefore(crt), 0);
    X509_gmtime_adj(X509_getm_notAfter(crt), 60L*60*24*valid_days);
    X509_set_pubkey(crt, pkey);

    X509_NAME *name = mk_name(cn ? cn : "localhost");
    if (!name) goto done;
    X509_set_subject_name(crt, name);
    X509_set_issuer_name(crt, name);
    X509_NAME_free(name);

    if (!add_ext(crt, NID_basic_constraints, "CA:FALSE")) goto done;
    if (!add_ext(crt, NID_key_usage, "digitalSignature,keyEncipherment")) goto done;
    if (!add_ext(crt, NID_ext_key_usage, "serverAuth")) goto done;
    if (!add_ext(crt, NID_subject_alt_name, sans)) goto done;

    if (!X509_sign(crt, pkey, EVP_sha256())) goto done;

    *out_key = pkey; *out_crt = crt; pkey = NULL; crt = NULL; ok = 1;

done:
    if (rsa) RSA_free(rsa);
    if (e) BN_free(e);
    if (pkey) EVP_PKEY_free(pkey);
    if (crt) X509_free(crt);
    return ok;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s [--port N] [--addr IP] [--cn NAME] [--san VALUE ...]\n", argv0);
    fprintf(stderr, "Defaults: --port 8443, --addr 0.0.0.0, --cn localhost; SANs include localhost,127.0.0.1,::1\n");
}

int main(int argc, char **argv) {
    const char *bind_ip = "0.0.0.0";
    uint16_t port = 8443;
    const char *cn = "localhost";
    int valid_days = 365*5;

    int i = 1, san_count = 0; char *san_vals[64];
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_sigint);

    while (i < argc) {
        if (!strcmp(argv[i], "--port") && i+1 < argc)      { port = (uint16_t)atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--addr") && i+1 < argc)  { bind_ip = argv[++i]; }
        else if (!strcmp(argv[i], "--cn") && i+1 < argc)    { cn = argv[++i]; }
        else if (!strcmp(argv[i], "--san") && i+1 < argc && san_count < 64) { san_vals[san_count++] = argv[++i]; }
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "Unknown arg: %s\n", argv[i]); usage(argv[0]); return 1; }
        ++i;
    }

    OPENSSL_init_ssl(0, NULL);
    SSL_load_error_strings();

    char *sans = build_sans(san_count, san_vals);
    if (!sans) { fprintf(stderr, "Out of memory building SANs.\n"); return 1; }

    EVP_PKEY *key = NULL; X509 *crt = NULL;
    if (!make_self_signed(&key, &crt, cn, sans, valid_days)) {
        fprintf(stderr, "Failed to create self-signed cert.\n");
        free(sans);
        return 1;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die("SSL_CTX_new");
#ifdef SSL_CTX_set_ecdh_auto
    SSL_CTX_set_ecdh_auto(ctx, 1);
#endif
#ifdef TLS1_2_VERSION
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#endif
    if (SSL_CTX_use_certificate(ctx, crt) != 1) die("use cert");
    if (SSL_CTX_use_PrivateKey(ctx, key) != 1) die("use key");
    if (SSL_CTX_check_private_key(ctx) != 1) die("key check");
    X509_free(crt); EVP_PKEY_free(key); free(sans);

    int listen_fd = create_listen_socket(bind_ip, port);
    printf("HTTPS listening on https://%s:%u (Ctrl+C to stop)\n", bind_ip, port);

    const char *body = "Hello from a single-file HTTPS server!\n";

    while (g_keep_running) {
        struct sockaddr_in cli; socklen_t clilen = sizeof(cli);
        int fd = accept(listen_fd, (struct sockaddr*)&cli, &clilen);
        if (fd < 0) {
            if (errno == EINTR && !g_keep_running) break;
            perror("accept");
            continue;
        }
        int on = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

        SSL *ssl = SSL_new(ctx);
        if (!ssl) { close(fd); continue; }
        SSL_set_fd(ssl, fd);

        if (SSL_accept(ssl) != 1) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl); close(fd); continue;
        }

        char buf[2048];
        int n = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (n < 0) { n = 0; }
        buf[n] = '\0';

        bool is_health = (n >= 12 && strstr(buf, "GET /health") == buf);

        char datebuf[64]; http_date(datebuf, sizeof(datebuf));
        char resp[1024];
        if (is_health) {
            const char *ok = "OK\n";
            snprintf(resp, sizeof(resp),
                "HTTP/1.1 200 OK\r\n"
                "Date: %s\r\n"
                "Server: single-file-https/1\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n\r\n%s",
                datebuf, strlen(ok), ok);
        } else {
            int blen = (int)strlen(body);
            snprintf(resp, sizeof(resp),
                "HTTP/1.1 200 OK\r\n"
                "Date: %s\r\n"
                "Server: single-file-https/1\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %d\r\n"
                "Connection: close\r\n\r\n%s",
                datebuf, blen, body);
        }

        SSL_write(ssl, resp, (int)strlen(resp));
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}
