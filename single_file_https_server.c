// single_file_https_server.c
// Minimal single-file HTTPS server with runtime self-signed cert.
// No public CA / Let's Encrypt needed. Good for demos, local dev, or
// controlled environments where you accept a self-signed cert.
//
// Default behavior: serve HTTPS, but DO NOT print or write the private key by default.
// You can optionally write PEM files via --write-pem <prefix>.
//
// Build (Linux/macOS):
//   gcc -O2 -Wall -Wextra -o https_server single_file_https_server.c -lssl -lcrypto
//
// Usage:
//   ./https_server [--port N] [--addr IP] [--cn NAME] [--san VALUE ...]
//                  [--valid-days D] [--write-pem PREFIX]
//                  [--print-cert] [--print-key]
//
// Examples:
//   ./https_server                                 # :8443, SANs: localhost,127.0.0.1,::1
//   ./https_server --port 8443 --san 38.80.152.249 # add public IP SAN to avoid name mismatch
//   ./https_server --addr 0.0.0.0 --port 443       # bind privileged port (needs caps/root)
//   ./https_server --write-pem server              # writes server.crt and server.key with 0600
//
// NOTE: single-threaded, blocking, tiny HTTP/1.1 responder ("Hello" + /health).

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
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

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static int create_listen_socket(const char *bind_ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");

    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
        die("setsockopt SO_REUSEADDR");
#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0)
        ; // ignore failures
#endif

    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (bind_ip && inet_pton(AF_INET, bind_ip, &addr.sin_addr) == 1) {
        // ok
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        die("bind");
    if (listen(fd, 64) < 0)
        die("listen");

    // Set TCP_NODELAY for snappier writes (optional)
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    return fd;
}

static X509_NAME *dn(const char *common_name) {
    X509_NAME *name = X509_NAME_new();
    if (!name) return NULL;
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"SingleFileHTTPS", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)common_name, -1, -1, 0);
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

static bool is_ip_literal(const char *s) {
    struct in6_addr a6; struct in_addr a4;
    return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1;
}

static int write_file_0600(const char *path, const unsigned char *data, size_t len) {
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) return 0;
    ssize_t w = write(fd, data, len);
    close(fd);
    return w == (ssize_t)len;
}

// Creates a 2048-bit RSA key and a self-signed X.509 certificate.
static int create_self_signed(EVP_PKEY **out_pkey, X509 **out_cert,
                              const char *common_name, const char *sans,
                              int valid_days) {
    int ret = 0;
    EVP_PKEY *pkey = NULL; X509 *x509 = NULL; RSA *rsa = NULL; BIGNUM *e = NULL;

    pkey = EVP_PKEY_new();
    if (!pkey) goto end;

    rsa = RSA_new(); e = BN_new(); if (!rsa || !e) goto end;
    if (!BN_set_word(e, RSA_F4)) goto end;
    if (!RSA_generate_key_ex(rsa, 2048, e, NULL)) goto end;
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) goto end; // pkey owns rsa now
    rsa = NULL;

    x509 = X509_new();
    if (!x509) goto end;

    ASN1_INTEGER_set(X509_get_serialNumber(x509), (long)time(NULL));
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 60L*60*24*valid_days);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = dn(common_name);
    if (!name) goto end;
    X509_set_subject_name(x509, name);
    X509_set_issuer_name(x509, name);
    X509_NAME_free(name);

    if (!add_ext(x509, NID_basic_constraints, "CA:FALSE")) goto end;
    if (!add_ext(x509, NID_key_usage, "digitalSignature,keyEncipherment")) goto end;
    if (!add_ext(x509, NID_ext_key_usage, "serverAuth")) goto end;
    if (!add_ext(x509, NID_subject_alt_name, sans)) goto end;

    if (!X509_sign(x509, pkey, EVP_sha256())) goto end;

    *out_pkey = pkey; *out_cert = x509; pkey = NULL; x509 = NULL;
    ret = 1;

end:
    if (rsa) RSA_free(rsa);
    if (e) BN_free(e);
    if (pkey) EVP_PKEY_free(pkey);
    if (x509) X509_free(x509);
    return ret;
}

static int pem_to_memory(EVP_PKEY *pkey, X509 *cert, unsigned char **crt_buf, size_t *crt_len,
                         unsigned char **key_buf, size_t *key_len) {
    BIO *bio_crt = BIO_new(BIO_s_mem());
    BIO *bio_key = BIO_new(BIO_s_mem());
    if (!bio_crt || !bio_key) goto end;

    if (!PEM_write_bio_X509(bio_crt, cert)) goto end;
    if (!PEM_write_bio_PrivateKey(bio_key, pkey, NULL, NULL, 0, NULL, NULL)) goto end;

    *crt_len = BIO_get_mem_data(bio_crt, crt_buf);
    *key_len = BIO_get_mem_data(bio_key, key_buf);
    // NOTE: The returned pointers are internal to BIO buffers; we will copy them before BIO_free.

    BIO_free(bio_crt); BIO_free(bio_key);
    return 1;
end:
    if (bio_crt) BIO_free(bio_crt);
    if (bio_key) BIO_free(bio_key);
    return 0;
}

static char *build_sans_from_args(int san_count, char **sans_vals) {
    // Always include localhost/loopbacks
    const char *base = "DNS:localhost,IP:127.0.0.1,IP:::1";
    size_t cap = 256 + (size_t)san_count * 128;
    char *buf = (char*)malloc(cap);
    if (!buf) return NULL;
    snprintf(buf, cap, "%s", base);
    for (int i = 0; i < san_count; ++i) {
        const char *a = sans_vals[i];
        strncat(buf, ",", cap - strlen(buf) - 1);
        if (is_ip_literal(a)) strncat(buf, "IP:", cap - strlen(buf) - 1);
        else                  strncat(buf, "DNS:", cap - strlen(buf) - 1);
        strncat(buf, a, cap - strlen(buf) - 1);
    }
    return buf;
}

static void http_date(char *out, size_t n) {
    time_t t = time(NULL); struct tm gm;
    gmtime_r(&t, &gm);
    strftime(out, n, "%a, %d %b %Y %H:%M:%S GMT", &gm);
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s [--port N] [--addr IP] [--cn NAME] [--san VALUE ...]
"
        "           [--valid-days D] [--write-pem PREFIX] [--print-cert] [--print-key]
"
        "
Defaults: --port 8443, --addr 0.0.0.0, --cn localhost, SANs include localhost,127.0.0.1,::1
",
        argv0);
}

int main(int argc, char **argv) {
    // Defaults
    const char *bind_ip = "0.0.0.0";
    uint16_t port = 8443;
    const char *cn = "localhost";
    int valid_days = 365*5;
    const char *pem_prefix = NULL;
    bool print_cert = false, print_key = false;

    // Basic arg parsing
    int i = 1; int san_count = 0; char *san_vals[64];
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_sigint);

    while (i < argc) {
        if (!strcmp(argv[i], "--port") && i+1 < argc) { port = (uint16_t)atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--addr") && i+1 < argc) { bind_ip = argv[++i]; }
        else if (!strcmp(argv[i], "--cn") && i+1 < argc) { cn = argv[++i]; }
        else if (!strcmp(argv[i], "--san") && i+1 < argc && san_count < 64) { san_vals[san_count++] = argv[++i]; }
        else if (!strcmp(argv[i], "--valid-days") && i+1 < argc) { valid_days = atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--write-pem") && i+1 < argc) { pem_prefix = argv[++i]; }
        else if (!strcmp(argv[i], "--print-cert")) { print_cert = true; }
        else if (!strcmp(argv[i], "--print-key")) { print_key = true; }
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "Unknown arg: %s
", argv[i]); usage(argv[0]); return 1; }
        ++i;
    }

    // Initialize OpenSSL
    OPENSSL_init_ssl(0, NULL);
    SSL_load_error_strings();

    char *sans = build_sans_from_args(san_count, san_vals);
    if (!sans) { fprintf(stderr, "Out of memory building SANs.
"); return 1; }

    EVP_PKEY *pkey = NULL; X509 *cert = NULL;
    if (!create_self_signed(&pkey, &cert, cn, sans, valid_days)) {
        fprintf(stderr, "Failed to create self-signed cert.
");
        free(sans);
        return 1;
    }

    // Optionally write PEMs to disk (0600)
    if (pem_prefix) {
        unsigned char *crt_mem = NULL, *key_mem = NULL; size_t crt_len = 0, key_len = 0;
        BIO *bio_crt = BIO_new(BIO_s_mem());
        BIO *bio_key = BIO_new(BIO_s_mem());
        if (!bio_crt || !bio_key) die("BIO_new");
        if (!PEM_write_bio_X509(bio_crt, cert)) die("write crt");
        if (!PEM_write_bio_PrivateKey(bio_key, pkey, NULL, NULL, 0, NULL, NULL)) die("write key");
        size_t n1 = BIO_get_mem_data(bio_crt, &crt_mem);
        size_t n2 = BIO_get_mem_data(bio_key, &key_mem);
        char crt_path[512], key_path[512];
        snprintf(crt_path, sizeof(crt_path), "%s.crt", pem_prefix);
        snprintf(key_path, sizeof(key_path), "%s.key", pem_prefix);
        if (!write_file_0600(crt_path, crt_mem, n1)) die("write crt file");
        if (!write_file_0600(key_path, key_mem, n2)) die("write key file");
        BIO_free(bio_crt); BIO_free(bio_key);
        fprintf(stderr, "Wrote %s and %s (0600)
", crt_path, key_path);
    }

    // Optionally print PEMs to stdout
    if (print_cert) {
        PEM_write_X509(stdout, cert);
    }
    if (print_key) {
        PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die("SSL_CTX_new");
    SSL_CTX_set_ecdh_auto(ctx, 1);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate(ctx, cert) != 1) die("use cert");
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) die("use key");
    if (SSL_CTX_check_private_key(ctx) != 1) die("key check");

    free(sans);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    int listen_fd = create_listen_socket(bind_ip, port);
    printf("HTTPS listening on https://%s:%u (Ctrl+C to stop)
", bind_ip, port);

    // Prepare a tiny HTTP response
    const char *body = "Hello from a single-file HTTPS server!
";
    char datebuf[64]; http_date(datebuf, sizeof(datebuf));
    char resp[1024];
    int body_len = (int)strlen(body);

    // Main accept loop
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

        // Read a bit of the request (very small, just to distinguish /health)
        char buf[2048]; int n = SSL_read(ssl, buf, sizeof(buf)-1);
        if (n < 0) n = 0; buf[n] = '
