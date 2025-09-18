// single_file_https_server.c
// HTTPS server with runtime self-signed cert, token-gated uploads.
// Flow:
//  - GET /  -> prints a fresh random token to client and logs it serverside.
//  - Server console commands: list | enable <n> | disable <n> | help
//  - PUT /upload/<TOKEN>/<FILENAME> -> saves file (only if token is enabled).
//
// Build: gcc -O2 -Wall -Wextra -pthread -o https_server single_file_https_server.c -lssl -lcrypto
// Run:   ./https_server --port 8443 --san <PUBLIC_IP>

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

static volatile sig_atomic_t g_keep_running = 1;
static void handle_sigint(int s){ (void)s; g_keep_running = 0; }

// --------------------- tiny utils ---------------------
static void http_date(char *out, size_t n){
    time_t t = time(NULL); struct tm gm;
    gmtime_r(&t, &gm);
    strftime(out, n, "%a, %d %b %Y %H:%M:%S GMT", &gm);
}
static void die(const char *m){ perror(m); exit(EXIT_FAILURE); }

static bool is_ip(const char *s){
    struct in6_addr a6; struct in_addr a4;
    return inet_pton(AF_INET, s, &a4)==1 || inet_pton(AF_INET6, s, &a6)==1;
}

static int add_ext(X509 *cert, int nid, const char *value){
    X509V3_CTX ctx; X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char*)value);
    if(!ex) return 0;
    int ok = X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return ok;
}

static X509_NAME *mk_name(const char *cn){
    X509_NAME *name = X509_NAME_new();
    if(!name) return NULL;
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"SingleFileHTTPS", -1,-1,0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)cn, -1,-1,0);
    return name;
}

static char *build_sans(int n, char **vals){
    const char *base = "DNS:localhost,IP:127.0.0.1,IP:::1";
    size_t cap = 256 + (size_t)n*128;
    char *buf = (char*)malloc(cap);
    if(!buf) return NULL;
    snprintf(buf, cap, "%s", base);
    for(int i=0;i<n;++i){
        const char *a = vals[i];
        strncat(buf, ",", cap - strlen(buf) - 1);
        strncat(buf, is_ip(a) ? "IP:" : "DNS:", cap - strlen(buf) - 1);
        strncat(buf, a, cap - strlen(buf) - 1);
    }
    return buf;
}

static int create_listen_socket(const char *bind_ip, uint16_t port){
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd<0) die("socket");
    int on=1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family = AF_INET;
    if(!bind_ip || inet_pton(AF_INET, bind_ip, &a.sin_addr)!=1)
        a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if(bind(fd,(struct sockaddr*)&a,sizeof(a))<0) die("bind");
    if(listen(fd,64)<0) die("listen");
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    return fd;
}

static int make_self_signed(EVP_PKEY **out_key, X509 **out_crt,
                            const char *cn, const char *sans, int valid_days){
    int ok=0;
    EVP_PKEY *pkey = EVP_PKEY_new(); X509 *crt = X509_new();
    RSA *rsa = RSA_new(); BIGNUM *e = BN_new();
    if(!pkey||!crt||!rsa||!e) goto done;
    if(!BN_set_word(e, RSA_F4)) goto done;
    if(!RSA_generate_key_ex(rsa, 2048, e, NULL)) goto done;
    if(!EVP_PKEY_assign_RSA(pkey, rsa)) goto done; rsa=NULL;

    ASN1_INTEGER_set(X509_get_serialNumber(crt), (long)time(NULL));
    X509_gmtime_adj(X509_getm_notBefore(crt), 0);
    X509_gmtime_adj(X509_getm_notAfter(crt), 60L*60*24*valid_days);
    X509_set_pubkey(crt, pkey);

    X509_NAME *name = mk_name(cn?cn:"localhost");
    if(!name) goto done;
    X509_set_subject_name(crt, name);
    X509_set_issuer_name(crt, name);
    X509_NAME_free(name);

    if(!add_ext(crt, NID_basic_constraints, "CA:FALSE")) goto done;
    if(!add_ext(crt, NID_key_usage, "digitalSignature,keyEncipherment")) goto done;
    if(!add_ext(crt, NID_ext_key_usage, "serverAuth")) goto done;
    if(!add_ext(crt, NID_subject_alt_name, sans)) goto done;

    if(!X509_sign(crt, pkey, EVP_sha256())) goto done;

    *out_key = pkey; *out_crt = crt; pkey=NULL; crt=NULL; ok=1;
done:
    if(rsa) RSA_free(rsa);
    if(e) BN_free(e);
    if(pkey) EVP_PKEY_free(pkey);
    if(crt) X509_free(crt);
    return ok;
}

// --------------------- token registry ---------------------
typedef struct {
    char token[65];   // 32-byte (256-bit) hex -> 64 chars + NUL
    bool enabled;
    time_t created;
} TokenEntry;

#define MAX_TOKENS 1024
static TokenEntry g_tokens[MAX_TOKENS];
static size_t     g_token_count = 0;
static pthread_mutex_t g_tok_mx = PTHREAD_MUTEX_INITIALIZER;

static void hex_from_bytes(const unsigned char *in, size_t n, char *out){
    static const char *H="0123456789abcdef";
    for(size_t i=0;i<n;++i){ out[2*i]=H[(in[i]>>4)&0xF]; out[2*i+1]=H[in[i]&0xF]; }
    out[2*n]='\0';
}
static void new_token(char *out64){
    unsigned char r[32]; RAND_bytes(r,sizeof(r));
    hex_from_bytes(r,sizeof(r),out64);
}
static int add_token(const char *tok){
    pthread_mutex_lock(&g_tok_mx);
    if(g_token_count>=MAX_TOKENS){ pthread_mutex_unlock(&g_tok_mx); return -1; }
    strncpy(g_tokens[g_token_count].token, tok, sizeof(g_tokens[g_token_count].token));
    g_tokens[g_token_count].token[64]='\0';
    g_tokens[g_token_count].enabled=false;
    g_tokens[g_token_count].created=time(NULL);
    int id = (int)g_token_count + 1; // 1-based for UX
    ++g_token_count;
    pthread_mutex_unlock(&g_tok_mx);
    return id;
}
static int find_token_index(const char *tok){
    int idx=-1;
    pthread_mutex_lock(&g_tok_mx);
    for(size_t i=0;i<g_token_count;++i){
        if(strcmp(g_tokens[i].token,tok)==0){ idx=(int)i; break; }
    }
    pthread_mutex_unlock(&g_tok_mx);
    return idx;
}
static void print_tokens(void){
    pthread_mutex_lock(&g_tok_mx);
    fprintf(stderr, "\n== Active tokens ==\n");
    for(size_t i=0;i<g_token_count;++i){
        char ts[32]; struct tm gm; gmtime_r(&g_tokens[i].created,&gm);
        strftime(ts,sizeof(ts),"%H:%M:%S", &gm);
        fprintf(stderr, "  %zu) %s  [%s]  @%sZ\n", i+1,
                g_tokens[i].token, g_tokens[i].enabled?"ENABLED":"disabled", ts);
    }
    if(g_token_count==0) fprintf(stderr,"  (none)\n");
    fprintf(stderr, "Commands: list | enable <#> | disable <#> | help\n\n");
    pthread_mutex_unlock(&g_tok_mx);
}
static bool token_enabled(const char *tok){
    bool ok=false;
    pthread_mutex_lock(&g_tok_mx);
    int idx = find_token_index(tok);
    if(idx>=0) ok = g_tokens[idx].enabled;
    pthread_mutex_unlock(&g_tok_mx);
    return ok;
}

// admin thread: read stdin commands
static void *admin_thread(void *arg){
    (void)arg;
    char line[128];
    fprintf(stderr, "Admin console ready. Type: list | enable <#> | disable <#> | help\n");
    while(g_keep_running && fgets(line,sizeof(line), stdin)){
        // strip nl
        size_t L=strlen(line); if(L && (line[L-1]=='\n'||line[L-1]=='\r')) line[L-1]=0;
        if(strcmp(line,"list")==0){ print_tokens(); continue; }
        if(strncmp(line,"enable ",7)==0){
            int n=atoi(line+7);
            if(n<=0){ fprintf(stderr,"bad id\n"); continue; }
            pthread_mutex_lock(&g_tok_mx);
            if((size_t)n>=1 && (size_t)n<=g_token_count){ g_tokens[n-1].enabled=true; fprintf(stderr,"enabled #%d\n", n); }
            else fprintf(stderr,"no such id\n");
            pthread_mutex_unlock(&g_tok_mx);
            continue;
        }
        if(strncmp(line,"disable ",8)==0){
            int n=atoi(line+8);
            if(n<=0){ fprintf(stderr,"bad id\n"); continue; }
            pthread_mutex_lock(&g_tok_mx);
            if((size_t)n>=1 && (size_t)n<=g_token_count){ g_tokens[n-1].enabled=false; fprintf(stderr,"disabled #%d\n", n); }
            else fprintf(stderr,"no such id\n");
            pthread_mutex_unlock(&g_tok_mx);
            continue;
        }
        if(strcmp(line,"help")==0){
            fprintf(stderr,"Commands: list | enable <#> | disable <#> | help\n");
            continue;
        }
        fprintf(stderr,"unknown command\n");
    }
    return NULL;
}

// --------------------- main ---------------------
static void usage(const char *argv0){
    fprintf(stderr, "Usage: %s [--port N] [--addr IP] [--cn NAME] [--san VALUE ...]\n", argv0);
    fprintf(stderr, "Defaults: --port 8443, --addr 0.0.0.0, --cn localhost; SANs include localhost,127.0.0.1,::1\n");
}

int main(int argc, char **argv){
    const char *bind_ip="0.0.0.0"; uint16_t port=8443; const char *cn="localhost"; int valid_days=365*5;
    int i=1, san_count=0; char *san_vals[64];

    signal(SIGPIPE, SIG_IGN); signal(SIGINT, handle_sigint);

    while(i<argc){
        if(!strcmp(argv[i],"--port")&&i+1<argc){ port=(uint16_t)atoi(argv[++i]); }
        else if(!strcmp(argv[i],"--addr")&&i+1<argc){ bind_ip=argv[++i]; }
        else if(!strcmp(argv[i],"--cn")  &&i+1<argc){ cn=argv[++i]; }
        else if(!strcmp(argv[i],"--san") &&i+1<argc && san_count<64){ san_vals[san_count++]=argv[++i]; }
        else if(!strcmp(argv[i],"-h")||!strcmp(argv[i],"--help")){ usage(argv[0]); return 0; }
        else { fprintf(stderr,"Unknown arg: %s\n", argv[i]); usage(argv[0]); return 1; }
        ++i;
    }

    OPENSSL_init_ssl(0,NULL); SSL_load_error_strings();
    char *sans=build_sans(san_count,san_vals); if(!sans){ fprintf(stderr,"OOM\n"); return 1; }

    EVP_PKEY *key=NULL; X509 *crt=NULL;
    if(!make_self_signed(&key,&crt,cn,sans,valid_days)){ fprintf(stderr,"cert fail\n"); free(sans); return 1; }

    SSL_CTX *ctx=SSL_CTX_new(TLS_server_method()); if(!ctx) die("SSL_CTX_new");
#ifdef SSL_CTX_set_ecdh_auto
    SSL_CTX_set_ecdh_auto(ctx,1);
#endif
#ifdef TLS1_2_VERSION
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#endif
    if(SSL_CTX_use_certificate(ctx, crt)!=1) die("use cert");
    if(SSL_CTX_use_PrivateKey(ctx, key)!=1) die("use key");
    if(SSL_CTX_check_private_key(ctx)!=1) die("key check");
    X509_free(crt); EVP_PKEY_free(key); free(sans);

    // admin thread
    pthread_t th; pthread_create(&th, NULL, admin_thread, NULL);

    int listen_fd=create_listen_socket(bind_ip,port);
    printf("HTTPS listening on https://%s:%u (Ctrl+C to stop)\n", bind_ip, port);

    mkdir("/workspace/uploads", 0700);

    while(g_keep_running){
        struct sockaddr_in cli; socklen_t clilen=sizeof(cli);
        int fd=accept(listen_fd,(struct sockaddr*)&cli,&clilen);
        if(fd<0){ if(errno==EINTR&&!g_keep_running) break; perror("accept"); continue; }
        int on=1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

        SSL *ssl=SSL_new(ctx); if(!ssl){ close(fd); continue; }
        SSL_set_fd(ssl, fd);
        if(SSL_accept(ssl)!=1){ ERR_print_errors_fp(stderr); SSL_free(ssl); close(fd); continue; }

        // read request
        char req[8192];
        int n=SSL_read(ssl, req, (int)sizeof(req)-1);
        if(n<0){ n=0; }
        req[n]='\0';

        // parse first line
        char method[8], path[1024];
        if(sscanf(req,"%7s %1023s", method, path)!=2){
            const char *bad="HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
            SSL_write(ssl,bad,(int)strlen(bad)); goto done;
        }

        // --------------------- PUT /upload/<TOKEN>/<FILENAME> ---------------------
        if(strcmp(method,"PUT")==0 && strncmp(path,"/upload/",8)==0){
            const char *rest = path+8;
            const char *slash = strchr(rest,'/');
            if(!slash){
                const char *bad="HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
                SSL_write(ssl,bad,(int)strlen(bad)); goto done;
            }
            char token[65]; char fname[512];
            size_t toklen = (size_t)(slash-rest);
            if(toklen==0 || toklen>64){ const char *bad="HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"; SSL_write(ssl,bad,(int)strlen(bad)); goto done; }
            memcpy(token, rest, toklen); token[toklen]='\0';
            snprintf(fname,sizeof(fname),"%s", slash+1);

            // filename sanitize
            if(strstr(fname,"..") || strchr(fname,'/')){
                const char *bad="HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
                SSL_write(ssl,bad,(int)strlen(bad)); goto done;
            }
            if(!token_enabled(token)){
                const char *forb="HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
                SSL_write(ssl,forb,(int)strlen(forb)); goto done;
            }

            // find Content-Length
            const char *cl = strcasestr(req, "\nContent-Length:");
            if(!cl){
                const char *lenreq="HTTP/1.1 411 Length Required\r\nConnection: close\r\n\r\n";
                SSL_write(ssl,lenreq,(int)strlen(lenreq)); goto done;
            }
            long content_len = strtol(cl+16, NULL, 10);
            if(content_len<=0 || content_len > 25*1024*1024){
                const char *toolarge="HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n";
                SSL_write(ssl,toolarge,(int)strlen(toolarge)); goto done;
            }

            char *hdr_end = strstr(req,"\r\n\r\n");
            if(!hdr_end){
                const char *bad="HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
                SSL_write(ssl,bad,(int)strlen(bad)); goto done;
            }
            size_t header_len = (size_t)(hdr_end + 4 - req);

            char fullpath[1024];
            snprintf(fullpath,sizeof(fullpath),"/workspace/uploads/%s", fname);
            FILE *fp=fopen(fullpath,"wb");
            if(!fp){
                const char *err="HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
                SSL_write(ssl,err,(int)strlen(err)); goto done;
            }

            // write any body already read
            size_t in_buf = (size_t)n - header_len;
            if(in_buf>0){
                if(fwrite(hdr_end+4,1,in_buf,fp)!=in_buf){ fclose(fp);
                    const char *err="HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
                    SSL_write(ssl,err,(int)strlen(err)); goto done;
                }
            }
            long remaining = content_len - (long)in_buf;
            char buf[16384];
            while(remaining>0){
                int r = SSL_read(ssl, buf, (int)((remaining<(long)sizeof(buf))?remaining:(long)sizeof(buf)));
                if(r<=0){ fclose(fp);
                    const char *err="HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
                    SSL_write(ssl,err,(int)strlen(err)); goto done;
                }
                if(fwrite(buf,1,(size_t)r,fp)!=(size_t)r){ fclose(fp);
                    const char *err="HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
                    SSL_write(ssl,err,(int)strlen(err)); goto done;
                }
                remaining -= r;
            }
            fclose(fp);

            char ok[512];
            int m = snprintf(ok,sizeof(ok),
                "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nSaved to %s\n",
                fullpath);
            SSL_write(ssl,ok,m);
            goto done;
        }

        // --------------------- GET /health ---------------------
        if(strcmp(method,"GET")==0 && strcmp(path,"/health")==0){
            const char *h="HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nOK\n";
            SSL_write(ssl,h,(int)strlen(h)); goto done;
        }

        // --------------------- GET / -> issue token ---------------------
        if(strcmp(method,"GET")==0 && strcmp(path,"/")==0){
            char tok[65]; new_token(tok);
            int id = add_token(tok);

            // log / show list entry serverside
            fprintf(stderr,"New token #%d: %s\n", id, tok);
            print_tokens();

            // show token to client with simple instructions
            char datebuf[64]; http_date(datebuf,sizeof(datebuf));
            char body[1024];
            snprintf(body,sizeof(body),
                "Hello from a single-file HTTPS server!\n"
                "token: %s\n\n"
                "Ask the server operator to 'enable %d' to allow uploads.\n"
                "Then upload with:\n"
                "  curl -k -T ./FILE https://<PUBLIC_IP>:<EXTERNAL_PORT>/upload/%s/FILE\n",
                tok, id, tok);
            char resp[1600];
            int blen=(int)strlen(body);
            int m=snprintf(resp,sizeof(resp),
                "HTTP/1.1 200 OK\r\nDate: %s\r\nServer: single-file-https/1\r\n"
                "Content-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
                datebuf, blen, body);
            SSL_write(ssl,resp,m);
            goto done;
        }

        // --------------------- fallback ---------------------
        {
            const char *bad="HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
            SSL_write(ssl,bad,(int)strlen(bad));
        }

    done:
        SSL_shutdown(ssl); SSL_free(ssl); close(fd);
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    g_keep_running=0;
    pthread_cancel(th); pthread_join(th,NULL);
    return 0;
}
