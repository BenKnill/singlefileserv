// single_file_https_server.c
// HTTPS server with runtime self-signed cert + token-gated directory uploads + drag&drop UI.
// - GET /              -> serves an HTML page showing Token #N and the token value, with drag&drop uploader
// - Server console     -> list | enable <#> | disable <#> | help
// - PUT /upload/<TOKEN>/<ANY/REL/OR/ABS/PATH>  -> writes under /workspace (mkdir -p), only if that token is enabled
//
// Build: gcc -O2 -Wall -Wextra -pthread -o https_server single_file_https_server.c -lssl -lcrypto
// Run  : ./https_server --port 8443 --san <PUBLIC_IP>

#define _GNU_SOURCE 1              /* for strcasestr on glibc */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>               /* strcasestr */
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

/* ---------------- util ---------------- */

static volatile sig_atomic_t g_keep_running = 1;
static void handle_sigint(int s){ (void)s; g_keep_running = 0; }

static void die(const char *m){ perror(m); exit(EXIT_FAILURE); }

static void http_date(char *out, size_t n){
    time_t t = time(NULL); struct tm gm;
    gmtime_r(&t, &gm);
    strftime(out, n, "%a, %d %b %Y %H:%M:%S GMT", &gm);
}

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
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"SingleFileHTTPS", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 0);
    return name;
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

/* ---------------- cert ---------------- */

static int make_self_signed(EVP_PKEY **out_key, X509 **out_crt,
                            const char *cn, const char *sans, int valid_days){
    int ok=0;
    EVP_PKEY *pkey = EVP_PKEY_new(); X509 *crt = X509_new();
    RSA *rsa = RSA_new(); BIGNUM *e = BN_new();
    if(!pkey||!crt||!rsa||!e) goto done;
    if(!BN_set_word(e, RSA_F4)) goto done;
    if(!RSA_generate_key_ex(rsa, 2048, e, NULL)) goto done;
    if(!EVP_PKEY_assign_RSA(pkey, rsa)) goto done;
    rsa = NULL;

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

/* ---------------- token registry ---------------- */

typedef struct {
    char  token[65];   // 32 bytes -> 64 hex chars + NUL
    bool  enabled;
    time_t created;
} TokenEntry;

#define MAX_TOKENS 1024
static TokenEntry      g_tokens[MAX_TOKENS];
static size_t          g_token_count = 0;
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
    int id = (int)g_token_count + 1;
    ++g_token_count;
    pthread_mutex_unlock(&g_tok_mx);
    return id;
}
static int find_token_index_unlocked(const char *tok){
    for(size_t i=0;i<g_token_count;++i){
        if(strcmp(g_tokens[i].token, tok)==0) return (int)i;
    }
    return -1;
}
static bool token_enabled(const char *tok){
    bool ok=false;
    pthread_mutex_lock(&g_tok_mx);
    int idx = find_token_index_unlocked(tok);
    if(idx>=0) ok = g_tokens[idx].enabled;
    pthread_mutex_unlock(&g_tok_mx);
    return ok;
}
static void print_tokens(void){
    pthread_mutex_lock(&g_tok_mx);
    fprintf(stderr, "\n== Active tokens ==\n");
    for(size_t i=0;i<g_token_count;++i){
        char ts[32]; struct tm gm; gmtime_r(&g_tokens[i].created,&gm);
        strftime(ts,sizeof(ts),"%H:%M:%S",&gm);
        fprintf(stderr, "  %zu) %s  [%s]  @%sZ\n",
                i+1, g_tokens[i].token, g_tokens[i].enabled?"ENABLED":"disabled", ts);
    }
    if(g_token_count==0) fprintf(stderr,"  (none)\n");
    fprintf(stderr, "Commands: list | enable <#> | disable <#> | help\n\n");
    pthread_mutex_unlock(&g_tok_mx);
}

/* admin thread (stdin) */
static void *admin_thread(void *arg){
    (void)arg;
    char line[128];
    fprintf(stderr, "Admin console ready. Type: list | enable <#> | disable <#> | help\n");
    while(g_keep_running && fgets(line,sizeof(line), stdin)){
        size_t L=strlen(line); if(L && (line[L-1]=='\n'||line[L-1]=='\r')) line[L-1]=0;
        if(strcmp(line,"list")==0){ print_tokens(); continue; }
        if(strncmp(line,"enable ",7)==0){
            int n=atoi(line+7);
            pthread_mutex_lock(&g_tok_mx);
            if(n>0 && (size_t)n<=g_token_count){ g_tokens[n-1].enabled=true; fprintf(stderr,"enabled #%d\n", n); }
            else fprintf(stderr,"no such id\n");
            pthread_mutex_unlock(&g_tok_mx);
            continue;
        }
        if(strncmp(line,"disable ",8)==0){
            int n=atoi(line+8);
            pthread_mutex_lock(&g_tok_mx);
            if(n>0 && (size_t)n<=g_token_count){ g_tokens[n-1].enabled=false; fprintf(stderr,"disabled #%d\n", n); }
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

/* ---------------- path helpers ---------------- */

// URL-decode in-place (supports %HH and '+')
static int url_decode(char *s){
    char *o = s;
    while(*s){
        if(*s=='%'){
            if(!(isxdigit((unsigned char)s[1]) && isxdigit((unsigned char)s[2]))) return -1;
            int hi = isdigit((unsigned char)s[1]) ? s[1]-'0' : (10 + (tolower((unsigned char)s[1])-'a'));
            int lo = isdigit((unsigned char)s[2]) ? s[2]-'0' : (10 + (tolower((unsigned char)s[2])-'a'));
            *o = (char)((hi<<4) | lo);
            s += 3; ++o;
            continue;
        } else if(*s=='+'){
            *o++ = ' '; ++s; continue;
        } else {
            *o++ = *s++;
        }
    }
    *o = '\0';
    return 0;
}

// mkdir -p
static int mkdir_p(const char *path, mode_t mode){
    char buf[2048]; snprintf(buf,sizeof(buf),"%s",path);
    size_t len=strlen(buf); if(len==0) return -1;
    if(buf[len-1]=='/') buf[len-1]='\0';
    for(char *p=buf+1; *p; ++p){
        if(*p=='/'){ *p='\0'; if(mkdir(buf,mode)&&errno!=EEXIST) return -1; *p='/'; }
    }
    if(mkdir(buf,mode)&&errno!=EEXIST) return -1;
    return 0;
}

// Normalize to /workspace jail.
// in: requested path (may start with '/' or relative)
// out: absolute path under /workspace; returns 0 on success, -1 if escape attempt
static int build_workspace_path(const char *in, char *out, size_t out_sz){
    const char *J="/workspace";
    char tmp[2048];
    if(!in||!*in) return -1;
    while(*in=='/') ++in;                          // strip leading '/'
    snprintf(tmp,sizeof(tmp),"%s/%s", J, in);

    // normalize: collapse //, /./, and reject .. components
    char norm[2048]; size_t nlen=0;
    for(size_t i=0; tmp[i] && nlen+1<sizeof(norm); ){
        while(tmp[i]=='/') ++i;
        size_t start=i; while(tmp[i] && tmp[i]!='/') ++i;
        size_t clen = i-start; if(clen==0) break;

        if(clen==1 && tmp[start]=='.'){
            // skip
        } else if(clen==2 && tmp[start]=='.' && tmp[start+1]=='.'){
            return -1; // block traversal
        } else {
            norm[nlen++] = '/';
            if(nlen+clen>=sizeof(norm)) return -1;
            memcpy(norm+nlen, tmp+start, clen); nlen+=clen;
        }
    }
    if(nlen==0){ snprintf(out,out_sz,"%s", J); return 0; }
    norm[nlen]='\0';
    if(strncmp(norm, J, strlen(J))!=0) return -1;
    snprintf(out,out_sz,"%s", norm);
    return 0;
}

/* ---------------- HTTP helpers ---------------- */

#define HDR_BUF_MAX  65536
#define UPLOAD_MAX   (100*1024*1024)   /* 100 MB */

static int read_until_headers(SSL *ssl, char *buf, int bufsz, int *out_total, int *out_header_len){
    int total=0;
    int header_len=-1;
    while(total < bufsz){
        int r = SSL_read(ssl, buf+total, bufsz-total);
        if(r<=0) break;
        total += r;
        char *p = NULL;
        if(total >= 4) p = strstr(buf, "\r\n\r\n");
        if(p){ header_len = (int)((p - buf) + 4); break; }
        if(total >= HDR_BUF_MAX) break;
    }
    if(out_total) *out_total = total;
    if(out_header_len) *out_header_len = header_len;
    return (header_len>0) ? 0 : -1;
}

static void send_simple(SSL *ssl, int code, const char *text){
    char resp[256];
    int n = snprintf(resp,sizeof(resp),
        "HTTP/1.1 %d %s\r\nConnection: close\r\n\r\n", code, text?text:"");
    SSL_write(ssl, resp, n);
}

/* ---------------- main ---------------- */

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

    mkdir("/workspace/uploads", 0700);
    int listen_fd=create_listen_socket(bind_ip,port);
    printf("HTTPS listening on https://%s:%u (Ctrl+C to stop)\n", bind_ip, port);

    while(g_keep_running){
        struct sockaddr_in cli; socklen_t clilen=sizeof(cli);
        int fd=accept(listen_fd,(struct sockaddr*)&cli,&clilen);
        if(fd<0){ if(errno==EINTR&&!g_keep_running) break; perror("accept"); continue; }
        int on=1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

        SSL *ssl=SSL_new(ctx); if(!ssl){ close(fd); continue; }
        SSL_set_fd(ssl, fd);
        if(SSL_accept(ssl)!=1){ ERR_print_errors_fp(stderr); SSL_free(ssl); close(fd); continue; }

        /* read headers */
        char buf[HDR_BUF_MAX];
        int total=0, hlen=-1;
        if(read_until_headers(ssl, buf, sizeof(buf)-1, &total, &hlen)!=0){
            send_simple(ssl,400,"Bad Request");
            SSL_shutdown(ssl); SSL_free(ssl); close(fd); continue;
        }
        buf[total]='\0';

        /* parse request line */
        char method[8], path_raw[2048];
        if(sscanf(buf,"%7s %2047s", method, path_raw)!=2){
            send_simple(ssl,400,"Bad Request");
            SSL_shutdown(ssl); SSL_free(ssl); close(fd); continue;
        }

        /* helper: header lookups */
        const char *hdr_expect = strcasestr(buf, "\nExpect:");
        const char *hdr_len    = strcasestr(buf, "\nContent-Length:");
        const char *hdr_te     = strcasestr(buf, "\nTransfer-Encoding:");

        /* respond 100-continue if asked */
        if(hdr_expect && strcasestr(hdr_expect, "100-continue")){
            const char *cont="HTTP/1.1 100 Continue\r\n\r\n";
            SSL_write(ssl, cont, (int)strlen(cont));
        }

        /* GET /health */
        if(strcmp(method,"GET")==0 && strcmp(path_raw,"/health")==0){
            const char *h="HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nOK\n";
            SSL_write(ssl,h,(int)strlen(h));
            SSL_shutdown(ssl); SSL_free(ssl); close(fd); continue;
        }

        /* GET / -> serve drag&drop HTML, mint a token and show its number */
        if(strcmp(method,"GET")==0 && strcmp(path_raw,"/")==0){
            char tok[65]; new_token(tok);
            int id = add_token(tok);
            fprintf(stderr,"New token #%d: %s\n", id, tok);
            print_tokens();

            const char *html_head =
                "<!doctype html><html><head><meta charset=utf-8>"
                "<meta name=viewport content='width=device-width,initial-scale=1'>"
                "<title>Single-file HTTPS Uploader</title>"
                "<style>"
                "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif;margin:0;padding:24px;background:#0b1020;color:#e8eefc}"
                "h1{margin:0 0 8px;font-size:20px}"
                ".card{max-width:980px;margin:0 auto;background:#121a33;border-radius:14px;padding:20px;box-shadow:0 8px 24px rgba(0,0,0,.35)}"
                ".muted{color:#9db0d8}"
                ".row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}"
                "input[type=text]{background:#0e152b;border:1px solid #2a3a6d;color:#e8eefc;border-radius:10px;padding:10px 12px;min-width:320px}"
                ".drop{margin-top:16px;border:2px dashed #3b56a8;border-radius:14px;padding:28px;text-align:center}"
                ".drop.drag{background:#0e1a3f}"
                "button{background:#3b56a8;color:#fff;border:0;border-radius:10px;padding:10px 16px;cursor:pointer}"
                ".log{margin-top:14px;white-space:pre-wrap;font-family:ui-monospace,Menlo,Consolas,monospace;background:#0e152b;border:1px solid #2a3a6d;border-radius:10px;padding:12px;max-height:320px;overflow:auto}"
                "</style></head><body><div class=card>";

            char html_body[6000];
            snprintf(html_body, sizeof(html_body),
                "<h1>Single-file HTTPS Uploader</h1>"
                "<p class=muted>Token <b>#%d</b> minted. Ask the server operator to run <code>enable %d</code> in the console, then drop files below.</p>"
                "<p class=muted><b>Token value:</b> <code id=token>%s</code></p>"
                "<div class=row>"
                "<label>Destination inside <code>/workspace</code>:</label>"
                "<input id=dest type=text placeholder='uploads/' value='uploads/'>"
                "<button id=pick>Choose Files</button>"
                "</div>"
                "<div id=drop class=drop>Drop files here</div>"
                "<div class=log id=log></div>"
                "<script>"
                "const TOKEN=%c%s%c;"
                "const log=e=>{const L=document.getElementById('log');L.textContent+=(e+'\\n');L.scrollTop=L.scrollHeight;};"
                "const enc=p=>encodeURIComponent(p).replace(/%%2F/g,'/');"
                "const $=i=>document.getElementById(i);"
                "const destBox=$('dest'), drop=$('drop'), pick=$('pick');"
                "function cleanDest(){let d=destBox.value||'';d=d.replace(/^\\/+/, '');if(d && !d.endsWith('/')) d+='/';return d;}"
                "async function sendOne(file){"
                "  const dest=cleanDest()+file.name;"
                "  const url='/upload/'+TOKEN+'/'+enc(dest);"
                "  log('Uploading '+file.name+' -> '+dest+' ...');"
                "  try{"
                "    const r=await fetch(url,{method:'PUT',body:file});"
                "    const t=await r.text();"
                "    log('  '+r.status+' '+t.trim());"
                "  }catch(err){log('  ERROR '+err);}"
                "}"
                "function handleFiles(files){for(const f of files) sendOne(f);}"
                "pick.onclick=()=>{const i=document.createElement('input');i.type='file';i.multiple=true;i.onchange=()=>handleFiles(i.files);i.click();};"
                "drop.ondragover=e=>{e.preventDefault();drop.classList.add('drag');};"
                "drop.ondragleave=e=>{drop.classList.remove('drag');};"
                "drop.ondrop=e=>{e.preventDefault();drop.classList.remove('drag');handleFiles(e.dataTransfer.files);};"
                "</script>"
                "</div></body></html>"
                , id, id, tok, '"', tok, '"');

            char resp[8192];
            int blen=(int)strlen(html_head)+(int)strlen(html_body);
            char hdr[256];
            int h = snprintf(hdr,sizeof(hdr),
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                "Content-Length: %d\r\nConnection: close\r\n\r\n", blen);
            SSL_write(ssl, hdr, h);
            SSL_write(ssl, html_head, (int)strlen(html_head));
            SSL_write(ssl, html_body, (int)strlen(html_body));
            SSL_shutdown(ssl); SSL_free(ssl); close(fd); continue;
        }

        /* PUT /upload/<TOKEN>/<PATH> */
        if(strcmp(method,"PUT")==0 && strncmp(path_raw,"/upload/",8)==0){
            const char *rest = path_raw + 8;
            const char *slash = strchr(rest,'/');
            if(!slash){ send_simple(ssl,400,"Bad Request"); goto closeconn; }

            char token[65];
            size_t toklen = (size_t)(slash - rest);
            if(toklen==0 || toklen>64){ send_simple(ssl,400,"Bad Request"); goto closeconn; }
            memcpy(token, rest, toklen); token[toklen]='\0';

            if(!token_enabled(token)){ send_simple(ssl,403,"Forbidden"); goto closeconn; }

            // destination path (URL-decoded)
            char dest_enc[2048]; snprintf(dest_enc,sizeof(dest_enc),"%s", slash+1);
            if(url_decode(dest_enc)!=0){ send_simple(ssl,400,"Bad Request"); goto closeconn; }

            // jail to /workspace
            char fullpath[2048];
            if(build_workspace_path(dest_enc, fullpath, sizeof(fullpath))!=0){
                send_simple(ssl,400,"Bad Path"); goto closeconn;
            }

            // require Content-Length (no chunked)
            if(strcasestr(buf, "\nTransfer-Encoding:") && strcasestr(buf, "chunked")){
                send_simple(ssl,501,"Not Implemented"); goto closeconn;
            }
            const char *cl = strcasestr(buf, "\nContent-Length:");
            if(!cl){ send_simple(ssl,411,"Length Required"); goto closeconn; }
            long content_len = strtol(cl + (int)strlen("\nContent-Length:"), NULL, 10);
            if(content_len<=0 || content_len>UPLOAD_MAX){
                send_simple(ssl,413,"Payload Too Large"); goto closeconn;
            }

            // write body (including any bytes already in buf)
            char *hdr_end = strstr(buf, "\r\n\r\n");
            size_t already = (size_t)total - (size_t)((hdr_end+4) - buf);

            // ensure parent dirs
            {
                char dir[2048]; snprintf(dir,sizeof(dir),"%s",fullpath);
                char *lastslash = strrchr(dir,'/');
                if(lastslash){ *lastslash='\0'; if(mkdir_p(dir,0700)!=0){ send_simple(ssl,500,"Server Error"); goto closeconn; } }
            }
            FILE *fp = fopen(fullpath,"wb");
            if(!fp){ send_simple(ssl,500,"Server Error"); goto closeconn; }

            if(already>0){
                if(fwrite(hdr_end+4,1,already,fp)!=already){ fclose(fp); send_simple(ssl,500,"Server Error"); goto closeconn; }
            }
            long remaining = content_len - (long)already;
            char chunk[16384];
            while(remaining>0){
                int toread = (int)((remaining < (long)sizeof(chunk)) ? remaining : (long)sizeof(chunk));
                int r = SSL_read(ssl, chunk, toread);
                if(r<=0){ fclose(fp); send_simple(ssl,400,"Bad Request"); goto closeconn; }
                if(fwrite(chunk,1,(size_t)r,fp)!=(size_t)r){ fclose(fp); send_simple(ssl,500,"Server Error"); goto closeconn; }
                remaining -= r;
            }
            fclose(fp);

            char ok[512];
            int n = snprintf(ok,sizeof(ok),
                "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n"
                "Connection: close\r\n\r\nSaved to %s\n", fullpath);
            SSL_write(ssl, ok, n);
            goto closeconn;
        }

        /* default */
        send_simple(ssl,404,"Not Found");

    closeconn:
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    g_keep_running=0;
    pthread_cancel(th); pthread_join(th,NULL);
    return 0;
}
