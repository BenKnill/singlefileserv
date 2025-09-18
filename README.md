# single-file-https-server

```bash
apt-get update && apt-get install -y build-essential libssl-dev && gcc -O2 -Wall -Wextra -o https_server single_file_https_server.c -lssl -lcrypto && ./https_server --port 8443 --san $(curl -s ifconfig.me)
