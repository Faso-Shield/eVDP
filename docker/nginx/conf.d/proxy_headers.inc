proxy_http_version 1.1;
# $http_host et non $host : $host retire le numero de port. Django
# reconstruit alors l'origine attendue a partir de request.get_host() sans
# le port ("http://127.0.0.1"), la compare a l'en-tete Origin envoye par le
# navigateur ("http://127.0.0.1:8090") et rejette le POST en 403 CSRF.
# $server_port ne convient pas non plus : il vaut 80 dans le conteneur, pas
# le port publie sur l'hote.
proxy_set_header Host              $http_host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $http_host;
proxy_set_header Connection        "";
proxy_redirect off;
proxy_connect_timeout 10s;
proxy_send_timeout    60s;
proxy_read_timeout    60s;
proxy_buffering on;
proxy_buffers 16 16k;
proxy_busy_buffers_size 32k;
