# =============================================================================
# Proxy de tuiles cartographiques Esri : trois couches.
#
#   /tiles/z/y/x        imagerie satellite (World Imagery)
#   /tiles/plan/z/y/x   plan avec routes et localites (World Street Map)
#   /tiles/noms/z/y/x   noms de lieux et frontieres sur fond transparent,
#                       superposes au satellite en vue « Hybride »
#
# La correspondance couche -> service Esri est la map $evdp_tile_service de
# nginx.conf (une map ne peut pas etre declaree dans un server).
#
# Inclus par evdp.conf, tls.conf(.template) et dev/evdp.conf : une seule
# definition pour tous les environnements.
#
# Le navigateur ne charge que /tiles/... sur la meme origine que la
# plateforme : aucune origine externe n'est ajoutee a la CSP (img-src 'self'),
# l'IP et le Referer des utilisateurs ne fuient pas vers le fournisseur, et
# le cache disque (zone evdp_tiles, nginx.conf) limite les appels sortants.
#
# Pre-requis : le conteneur Nginx doit pouvoir sortir en HTTPS vers
# server.arcgisonline.com (reseau evdp-frontend).
# =============================================================================

location ~ "^/tiles/(?:(?<tile_layer>plan|noms)/)?(?<tile_z>\d{1,2})/(?<tile_y>\d{1,7})/(?<tile_x>\d{1,7})$" {
    limit_req zone=evdp_general burst=200 nodelay;

    proxy_pass https://server.arcgisonline.com/ArcGIS/rest/services/$evdp_tile_service/MapServer/tile/$tile_z/$tile_y/$tile_x;
    proxy_ssl_server_name on;
    proxy_set_header Host server.arcgisonline.com;
    proxy_set_header Accept "image/png,image/jpeg,image/*";
    proxy_set_header Referer "";
    proxy_set_header Cookie "";
    proxy_set_header Authorization "";
    proxy_set_header User-Agent "eVDP/1.0";
    proxy_connect_timeout 10s;
    proxy_read_timeout 20s;

    proxy_cache evdp_tiles;
    # La couche fait partie de la cle : sans elle, plan et satellite d'une
    # meme case se serviraient mutuellement depuis le cache.
    proxy_cache_key "$evdp_tile_service/$tile_z/$tile_y/$tile_x";
    proxy_cache_valid 200 30d;
    proxy_cache_valid 404 1h;
    proxy_cache_lock on;
    proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
    proxy_ignore_headers Set-Cookie Cache-Control Expires;
    proxy_hide_header Set-Cookie;
    proxy_hide_header Cache-Control;
    proxy_hide_header Expires;
    proxy_hide_header Access-Control-Allow-Origin;

    add_header Cache-Control "public, max-age=2592000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Cache-Status $upstream_cache_status always;
    access_log off;
}
