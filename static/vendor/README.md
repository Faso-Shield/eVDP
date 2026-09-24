# Bibliotheques tierces servies localement

La CSP de production (`script-src 'self'`) interdit tout script tiers : les
bibliotheques de la cartographie sont donc copiees ici plutot que chargees
depuis un CDN.

| Dossier         | Bibliotheque           | Version | Source                                   | Licence      |
|-----------------|------------------------|---------|------------------------------------------|--------------|
| `leaflet/`      | Leaflet                | 1.9.4   | https://unpkg.com/leaflet@1.9.4/dist/    | BSD-2-Clause |
| `markercluster/`| Leaflet.markercluster  | 1.5.3   | https://unpkg.com/leaflet.markercluster@1.5.3/dist/ | MIT |
| `leaflet-heat/` | Leaflet.heat           | 0.2.0   | https://unpkg.com/leaflet.heat@0.2.0/dist/ | BSD-2-Clause |

Les commentaires `sourceMappingURL` ont ete retires : les fichiers `.map` ne
sont pas distribues, et `CompressedManifestStaticFilesStorage` echouerait au
`collectstatic` sur une reference absente.
