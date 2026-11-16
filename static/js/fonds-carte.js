/* eVDP — selecteur de fond de carte (Plan, Satellite, Hybride), commun a la
 * carte nationale (carte.js) et a la carte de position d'une organisation
 * (org-location.js).
 *
 * Les fonds viennent du serveur (apps.dashboard.maps.basemaps) : un fond
 * dont l'URL est vide n'y figure pas. « Hybride » est le satellite avec les
 * noms de lieux superposes. Le dernier choix est memorise par le navigateur,
 * sous une cle propre a chaque carte ; un stockage refuse (navigation privee)
 * ramene simplement au fond par defaut.
 */
(function () {
  "use strict";

  function stored(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
  }

  function store(key, id) {
    try { window.localStorage.setItem(key, id); } catch (e) { /* sans memoire */ }
  }

  function esc(value) {
    var div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
  }

  function layerFor(b) {
    var base = L.tileLayer(b.tiles, { attribution: b.attribution, maxZoom: 18 });
    if (!b.overlay) return base;
    return L.layerGroup([base, L.tileLayer(b.overlay, { maxZoom: 18, zIndex: 2 })]);
  }

  /* Pose le fond initial sur `map` et, s'il y a un choix, le selecteur.
   * options : storageKey (memoire du choix), preferred (fond par defaut). */
  function add(map, choices, options) {
    options = options || {};
    if (!choices || !choices.length) return null;
    var layers = {};
    var byId = {};
    choices.forEach(function (b) {
      byId[b.id] = layerFor(b);
      layers[esc(b.label)] = byId[b.id];
    });
    var initial =
      (options.storageKey && byId[stored(options.storageKey)]) ||
      byId[options.preferred] ||
      byId[choices[0].id];
    initial.addTo(map);
    if (choices.length > 1) {
      L.control.layers(layers, null, { position: "topright", collapsed: false }).addTo(map);
      map.on("baselayerchange", function (e) {
        if (!options.storageKey) return;
        Object.keys(byId).forEach(function (id) {
          if (byId[id] === e.layer) store(options.storageKey, id);
        });
      });
    }
    return initial;
  }

  window.evdpBasemaps = { add: add };
})();
