/* eVDP — choix de la position d'une organisation sur une carte.
 *
 * La case « Coordonnees GPS » du formulaire reste la source de verite : la
 * carte ne fait que la lire et l'ecrire. Un clic ou un glisser place le
 * point ; un collage (format Google Maps « 12.377635, -1.487849 », lien ou
 * degres-minutes-secondes) le deplace aussitot. Le serveur refait l'analyse
 * a l'enregistrement (apps/organizations/geo.py) : ce script n'est qu'un
 * apercu.
 */
(function () {
  "use strict";

  var box = document.getElementById("location-picker-map");
  var input = document.getElementById("id_coordinates");
  if (!box || !input || typeof L === "undefined") return;

  // Emprise du Burkina Faso (apps/organizations/geo.py).
  var BOUNDS = [[9.3, -5.6], [15.2, 2.5]];
  var marker = null;

  var map = L.map(box, { minZoom: 5, maxZoom: 18 });
  map.fitBounds(BOUNDS);
  if (box.dataset.tiles) {
    L.tileLayer(box.dataset.tiles, { attribution: box.dataset.attribution, maxZoom: 18 }).addTo(map);
  }

  function inBurkina(lat, lon) {
    return lat >= BOUNDS[0][0] && lat <= BOUNDS[1][0] && lon >= BOUNDS[0][1] && lon <= BOUNDS[1][1];
  }

  var NUM = "[-+]?\\d{1,3}(?:[.,]\\d+)?";
  var URL_PATTERNS = [
    new RegExp("!3d(" + NUM + ")!4d(" + NUM + ")"),
    new RegExp("[?&](?:q|query|ll|center|destination)=(" + NUM + ")(?:,|%2C)\\s*(" + NUM + ")"),
    new RegExp("@(" + NUM + "),(" + NUM + ")"),
  ];
  var DMS = /(\d{1,3}(?:[.,]\d+)?)\s*°\s*(?:(\d{1,2}(?:[.,]\d+)?)\s*['′’]\s*)?(?:(\d{1,2}(?:[.,]\d+)?)\s*(?:"|″|”|''|′′)\s*)?([NSEWO])/gi;

  function num(text) { return parseFloat(String(text || "0").replace(",", ".")); }

  function parse(text) {
    text = String(text || "").trim();
    if (!text) return null;
    for (var i = 0; i < URL_PATTERNS.length; i++) {
      var m = text.match(URL_PATTERNS[i]);
      if (m) return [num(m[1]), num(m[2])];
    }
    var dms = [], d, lat = null, lon = null;
    DMS.lastIndex = 0;
    while ((d = DMS.exec(text))) dms.push(d);
    if (dms.length === 2) {
      dms.forEach(function (p) {
        var v = num(p[1]) + num(p[2]) / 60 + num(p[3]) / 3600;
        var h = p[4].toUpperCase();
        if ("SWO".indexOf(h) >= 0) v = -v;
        if (h === "N" || h === "S") lat = v; else lon = v;
      });
      if (lat !== null && lon !== null) return [lat, lon];
    }
    var chunks;
    if (text.indexOf(";") >= 0) chunks = text.split(";");
    else if (/\d,\s*[-+]?\d/.test(text) && text.split(",").length === 2) chunks = text.split(",");
    else chunks = text.replace(/,/g, " ").split(/\s+/);
    chunks = chunks.map(function (c) { return c.trim(); }).filter(Boolean);
    var whole = new RegExp("^" + NUM + "$");
    if (chunks.length !== 2 || !whole.test(chunks[0]) || !whole.test(chunks[1])) return null;
    return [num(chunks[0]), num(chunks[1])];
  }

  function readInputs() {
    return parse(input.value);
  }

  function writeInputs(latlng) {
    input.value = latlng.lat.toFixed(6) + ", " + latlng.lng.toFixed(6);
  }

  function placeMarker(position, zoom) {
    if (!marker) {
      marker = L.marker(position, {
        draggable: true,
        icon: L.divIcon({ className: "", html: '<div class="location-pin"></div>', iconSize: [18, 18] }),
      }).addTo(map);
      marker.on("dragend", function () { writeInputs(marker.getLatLng()); });
    } else {
      marker.setLatLng(position);
    }
    if (zoom) map.setView(position, zoom);
  }

  function syncFromInputs(zoom) {
    var position = readInputs();
    if (position && inBurkina(position[0], position[1])) {
      placeMarker(position, zoom);
    } else if (marker && !position) {
      map.removeLayer(marker);
      marker = null;
    }
  }

  map.on("click", function (e) {
    placeMarker(e.latlng);
    writeInputs(e.latlng);
  });
  // Le point suit la case des la saisie ou le collage.
  input.addEventListener("input", function () { syncFromInputs(16); });

  var clear = document.getElementById("location-picker-clear");
  if (clear) {
    clear.addEventListener("click", function () {
      input.value = "";
      syncFromInputs();
      map.fitBounds(BOUNDS);
    });
  }

  syncFromInputs(16);
})();
