/* eVDP — choix de la position d'une organisation sur une carte.
 *
 * Les champs latitude / longitude du formulaire restent la source de verite :
 * la carte ne fait que les lire et les ecrire. Un clic ou un glisser place le
 * point ; une saisie au clavier le deplace.
 */
(function () {
  "use strict";

  var box = document.getElementById("location-picker-map");
  var latInput = document.getElementById("id_latitude");
  var lonInput = document.getElementById("id_longitude");
  if (!box || !latInput || !lonInput || typeof L === "undefined") return;

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

  function readInputs() {
    var lat = parseFloat(String(latInput.value).replace(",", "."));
    var lon = parseFloat(String(lonInput.value).replace(",", "."));
    return isNaN(lat) || isNaN(lon) ? null : [lat, lon];
  }

  function writeInputs(latlng) {
    latInput.value = latlng.lat.toFixed(6);
    lonInput.value = latlng.lng.toFixed(6);
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
  latInput.addEventListener("change", function () { syncFromInputs(15); });
  lonInput.addEventListener("change", function () { syncFromInputs(15); });

  var clear = document.getElementById("location-picker-clear");
  if (clear) {
    clear.addEventListener("click", function () {
      latInput.value = "";
      lonInput.value = "";
      syncFromInputs();
      map.fitBounds(BOUNDS);
    });
  }

  syncFromInputs(16);
})();
