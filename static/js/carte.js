/* eVDP — carte des organisations et des signalements (Leaflet).
 *
 * Toutes les donnees viennent de dashboard:map_data, deja filtrees par le
 * perimetre de l'utilisateur. Les chaines (noms d'organisation, titres de
 * dossier) sont saisies par des tiers : elles passent toutes par esc()
 * avant d'entrer dans du HTML.
 */
(function () {
  "use strict";

  var SEVERITIES = [
    ["CRITICAL", "Critique", "--sev-critical"],
    ["HIGH", "Élevée", "--sev-high"],
    ["MEDIUM", "Moyenne", "--sev-medium"],
    ["LOW", "Faible", "--sev-low"],
    ["INFO", "Informative", "--sev-info"],
  ];
  var NONE_COLOR_VAR = "--evdp-accent";

  var map, baseLayer, layer, mode = "markers", data = null;
  var mapEl = document.getElementById("map");
  if (!mapEl || typeof L === "undefined") return;

  function cssVar(name, fallback) {
    var value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return value || fallback;
  }

  var COLORS = {};
  var LABELS = {};
  SEVERITIES.forEach(function (s) {
    COLORS[s[0]] = cssVar(s[2], "#5c6b7d");
    LABELS[s[0]] = s[1];
  });
  var NONE_COLOR = cssVar(NONE_COLOR_VAR, "#0d7a5f");

  function color(severity) {
    return severity ? COLORS[severity] : NONE_COLOR;
  }

  function esc(value) {
    var div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
  }

  function severityClass(severity) {
    return "sev-" + String(severity || "info").toLowerCase();
  }

  function sevBreakdown(counts) {
    return SEVERITIES.filter(function (s) { return counts[s[0]]; })
      .map(function (s) {
        return '<span class="badge ' + severityClass(s[0]) + '">' + esc(s[1]) + " " + counts[s[0]] + "</span>";
      })
      .join(" ") || '<span class="muted">Aucun signalement</span>';
  }

  // ------------------------------------------------------------------ carte
  function initMap() {
    map = L.map(mapEl, { preferCanvas: true, minZoom: 6, maxZoom: 18 });
    map.fitBounds([[9.4, -5.5], [15.1, 2.4]]);
    map.setMaxBounds([[8.0, -7.5], [16.5, 4.5]]);

    var legend = L.control({ position: "bottomright" });
    legend.onAdd = function () {
      var box = L.DomUtil.create("div", "map-legend");
      box.innerHTML =
        "<strong>Sévérité la plus haute</strong>" +
        SEVERITIES.map(function (s) {
          return '<div><span class="map-dot" style="background:' + COLORS[s[0]] + '"></span>' + esc(s[1]) + "</div>";
        }).join("") +
        '<div><span class="map-dot" style="background:' + NONE_COLOR + '"></span>Aucun signalement</div>';
      return box;
    };
    legend.addTo(map);
  }

  function setBaseLayer(payload) {
    if (baseLayer || !payload.tiles) return;
    baseLayer = L.tileLayer(payload.tiles, { attribution: payload.attribution, maxZoom: 18 });
    baseLayer.addTo(map);
  }

  function clearLayer() {
    if (layer) map.removeLayer(layer);
    layer = null;
  }

  function orgPopup(o) {
    var title = o.acronym ? esc(o.acronym) + " — " + esc(o.name) : esc(o.name);
    var recent = (o.recent || []).map(function (c) {
      return '<li><a href="' + esc(c.url) + '"><span class="mono">' + esc(c.case_id) + "</span></a> " +
        '<span class="badge ' + severityClass(c.severity) + '">' + esc(LABELS[c.severity] || c.severity) + "</span><br>" +
        esc(c.title) + "</li>";
    }).join("");
    return '<div class="map-popup-title">' + title + "</div>" +
      '<div class="muted">' + esc(o.sector) + " · " + esc(o.region) + "</div>" +
      '<div class="map-popup-pos">' + (o.precise
        ? "Position GPS : <span class=\"mono\">" + o.lat.toFixed(6) + ", " + o.lon.toFixed(6) + "</span>"
        : "Position approximative : chef-lieu de la région") + "</div>" +
      '<div class="map-popup-grid">' +
      "<span>Signalements</span><strong>" + o.total + "</strong>" +
      "<span>En cours</span><strong>" + o.open + "</strong>" +
      "<span>SLA dépassés</span><strong>" + o.sla_breached + "</strong>" +
      "<span>Dernier</span><strong>" + esc(o.last_report || "—") + "</strong>" +
      "</div>" +
      '<div class="map-popup-sev">' + sevBreakdown(o.by_severity) + "</div>" +
      (recent ? '<ul class="map-popup-cases">' + recent + "</ul>" : "") +
      '<div class="btn-row map-popup-actions">' +
      (o.cases_url ? '<a class="btn btn-sm" href="' + esc(o.cases_url) + '">Dossiers</a>' : "") +
      '<a class="btn btn-sm btn-outline" href="' + esc(o.detail_url) + '">Fiche</a>' +
      "</div>";
  }

  function markerIcon(o) {
    var size = o.total ? Math.min(34, 16 + Math.sqrt(o.total) * 4) : 12;
    return L.divIcon({
      className: "",
      html: '<div class="map-marker' + (o.precise ? "" : " approx") + '" style="background:' + color(o.dominant) +
        ";width:" + size + "px;height:" + size + 'px">' + (o.total || "") + "</div>",
      iconSize: [size, size],
    });
  }

  function showMarkers(payload) {
    layer = L.markerClusterGroup({
      maxClusterRadius: 44,
      // A l'echelle d'un quartier, chaque organisation est a sa position
      // reelle : plus de regroupement.
      disableClusteringAtZoom: 13,
      iconCreateFunction: function (cluster) {
        var children = cluster.getAllChildMarkers();
        var worst = null, total = 0;
        children.forEach(function (m) {
          total += m.options.total;
          var rank = SEVERITIES.findIndex(function (s) { return s[0] === m.options.dominant; });
          if (rank >= 0 && (worst === null || rank < worst)) worst = rank;
        });
        var sev = worst === null ? null : SEVERITIES[worst][0];
        return L.divIcon({
          className: "",
          // Le chiffre est celui des signalements, comme sur un marqueur
          // isole ; le nombre d'organisations est dans l'infobulle.
          html: '<div class="map-marker cluster" style="background:' + color(sev) + '" title="' +
            children.length + " organisations, " + total + ' signalement(s)">' + total + "</div>",
          iconSize: [40, 40],
        });
      },
    });
    payload.organizations.forEach(function (o) {
      L.marker([o.lat, o.lon], { icon: markerIcon(o), title: o.name, total: o.total, dominant: o.dominant, orgId: o.id })
        .bindPopup(orgPopup(o), { maxWidth: 330 })
        .addTo(layer);
    });
    layer.addTo(map);
  }

  function showHeat(payload) {
    var points = payload.organizations.filter(function (o) { return o.heat > 0; });
    var max = points.reduce(function (acc, o) { return Math.max(acc, o.heat); }, 0) || 1;
    layer = L.heatLayer(points.map(function (o) { return [o.lat, o.lon, o.heat / max]; }), {
      radius: 38,
      blur: 26,
      // leaflet.heat divise l'intensite par 2^(maxZoom - zoom) : au-dela de
      // 6-7 (vue nationale), les points deviennent invisibles.
      maxZoom: 7,
      minOpacity: 0.25,
      gradient: { 0.2: COLORS.LOW, 0.45: COLORS.MEDIUM, 0.7: COLORS.HIGH, 1.0: COLORS.CRITICAL },
    });
    layer.addTo(map);
  }

  function showRegions(payload) {
    layer = L.layerGroup();
    payload.regions.forEach(function (r) {
      L.circleMarker([r.lat, r.lon], {
        radius: Math.min(46, 10 + Math.sqrt(r.total) * 6),
        color: color(r.dominant),
        fillColor: color(r.dominant),
        fillOpacity: 0.35,
        weight: 2,
      })
        .bindTooltip(esc(r.name) + " (" + r.total + ")")
        .bindPopup(
          '<div class="map-popup-title">' + esc(r.name) + '</div><div class="muted">Chef-lieu : ' + esc(r.capital) + "</div>" +
          '<div class="map-popup-grid">' +
          "<span>Organisations</span><strong>" + r.organizations + "</strong>" +
          "<span>Signalements</span><strong>" + r.total + "</strong>" +
          "<span>En cours</span><strong>" + r.open + "</strong>" +
          "<span>SLA dépassés</span><strong>" + r.sla_breached + "</strong>" +
          "</div>" +
          '<div class="map-popup-sev">' + sevBreakdown(r.by_severity) + "</div>"
        )
        .addTo(layer);
    });
    layer.addTo(map);
  }

  function render() {
    if (!data) return;
    clearLayer();
    if (mode === "heat") showHeat(data);
    else if (mode === "regions") showRegions(data);
    else showMarkers(data);
  }

  // ---------------------------------------------------------------- panneau
  function renderSummary(payload) {
    var t = payload.totals;
    var rows = [
      ["Organisations affichées", t.organizations],
      ["Organisations signalées", t.reported],
      ["Signalements", t.cases],
      ["En cours", t.open],
      ["SLA dépassés", t.sla_breached],
    ].map(function (r) {
      return '<div class="flex-between"><span>' + r[0] + "</span><strong>" + r[1] + "</strong></div>";
    }).join("");
    var sev = SEVERITIES.map(function (s) {
      return '<div class="flex-between"><span><span class="map-dot" style="background:' + COLORS[s[0]] + '"></span>' +
        esc(s[1]) + "</span><strong>" + (t.by_severity[s[0]] || 0) + "</strong></div>";
    }).join("");
    var warn = t.unlocated
      ? '<p class="map-warn">' + t.unlocated + " organisation(s) signalée(s) sans région reconnue ni coordonnées : absentes de la carte.</p>"
      : "";
    document.getElementById("map-summary").innerHTML = rows + "<hr>" + sev + warn;
  }

  function renderList(payload) {
    var box = document.getElementById("map-list");
    var orgs = payload.organizations.slice().sort(function (a, b) {
      return b.open - a.open || b.total - a.total || a.name.localeCompare(b.name);
    });
    if (!orgs.length) {
      box.innerHTML = '<p class="muted map-list-empty">Aucune organisation pour ces filtres.</p>';
      return;
    }
    box.innerHTML = orgs.map(function (o) {
      return '<button type="button" class="map-list-item" data-id="' + esc(o.id) + '">' +
        '<span class="map-dot" style="background:' + color(o.dominant) + '"></span>' +
        '<span class="map-list-name">' + esc(o.acronym || o.name) +
        '<small class="muted">' + esc(o.region) + "</small></span>" +
        '<strong class="mono">' + o.total + "</strong></button>";
    }).join("");
  }

  function focusOrganization(id) {
    var org = data && data.organizations.find(function (o) { return o.id === id; });
    if (!org) return;
    if (mode !== "markers") switchMode("markers");
    // Position GPS : zoom rue ; chef-lieu : zoom ville, la precision
    // n'en permet pas davantage.
    map.setView([org.lat, org.lon], org.precise ? 16 : 12, { animate: false });
    var target = null;
    layer.eachLayer(function (m) { if (m.options.orgId === id) target = m; });
    if (target) layer.zoomToShowLayer(target, function () { target.openPopup(); });
  }

  // ---------------------------------------------------------------- donnees
  function query() {
    var form = document.getElementById("map-filters");
    var params = new URLSearchParams();
    new FormData(form).forEach(function (value, key) {
      if (value) params.append(key, value);
    });
    return params.toString();
  }

  // Lien direct depuis la fiche d'une organisation : /dashboard/carte/?org=<id>
  var pendingFocus = new URLSearchParams(window.location.search).get("org");

  function load() {
    var url = mapEl.dataset.url + "?" + query();
    document.getElementById("map-summary").innerHTML = '<p class="muted">Chargement…</p>';
    fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.json();
      })
      .then(function (payload) {
        data = payload;
        setBaseLayer(payload);
        render();
        renderSummary(payload);
        renderList(payload);
        if (pendingFocus) {
          focusOrganization(pendingFocus);
          pendingFocus = null;
        }
      })
      .catch(function () {
        document.getElementById("map-summary").innerHTML =
          '<p class="map-warn">Impossible de charger les données de la carte.</p>';
      });
  }

  function switchMode(next) {
    mode = next;
    document.querySelectorAll(".seg-btn").forEach(function (b) {
      b.classList.toggle("active", b.dataset.mode === next);
    });
    render();
  }

  function setFullscreen(on) {
    mapEl.classList.toggle("fullscreen", on);
    document.getElementById("map-exit").classList.toggle("d-none", !on);
    setTimeout(function () { map.invalidateSize(); }, 200);
  }

  document.addEventListener("DOMContentLoaded", function () {
    initMap();
    load();

    var form = document.getElementById("map-filters");
    form.addEventListener("submit", function (e) { e.preventDefault(); load(); });
    form.addEventListener("reset", function () { setTimeout(load, 0); });
    form.querySelectorAll("select, input[type=checkbox]").forEach(function (el) {
      el.addEventListener("change", load);
    });

    document.querySelectorAll(".seg-btn").forEach(function (b) {
      b.addEventListener("click", function () { switchMode(b.dataset.mode); });
    });

    document.getElementById("map-list").addEventListener("click", function (e) {
      var item = e.target.closest(".map-list-item");
      if (item) focusOrganization(item.dataset.id);
    });

    document.getElementById("map-fullscreen").addEventListener("click", function () {
      setFullscreen(!mapEl.classList.contains("fullscreen"));
    });
    document.getElementById("map-exit").addEventListener("click", function () { setFullscreen(false); });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && mapEl.classList.contains("fullscreen")) setFullscreen(false);
    });
  });
})();
