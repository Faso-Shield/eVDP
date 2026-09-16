(function () {
  "use strict";

  var typeField = document.getElementById("id_program_type");
  var anonymousField = document.getElementById("id_allows_anonymous_reports");
  var bountyHint = document.getElementById("bounty-hint");
  var anonymousHelp = document.getElementById("anonymous-reports-help");
  if (!typeField) return;

  var defaultHelpText = anonymousHelp ? anonymousHelp.textContent : "";

  function refresh() {
    var isBounty = typeField.value === "BUG_BOUNTY";
    if (bountyHint) bountyHint.hidden = !isBounty;
    if (anonymousField) {
      anonymousField.disabled = isBounty;
    }
    if (anonymousHelp) {
      anonymousHelp.textContent = isBounty
        ? "Sans effet pour un programme Bug Bounty : l'anonymat y est toujours désactivé."
        : defaultHelpText;
    }
  }

  typeField.addEventListener("change", refresh);
  refresh();
})();
