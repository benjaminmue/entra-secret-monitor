/*
 * customer-form.js
 *
 * Zeigt im Kundenformular nur die Felder der gewaehlten Anmeldeart.
 *
 * Progressive Enhancement: ohne JavaScript bleiben alle Felder sichtbar und
 * das Formular funktioniert unveraendert. Die Serverpruefung entscheidet in
 * beiden Faellen, welches Paar zusammenpasst; hier wird nichts erzwungen,
 * nur ausgeblendet, was zur Auswahl nicht gehoert.
 *
 * Inline eingebettet wuerde dieses Skript nicht laufen: die CSP des Portals
 * erlaubt script-src 'self'.
 */
(function () {
  "use strict";

  var auswahl = document.querySelector("[data-auth-type]");
  if (!auswahl) {
    return;
  }

  var bereiche = document.querySelectorAll("[data-auth-only]");
  if (!bereiche.length) {
    return;
  }

  /**
   * Blendet die Felder aus, die nicht zur gewaehlten Anmeldeart gehoeren.
   *
   * Nutzt das hidden-Attribut statt style.display, damit die Felder auch fuer
   * Screenreader verschwinden und nicht nur optisch.
   */
  function anwenden() {
    var gewaehlt = auswahl.value;
    Array.prototype.forEach.call(bereiche, function (bereich) {
      var gehoert_zu = bereich.getAttribute("data-auth-only");
      bereich.hidden = gehoert_zu !== gewaehlt;
    });
  }

  auswahl.addEventListener("change", anwenden);
  anwenden();
})();
