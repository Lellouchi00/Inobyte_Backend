(function () {
  "use strict";

  var script = document.currentScript;
  var apiKey = window.INOBYTE_API_KEY;
  var endpoint = window.INOBYTE_ENDPOINT ||
    (script && script.src ? new URL("/api/events/track", script.src).toString() : "/api/events/track");

  if (!apiKey) {
    return;
  }

  function basePayload(eventType, data) {
    return {
      apiKey: apiKey,
      eventType: eventType,
      data: Object.assign({
        currentUrl: window.location.href,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent
      }, data || {})
    };
  }

  function sendEvent(eventType, data) {
    try {
      fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(basePayload(eventType, data)),
        keepalive: true,
        credentials: "omit"
      }).catch(function () {});
    } catch (err) {
      // Tracking must never break the client's application.
    }
  }

  function getClickData(event) {
    var target = event.target;

    return {
      tagName: target && target.tagName ? target.tagName.toLowerCase() : null,
      elementId: target && target.id ? target.id : null,
      className: target && typeof target.className === "string" ? target.className.slice(0, 120) : null,
      text: target && target.innerText ? target.innerText.trim().slice(0, 120) : null,
      x: event.clientX,
      y: event.clientY
    };
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      sendEvent("page_view");
    }, { once: true });
  } else {
    sendEvent("page_view");
  }

  document.addEventListener("click", function (event) {
    sendEvent("click", getClickData(event));
  }, true);

  window.InobyteTracker = {
    track: sendEvent
  };
})();
