// corefile — Integrations settings page.
// Loads the current analyst's connected API keys and renders them like a real
// settings screen: partially masked, with reveal + copy.
//
// Note for the demo: the keys are fetched from /api/account/<uid>/integrations.
// The page only ever asks for its OWN uid — but the endpoint never checks
// ownership, so changing the uid in that request returns another analyst's
// keys (IDOR / BOLA). The masking here is cosmetic: the full secret is already
// in the JSON response, so it's not a security control.

const KEY_META = {
  github_pat: {
    label: "GitHub personal access token",
    hint: "Fetches debug symbols from private repositories.",
    icon: "🐙", keepStart: 8,
  },
  slack_bot_token: {
    label: "Slack bot token",
    hint: "Posts crash-signature alerts to #incidents.",
    icon: "💬", keepStart: 9,
  },
  aws_access_key_id: {
    label: "AWS access key ID",
    hint: "Reads raw core dumps from the crash-archive bucket.",
    icon: "☁️", keepStart: 4,
  },
  aws_secret_access_key: {
    label: "AWS secret access key",
    hint: "Paired with the access key ID above.",
    icon: "☁️", keepStart: 0,
  },
  telemetry_signing_key: {
    label: "Telemetry signing key",
    hint: "Signs outbound launch-telemetry payloads.",
    icon: "📡", keepStart: 8,
  },
};

function prettyName(key) {
  return (KEY_META[key] && KEY_META[key].label) ||
    key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// Keep a leading segment and the last 4 chars; mask the middle with dots.
function mask(value, keepStart) {
  const start = Math.min(keepStart || 6, Math.max(0, value.length - 4));
  const end = value.slice(-4);
  const hidden = Math.max(4, value.length - start - 4);
  return value.slice(0, start) + "•".repeat(Math.min(hidden, 24)) + end;
}

async function loadKeys() {
  const host = document.querySelector(".settings");
  const uid = host.dataset.uid;
  const wrap = document.getElementById("keys");

  let data;
  try {
    // The page requests only its own uid — but the endpoint doesn't enforce it.
    const res = await fetch("/api/account/" + uid + "/integrations");
    if (!res.ok) throw new Error("HTTP " + res.status);
    data = await res.json();
  } catch (e) {
    wrap.innerHTML = '<div class="keys-loading">Could not load integrations (' + e.message + ").</div>";
    return;
  }

  const entries = Object.entries(data.integrations || {});
  if (!entries.length) {
    wrap.innerHTML = '<div class="keys-loading">No connected services.</div>';
    return;
  }

  wrap.innerHTML = "";
  entries.forEach(([key, value]) => {
    const meta = KEY_META[key] || {};
    const card = document.createElement("div");
    card.className = "key-card";
    card.innerHTML =
      '<div class="key-icon">' + (meta.icon || "🔑") + "</div>" +
      '<div class="key-main">' +
        '<div class="key-top">' +
          '<span class="key-label">' + prettyName(key) + "</span>" +
          '<span class="key-status">Active</span>' +
        "</div>" +
        (meta.hint ? '<p class="key-hint">' + meta.hint + "</p>" : "") +
        '<div class="key-field">' +
          '<input class="key-value" type="text" readonly ' +
            'data-full="' + encodeURIComponent(value) + '" ' +
            'value="' + mask(value, meta.keepStart) + '" />' +
          '<button class="key-btn key-reveal" type="button">Reveal</button>' +
          '<button class="key-btn key-copy" type="button">Copy</button>' +
        "</div>" +
      "</div>";

    const input = card.querySelector(".key-value");
    const revealBtn = card.querySelector(".key-reveal");
    const copyBtn = card.querySelector(".key-copy");
    let shown = false;

    revealBtn.onclick = () => {
      shown = !shown;
      input.value = shown ? decodeURIComponent(input.dataset.full) : mask(value, meta.keepStart);
      revealBtn.textContent = shown ? "Hide" : "Reveal";
      input.classList.toggle("is-revealed", shown);
    };
    copyBtn.onclick = async () => {
      try { await navigator.clipboard.writeText(decodeURIComponent(input.dataset.full)); }
      catch (_e) { /* clipboard may be blocked in some contexts */ }
      copyBtn.textContent = "Copied";
      setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
    };

    wrap.appendChild(card);
  });
}

loadKeys();
