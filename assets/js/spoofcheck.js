// Email spoof check — runs entirely in the visitor's browser.
//
// There is no backend. Both Cloudflare and Google publish DNS-over-HTTPS endpoints that
// send Access-Control-Allow-Origin: *, so the page can resolve DNS directly. That removes
// the server, the hosting account, and the bill — but the better reason is that each
// visitor's lookups come from their own connection rather than one shared server IP, so
// there is no rate limit to police and no IP reputation to protect.
//
// Scoring is imported from verdict.mjs, which is the same module the local dev server and
// the test suite use.

import {
  normaliseDomain, dkimSelectors, isDkimRecord, buildResult,
} from "./verdict.mjs";

// Cloudflare first, Google as a fallback — some networks block one or the other, and a
// visitor on a locked-down corporate connection is exactly who wants this answer.
const RESOLVERS = [
  (name, type) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
  (name, type) => `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
];

// A DoH JSON answer returns TXT strings quoted, and a long record arrives as several
// quoted chunks that must be joined — the same way a resolver reassembles them.
function unquoteTxt(data) {
  const parts = String(data).match(/"([^"]*)"/g);
  return parts ? parts.map((p) => p.slice(1, -1)).join("") : String(data);
}

async function doh(name, type) {
  for (const build of RESOLVERS) {
    try {
      const res = await fetch(build(name, type), { headers: { accept: "application/dns-json" } });
      if (!res.ok) continue;
      const body = await res.json();
      // Status 3 is NXDOMAIN: a legitimate "no such record", not a failure to retry
      if (body.Status === 3) return [];
      if (body.Status !== 0 || !Array.isArray(body.Answer)) continue;
      return body.Answer;
    } catch {
      // try the next resolver
    }
  }
  return [];
}

const txt = async (name) =>
  (await doh(name, "TXT")).filter((a) => a.type === 16).map((a) => unquoteTxt(a.data));

const mx = async (name) =>
  (await doh(name, "MX"))
    .filter((a) => a.type === 15)
    .map((a) => {
      const [priority, ...rest] = String(a.data).split(/\s+/);
      return { priority: Number(priority) || 0, exchange: rest.join(" ").replace(/\.$/, "") };
    })
    .sort((a, b) => a.priority - b.priority)
    .map((m) => m.exchange);

export async function runCheck(rawDomain) {
  const domain = normaliseDomain(rawDomain);
  if (!domain) throw new Error("Enter a valid domain, like example.co.uk");

  const [rootTxt, dmarcTxt, mxHosts] = await Promise.all([
    txt(domain), txt(`_dmarc.${domain}`), mx(domain),
  ]);

  // selector guesses depend on the MX provider, so this runs after
  const selectors = dkimSelectors(mxHosts);
  const dkimHits = [];
  await Promise.all(selectors.map(async (sel) => {
    const rec = await txt(`${sel}._domainkey.${domain}`);
    if (rec.some(isDkimRecord)) dkimHits.push(sel);
  }));

  return buildResult({
    domain, rootTxt, dmarcTxt, mxHosts, dkimHits, triedCount: selectors.length,
  });
}

// ---------- UI ----------
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const results = document.getElementById("results");
const btn = document.getElementById("check-btn");
const input = document.getElementById("domain-input");

document.getElementById("check-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = input.value.trim();
  if (!domain) return;

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';
  results.innerHTML = "";

  try {
    render(await runCheck(domain));
  } catch (err) {
    results.innerHTML = `<div class="callout offline">${esc(err.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Check domain";
  }
});

function render(d) {
  const findings = d.findings.map((f) => `
    <div class="finding">
      <div class="finding-head">
        <span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span>
        <span class="finding-title">${esc(f.title)}</span>
      </div>
      <p>${esc(f.detail)}</p>
      <div class="fix"><b>Fix:</b> ${esc(f.fix)}</div>
    </div>`).join("");

  const rec = (label, value) => `
    <div class="rec">
      <div class="rec-label">${esc(label)}</div>
      ${value ? `<pre>${esc(value)}</pre>` : '<div class="absent">Not published</div>'}
    </div>`;

  results.innerHTML = `
    <div class="verdict">
      <div class="grade g-${esc(d.grade)}">${esc(d.grade)}</div>
      <div>
        <h3>${esc(d.headline)}</h3>
        <p>${esc(d.summary)}</p>
      </div>
    </div>

    <h2 class="section-header">&gt; Findings — ${esc(d.domain)}</h2>
    ${findings || '<p class="text-block">No issues found.</p>'}

    <h2 class="section-header">&gt; Records as published</h2>
    ${rec("SPF", d.records.spf)}
    ${rec("DMARC", d.records.dmarc)}
    <div class="rec">
      <div class="rec-label">DKIM selectors found</div>
      ${d.records.dkimSelectors.length
        ? `<pre>${esc(d.records.dkimSelectors.join(", "))}</pre>`
        : '<div class="absent">None found at the selectors tried — inconclusive, see note below</div>'}
    </div>
    ${rec("Mail servers", d.records.mx.join("\n"))}`;
}

// deep link: /spoofcheck.html?domain=example.co.uk
const preset = new URLSearchParams(location.search).get("domain");
if (preset) {
  input.value = preset;
  document.getElementById("check-form").requestSubmit();
}
