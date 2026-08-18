// Scoring logic for the email spoof check.
//
// SOURCE OF TRUTH: this file is copied from the spoofcheck project, where it is covered by
// a 38-case test suite (`node test.mjs`). If you change the scoring, change it there, run
// the tests, and copy it back:
//   cp ~/Documents/spoofcheck/lib/verdict.mjs assets/js/verdict.mjs
// Pure ESM, no Node APIs — which is why the same file runs in the browser, on the local
// dev server, and in a serverless function.

// ---------- input handling ----------
// Accept what someone would actually paste: a bare domain, a URL, an email address.
export function normaliseDomain(raw) {
  let d = String(raw || "").trim().toLowerCase();
  if (!d) return null;
  if (d.includes("@")) d = d.split("@").pop();              // someone pasted an email
  d = d.replace(/^[a-z]+:\/\//, "").split("/")[0].split("?")[0].split(":")[0];
  d = d.replace(/\.$/, "");                                  // trailing root dot
  if (d.startsWith("www.")) d = d.slice(4);
  if (d.length > 253 || d.length < 4) return null;
  if (!/^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d)) return null;
  return d;
}

// ---------- SPF ----------
// SPF says which servers may send for the domain. On its own it does NOT stop spoofing of
// the visible From: address — that's DMARC's job — but a missing or permissive SPF removes
// the foundation DMARC alignment is built on.
export function parseSpf(records) {
  const found = records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (!found.length) return { present: false };
  const record = found[0].trim();
  const all = /[-~?+]all\b/i.exec(record)?.[0]?.toLowerCase() || null;
  // each include/a/mx/ptr/exists/redirect costs a DNS lookup; over 10 is a permerror
  const lookups = (record.match(/\b(include|a|mx|ptr|exists|redirect)[:=]/gi) || []).length;
  return {
    present: true, record, duplicate: found.length > 1, all, lookups,
    tooManyLookups: lookups > 10,
  };
}

// ---------- DMARC ----------
// The record that actually decides what a receiver does with a forged From: address.
export function parseDmarc(records) {
  const found = records.filter((r) => /^v=DMARC1\s*;/i.test(r.trim()));
  if (!found.length) return { present: false };
  const record = found[0].trim();
  const tag = (t) => new RegExp(`\\b${t}\\s*=\\s*([^;\\s]+)`, "i").exec(record)?.[1]?.toLowerCase() || null;
  const pct = tag("pct");
  return {
    present: true, record,
    policy: tag("p"),
    subdomainPolicy: tag("sp"),
    pct: pct === null ? 100 : Number(pct),
    rua: /\brua\s*=/i.test(record),
    duplicate: found.length > 1,
  };
}

// ---------- DKIM selector guessing ----------
// Keys live at <selector>._domainkey.<domain> and the selector is not discoverable from
// DNS, so work backwards from the MX provider and fall back to common names. A miss is
// inconclusive, never a finding.
const COMMON_SELECTORS = ["default", "dkim", "mail", "k1", "s1", "s2", "key1"];
const PROVIDER_SELECTORS = [
  [/google|googlemail/i, ["google"]],
  [/outlook|microsoft|protection\.outlook/i, ["selector1", "selector2"]],
  [/zoho/i, ["zoho", "zmail"]],
  [/protonmail|proton\.me/i, ["protonmail", "protonmail2"]],
  [/mimecast/i, ["mimecast20230101", "mimecast"]],
  [/messagelabs|symantec/i, ["mldkim"]],
  [/mailgun/i, ["mailo", "smtp"]],
  [/sendgrid/i, ["s1", "s2"]],
  [/fastmail/i, ["fm1", "fm2", "fm3"]],
  [/ionos|1and1/i, ["ionos1"]],
];

export function dkimSelectors(mxHosts) {
  const host = mxHosts.join(" ");
  const guesses = new Set(COMMON_SELECTORS);
  for (const [re, sels] of PROVIDER_SELECTORS) {
    if (re.test(host)) sels.forEach((s) => guesses.add(s));
  }
  return [...guesses];
}

export const isDkimRecord = (r) => /v=DKIM1|p=[A-Za-z0-9+/]/i.test(r);

// ---------- verdict ----------
// One headline, because a business owner reads one line and stops. Everything else is
// supporting detail for whoever they forward it to.
export function assess({ spf, dmarc, dkim, mxHosts }) {
  const findings = [];
  const add = (severity, title, detail, fix) => findings.push({ severity, title, detail, fix });

  const enforcing = dmarc.present && (dmarc.policy === "reject" || dmarc.policy === "quarantine");
  const partial = dmarc.present && dmarc.policy === "quarantine";

  let grade, headline, summary;
  if (!dmarc.present) {
    grade = "F";
    headline = `Anyone on the internet can send email that appears to come from @${dmarc.domain || "your domain"}`;
    summary = "There is no DMARC record, so receiving mail servers have no instruction to reject forged messages using your name.";
  } else if (dmarc.policy === "none") {
    grade = "E";
    headline = "Forged email using your domain still gets delivered";
    summary = "A DMARC record exists but its policy is p=none, which only monitors. Receivers are told to take no action against forgeries.";
  } else if (partial) {
    grade = dmarc.pct === 100 ? "C" : "D";
    headline = "Forged email is sent to spam rather than rejected";
    summary = "DMARC is set to quarantine. Spoofed mail usually lands in junk instead of being refused outright — better than nothing, short of full protection.";
  } else {
    grade = spf.present && spf.all === "-all" ? "A" : "B";
    headline = "Your domain is protected against email spoofing";
    summary = "DMARC is set to reject, so receiving servers refuse mail that fails authentication as your domain.";
  }

  if (!dmarc.present) {
    add("critical", "No DMARC record",
      "Nothing at _dmarc." + (dmarc.domain || "yourdomain") + " tells receivers what to do with mail that fails authentication.",
      "Publish a DMARC record. Start at p=none with a reporting address to see who sends as you, then move to quarantine and reject.");
  } else {
    if (dmarc.policy === "none") {
      add("high", "DMARC policy is monitor-only (p=none)",
        "Failures are reported but nothing is blocked.",
        "Once your reports look clean, move to p=quarantine and then p=reject.");
    } else if (partial) {
      add("medium", "DMARC is set to quarantine, not reject",
        "Forged mail is filtered to spam rather than refused.",
        "Move to p=reject once you're confident all legitimate senders pass.");
    }
    if (dmarc.pct < 100) {
      add("medium", `DMARC applies to only ${dmarc.pct}% of mail`,
        "The pct tag limits how much mail the policy is applied to.",
        "Remove the pct tag, or set pct=100, once you're confident in the policy.");
    }
    if (!dmarc.rua) {
      add("low", "No DMARC reporting address",
        "Without a rua address you get no visibility of who is sending as your domain.",
        "Add rua=mailto:dmarc@yourdomain to receive aggregate reports.");
    }
    if (dmarc.duplicate) {
      add("high", "Multiple DMARC records",
        "More than one DMARC record is invalid; receivers will ignore all of them.",
        "Delete all but one _dmarc TXT record.");
    }
  }

  if (!spf.present) {
    add("high", "No SPF record",
      "Nothing declares which servers are allowed to send mail for your domain.",
      "Publish an SPF record listing your mail providers, ending in -all.");
  } else {
    if (spf.duplicate) {
      add("high", "Multiple SPF records",
        "More than one SPF record is a permanent error and receivers will fail the check entirely.",
        "Merge them into a single v=spf1 record.");
    }
    if (spf.all === "+all") {
      add("critical", "SPF allows the entire internet (+all)",
        "This explicitly authorises every server on the internet to send as your domain.",
        "Change +all to -all immediately.");
    } else if (spf.all === "?all") {
      add("medium", "SPF is set to neutral (?all)",
        "Neutral tells receivers to treat unauthorised senders no differently.",
        "Change ?all to -all, or ~all while testing.");
    } else if (!spf.all) {
      add("medium", "SPF record has no all mechanism",
        "Without a trailing all, the record's behaviour for unlisted senders is undefined.",
        "Append -all to the end of the record.");
    }
    if (spf.tooManyLookups) {
      add("high", `SPF needs ${spf.lookups} DNS lookups (limit is 10)`,
        "Over the limit, SPF returns permerror and the check fails for everyone.",
        "Flatten or remove some include: entries to get under 10.");
    }
  }

  if (!dkim.selectorsFound.length) {
    add("info", "DKIM could not be confirmed",
      `No key found at ${dkim.triedCount} common selectors. DKIM selectors aren't listed in DNS, so this is inconclusive rather than proof of absence.`,
      "Check with your mail provider that DKIM signing is switched on.");
  }

  if (!mxHosts.length) {
    add("info", "No MX records",
      "This domain doesn't publish mail servers, so it may not receive email at all.",
      "If the domain isn't used for email, a null MX record and a restrictive SPF make that explicit.");
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  return { grade, headline, summary, spoofable: !enforcing, findings };
}

// ---------- assembly ----------
// Takes raw DNS answers from whichever transport fetched them and produces the response
// body. Every transport ends here, so every transport produces identical output.
export function buildResult({ domain, rootTxt, dmarcTxt, mxHosts, dkimHits, triedCount }) {
  const spf = parseSpf(rootTxt);
  const dmarc = parseDmarc(dmarcTxt);
  dmarc.domain = domain;
  const dkim = { selectorsFound: [...dkimHits].sort(), triedCount };

  return {
    domain,
    checkedAt: new Date().toISOString(),
    ...assess({ spf, dmarc, dkim, mxHosts }),
    records: {
      spf: spf.present ? spf.record : null,
      dmarc: dmarc.present ? dmarc.record : null,
      dkimSelectors: dkim.selectorsFound,
      mx: mxHosts.slice(0, 5),
    },
  };
}
