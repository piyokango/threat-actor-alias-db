const state = {
  index: [],
  query: ""
};

const queryEl = document.getElementById("query");
const resultsEl = document.getElementById("results");
const statsEl = document.getElementById("stats");

function normalize(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[\s_\-./]+/g, " ")
    .replace(/[^\p{L}\p{N} ]+/gu, "")
    .replace(/\s+/g, " ")
    .trim();
}

function scoreActor(actor, query) {
  const q = normalize(query);
  if (!q) return 0;

  let score = 0;
  const fields = [
    actor.canonical_name,
    actor.mitre_id,
    actor.misp_uuid,
    ...(actor.search_names || []),
    ...(actor.naming_sources || []),
    ...(actor.source_ids || [])
  ].filter(Boolean);

  for (const field of fields) {
    const n = normalize(field);
    if (n === q) score = Math.max(score, 100);
    else if (n.startsWith(q)) score = Math.max(score, 80);
    else if (n.includes(q)) score = Math.max(score, 50);
  }

  return score;
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderActor(actor) {
  const names = (actor.names || [])
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name))
    .map(name => `<li>${escapeHtml(name.name)} <span class="name-source">(${escapeHtml(name.naming_org)} / ${escapeHtml(name.name_type)})</span></li>`)
    .join("");

  const refs = (actor.references || [])
    .slice(0, 8)
    .map(ref => `<li><a href="${escapeHtml(ref.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(ref.url)}</a></li>`)
    .join("");

  const moreRefs = (actor.references || []).length > 8
    ? `<li class="name-source">...and ${(actor.references || []).length - 8} more references in the JSON data</li>`
    : "";

  return `
    <article class="card">
      <h2>${escapeHtml(actor.canonical_name)}</h2>
      <div class="meta">
        ${actor.mitre_id ? `<span class="badge">MITRE ${escapeHtml(actor.mitre_id)}</span>` : ""}
        ${actor.misp_uuid ? `<span class="badge">MISP</span>` : ""}
        ${(actor.naming_sources || []).map(s => `<span class="badge">${escapeHtml(s)}</span>`).join("")}
        <span class="badge">${escapeHtml(actor.confidence || "unknown")}</span>
      </div>
      <strong>Names and aliases</strong>
      <ul class="names">${names || "<li>No aliases available</li>"}</ul>
      <div class="references">
        <strong>References</strong>
        <ul>${refs || "<li>No references available</li>"}${moreRefs}</ul>
      </div>
    </article>
  `;
}

function render() {
  const query = queryEl.value.trim();
  state.query = query;

  if (!query) {
    statsEl.textContent = `${state.index.length} actors loaded. Enter a name, alias, or ID to search.`;
    resultsEl.innerHTML = `<div class="empty">Enter a search term to begin.</div>`;
    return;
  }

  const matches = state.index
    .map(actor => ({ actor, score: scoreActor(actor, query) }))
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score || a.actor.canonical_name.localeCompare(b.actor.canonical_name))
    .slice(0, 50);

  statsEl.textContent = `${matches.length} result(s) for "${query}"`;

  if (!matches.length) {
    resultsEl.innerHTML = `<div class="empty">No matching actors found.</div>`;
    return;
  }

  resultsEl.innerHTML = matches.map(item => renderActor(item.actor)).join("");
}

async function loadIndex() {
  try {
    const response = await fetch("data/search-index.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    state.index = await response.json();
    render();
  } catch (error) {
    statsEl.textContent = `Failed to load search index: ${error.message}`;
    resultsEl.innerHTML = `<div class="empty">Run the update scripts or GitHub Actions to generate docs/data/search-index.json.</div>`;
  }
}

queryEl.addEventListener("input", render);
loadIndex();
