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

function getMatchedNames(actor, query) {
  const q = normalize(query);
  if (!q) return [];

  const matches = [];
  const seen = new Set();

  for (const name of actor.names || []) {
    const normalizedName = normalize(name.name);
    if (!normalizedName) continue;

    let matchType = null;
    if (normalizedName === q) {
      matchType = "exact";
    } else if (normalizedName.startsWith(q)) {
      matchType = "prefix";
    } else if (normalizedName.includes(q)) {
      matchType = "partial";
    }

    if (!matchType) continue;

    const key = normalizedName;
    if (seen.has(key)) continue;
    seen.add(key);

    matches.push({
      name: name.name,
      normalized_name: normalizedName,
      name_type: name.name_type,
      name_types: name.name_types || [name.name_type].filter(Boolean),
      sources: name.sources || [],
      match_type: matchType
    });
  }

  return matches.sort((a, b) => {
    const order = { exact: 0, prefix: 1, partial: 2 };
    return (order[a.match_type] ?? 99) - (order[b.match_type] ?? 99)
      || a.name.localeCompare(b.name);
  });
}

function scoreActor(actor, query) {
  const q = normalize(query);
  if (!q) return 0;

  let score = 0;
  const techniqueFields = ((actor.observed_techniques || {}).items || []).flatMap(item => [
    item.technique_id,
    item.name,
    ...(item.tactics || [])
  ]);
  const attributionFields = (actor.reported_attribution || []).flatMap(item => [
    item.type,
    item.value,
    item.source_name
  ]);

  const fields = [
    actor.canonical_name,
    actor.mitre_id,
    actor.misp_uuid,
    actor.overview?.text,
    ...(actor.search_names || []),
    ...(actor.naming_sources || []),
    ...(actor.source_ids || []),
    ...techniqueFields,
    ...attributionFields,
    ...((actor.recent_activity || []).flatMap(item => [
      item.title,
      item.publisher,
      ...(item.matched_names || [])
    ]))
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

function labelForNameType(type) {
  const labels = {
    canonical: "代表名",
    alias: "別称",
    vendor_name: "ベンダー呼称",
    former: "旧称",
    temporary_cluster: "暫定クラスタ名"
  };
  return labels[type] || type || "名称";
}

function labelForAttributionType(type) {
  const labels = {
    country: "国・地域",
    region: "地域",
    motivation: "動機",
    microsoft_origin_or_threat: "Microsoft分類"
  };
  return labels[type] || type || "分類";
}

function labelForTactic(tactic) {
  const labels = {
    "reconnaissance": "偵察",
    "resource-development": "リソース開発",
    "initial-access": "初期アクセス",
    "execution": "実行",
    "persistence": "永続化",
    "privilege-escalation": "権限昇格",
    "defense-evasion": "防御回避",
    "credential-access": "認証情報アクセス",
    "discovery": "探索",
    "lateral-movement": "横展開",
    "collection": "収集",
    "command-and-control": "C2",
    "exfiltration": "持ち出し",
    "impact": "影響"
  };
  return labels[tactic] || tactic || "不明";
}

function labelForSourceOrg(sourceName) {
  const labels = {
    "Microsoft current": "Microsoft現行名",
    "Microsoft previous": "Microsoft旧称",
    "Microsoft other": "Microsoft掲載名"
  };
  return labels[sourceName] || sourceName || "不明";
}

function renderSourceBadges(name) {
  const sources = Array.isArray(name.sources) && name.sources.length
    ? name.sources
    : [{
        naming_org: name.naming_org || name.source_id || "Unknown",
        source_ids: [name.source_id].filter(Boolean),
        name_types: [name.name_type || "alias"],
        source_urls: name.source_urls || []
      }];

  return sources.map(source => {
    const sourceUrls = Array.isArray(source.source_urls) ? source.source_urls : [];
    const titleParts = [];
    if (source.name_types && source.name_types.length) {
      titleParts.push(source.name_types.map(labelForNameType).join(", "));
    }
    if (sourceUrls.length) {
      titleParts.push(sourceUrls.slice(0, 3).join("\n"));
    }

    const title = titleParts.length ? ` title="${escapeHtml(titleParts.join("\n"))}"` : "";
    return `<span class="source-badge"${title}>${escapeHtml(labelForSourceOrg(source.naming_org))}</span>`;
  }).join("");
}

function isMatchedName(name, matchedNames) {
  const normalizedName = normalize(name.name);
  return matchedNames.some(match => match.normalized_name === normalizedName);
}

function renderMatchedSummary(actor, matchedNames) {
  if (!state.query || !matchedNames.length) {
    return "";
  }

  const exactMatches = matchedNames.filter(match => match.match_type === "exact");
  const displayMatches = (exactMatches.length ? exactMatches : matchedNames).slice(0, 4);

  const matchBadges = displayMatches.map(match => {
    const typeLabels = Array.isArray(match.name_types) && match.name_types.length
      ? match.name_types.map(labelForNameType).join(" / ")
      : labelForNameType(match.name_type);

    return `
      <span class="matched-name-badge">
        ${escapeHtml(match.name)}
        <span class="matched-name-type">${escapeHtml(typeLabels)}</span>
      </span>
    `;
  }).join("");

  const canonicalNote = normalize(actor.canonical_name) === normalize(displayMatches[0]?.name)
    ? ""
    : `<div class="matched-note">この検索語は代表名ではなく、このアクターの別称として登録されています。</div>`;

  return `
    <div class="matched-summary">
      <div class="matched-label">検索一致</div>
      <div class="matched-values">${matchBadges}</div>
      ${canonicalNote}
    </div>
  `;
}

function sortNamesForDisplay(names, matchedNames) {
  const matchSet = new Set(matchedNames.map(match => match.normalized_name));
  const typePriority = {
    canonical: 0,
    vendor_name: 1,
    former: 2,
    alias: 3,
    temporary_cluster: 4
  };

  return (names || []).slice().sort((a, b) => {
    const aMatched = matchSet.has(normalize(a.name)) ? 0 : 1;
    const bMatched = matchSet.has(normalize(b.name)) ? 0 : 1;
    if (aMatched !== bMatched) return aMatched - bMatched;

    const aType = typePriority[a.name_type] ?? 99;
    const bType = typePriority[b.name_type] ?? 99;
    if (aType !== bType) return aType - bType;

    return a.name.localeCompare(b.name);
  });
}

function renderNames(names, matchedNames) {
  if (!names || !names.length) {
    return "<p class=\"muted\">名称情報はありません。</p>";
  }

  const sortedNames = sortNamesForDisplay(names, matchedNames);

  const items = sortedNames.map(name => {
    const typeLabels = Array.isArray(name.name_types) && name.name_types.length
      ? name.name_types.map(labelForNameType).join(" / ")
      : labelForNameType(name.name_type);
    const matched = isMatchedName(name, matchedNames);

    return `
      <li class="name-row${matched ? " name-row-match" : ""}">
        <span class="alias-name">${escapeHtml(name.name)}${matched ? `<span class="inline-match-label">検索一致</span>` : ""}</span>
        <span class="name-type">${escapeHtml(typeLabels)}</span>
        <span class="source-badges">${renderSourceBadges(name)}</span>
      </li>
    `;
  }).join("");

  return `<ul class="names">${items}</ul>`;
}

function renderSourceSummary(actor) {
  const sources = actor.naming_sources || [];

  if (!sources.length) {
    return "";
  }

  return `
    <div class="source-summary">
      <strong>呼称確認元:</strong>
      ${sources.map(source => `<span class="badge badge-source">${escapeHtml(labelForSourceOrg(source))}</span>`).join("")}
    </div>
  `;
}

function renderOverview(actor) {
  const overview = actor.overview;
  if (!overview || !overview.text) {
    return "";
  }

  const sources = (overview.sources || []).map(source => {
    const urls = source.source_urls || [];
    if (urls.length) {
      return `<a href="${escapeHtml(urls[0])}" target="_blank" rel="noopener noreferrer">${escapeHtml(source.source_name || source.source_id)}</a>`;
    }
    return escapeHtml(source.source_name || source.source_id || "不明");
  }).join(", ");

  return `
    <section class="card-section overview">
      <h3>概要</h3>
      <p>${escapeHtml(overview.text)}</p>
      ${sources ? `<div class="section-source">出典: ${sources}</div>` : ""}
    </section>
  `;
}

function renderAttribution(actor) {
  const rows = actor.reported_attribution || [];
  if (!rows.length) {
    return "";
  }

  const items = rows.map(row => {
    const urls = row.source_urls || [];
    const source = urls.length
      ? `<a href="${escapeHtml(urls[0])}" target="_blank" rel="noopener noreferrer">${escapeHtml(row.source_name || row.source_id)}</a>`
      : escapeHtml(row.source_name || row.source_id || "不明");

    return `
      <li>
        <span class="attr-type">${escapeHtml(labelForAttributionType(row.type))}</span>
        <span class="attr-value">${escapeHtml(row.value)}</span>
        <span class="attr-source">${source}</span>
      </li>
    `;
  }).join("");

  return `
    <section class="card-section attribution">
      <h3>推定帰属</h3>
      <ul>${items}</ul>
      <p class="section-note">出典に記載された情報を表示しています。本DBは帰属を独自に断定しません。</p>
    </section>
  `;
}

function renderObservedTechniques(actor) {
  const data = actor.observed_techniques || {};
  const items = data.items || [];
  if (!items.length) {
    return "";
  }

  const tacticSummary = (data.tactics || []).slice(0, 6).map(tactic => {
    return `<span class="tactic-badge">${escapeHtml(labelForTactic(tactic.tactic))} <span>${escapeHtml(tactic.count)}</span></span>`;
  }).join("");

  const techniqueItems = items.map(item => {
    const tacticLabels = (item.tactics || []).map(tactic => {
      return `<span class="technique-tactic">${escapeHtml(labelForTactic(tactic))}</span>`;
    }).join("");

    const label = `${item.technique_id || ""} ${item.name || ""}`.trim();
    const link = item.url
      ? `<a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`
      : escapeHtml(label);

    return `
      <li>
        <span class="technique-name">${link}</span>
        <span class="technique-tactics">${tacticLabels}</span>
      </li>
    `;
  }).join("");

  const more = data.total && data.total > items.length
    ? `<div class="section-note">MITRE ATT&amp;CKにおける関連Technique ${data.total}件のうち、${items.length}件を表示しています。</div>`
    : "";

  return `
    <section class="card-section techniques">
      <h3>観測された主な攻撃手法</h3>
      ${tacticSummary ? `<div class="tactic-summary">${tacticSummary}</div>` : ""}
      <ul>${techniqueItems}</ul>
      ${more}
    </section>
  `;
}

function renderRecentActivity(actor) {
  const activity = actor.recent_activity || [];
  if (!activity.length) {
    return "";
  }

  const items = activity.slice(0, 5).map(item => {
    const matched = (item.matched_names || []).map(name => `<span class="activity-match">${escapeHtml(name)}</span>`).join("");
    const date = item.published_date || "日付不明";
    const publisher = item.publisher || "発行元不明";

    return `
      <li class="activity-item">
        <div class="activity-meta">${escapeHtml(date)} / ${escapeHtml(publisher)}</div>
        <a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.title)}</a>
        ${matched ? `<div class="activity-matches">一致名: ${matched}</div>` : ""}
      </li>
    `;
  }).join("");

  return `
    <section class="card-section recent-activity">
      <h3>最近の動向</h3>
      <ul>${items}</ul>
    </section>
  `;
}

function renderActor(actor, matchedNames) {
  const refs = (actor.references || [])
    .slice(0, 8)
    .map(ref => `<li><a href="${escapeHtml(ref.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(ref.url)}</a></li>`)
    .join("");

  const moreRefs = (actor.references || []).length > 8
    ? `<li class="name-source">...ほか ${(actor.references || []).length - 8} 件の参照情報がJSONデータに含まれています</li>`
    : "";

  return `
    <article class="card">
      <h2>${escapeHtml(actor.canonical_name)}</h2>

      ${renderMatchedSummary(actor, matchedNames)}

      <div class="meta">
        ${actor.mitre_id ? `<span class="badge">MITRE ${escapeHtml(actor.mitre_id)}</span>` : ""}
        ${actor.misp_uuid ? `<span class="badge">MISP Galaxy</span>` : ""}
        <span class="badge">${escapeHtml(actor.confidence || "不明")}</span>
      </div>

      ${renderSourceSummary(actor)}
      ${renderOverview(actor)}
      ${renderAttribution(actor)}
      ${renderObservedTechniques(actor)}
      ${renderRecentActivity(actor)}

      <section class="card-section">
        <h3>名称・別称</h3>
        ${renderNames(actor.names || [], matchedNames)}
      </section>

      <section class="card-section references">
        <h3>参照情報</h3>
        <ul>${refs || "<li>参照情報はありません</li>"}${moreRefs}</ul>
      </section>
    </article>
  `;
}

function render() {
  const query = queryEl.value.trim();
  state.query = query;

  if (!query) {
    statsEl.textContent = `${state.index.length}件のアクター情報を読み込みました。名称、別称、ID、出典組織、帰属情報、攻撃手法で検索できます。`;
    resultsEl.innerHTML = `<div class="empty">検索語を入力してください。</div>`;
    return;
  }

  const matches = state.index
    .map(actor => ({ actor, score: scoreActor(actor, query), matchedNames: getMatchedNames(actor, query) }))
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score || a.actor.canonical_name.localeCompare(b.actor.canonical_name))
    .slice(0, 50);

  statsEl.textContent = `「${query}」の検索結果: ${matches.length}件`;

  if (!matches.length) {
    resultsEl.innerHTML = `<div class="empty">一致するアクターは見つかりませんでした。</div>`;
    return;
  }

  resultsEl.innerHTML = matches.map(item => renderActor(item.actor, item.matchedNames)).join("");
}

async function loadIndex() {
  try {
    const response = await fetch("data/search-index.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    state.index = await response.json();
    render();
  } catch (error) {
    statsEl.textContent = `検索インデックスの読み込みに失敗しました: ${error.message}`;
    resultsEl.innerHTML = `<div class="empty">更新スクリプトまたはGitHub Actionsを実行して docs/data/search-index.json を生成してください。</div>`;
  }
}

queryEl.addEventListener("input", render);
loadIndex();
