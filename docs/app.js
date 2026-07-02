const state = {
  index: [],
  query: "",
  extendedSearch: false
};

const queryEl = document.getElementById("query");
const resultsEl = document.getElementById("results");
const statsEl = document.getElementById("stats");

let extendedSearchEl = null;

function normalize(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[\s_\-./]+/g, " ")
    .replace(/[^\p{L}\p{N} ]+/gu, "")
    .replace(/\s+/g, " ")
    .trim();
}

function makeExtendedSearchControl() {
  const panel = queryEl.closest(".search-panel") || queryEl.parentElement;
  if (!panel || document.getElementById("extended-search")) {
    extendedSearchEl = document.getElementById("extended-search");
    return;
  }

  const wrapper = document.createElement("label");
  wrapper.className = "extended-search-control";
  wrapper.innerHTML = `
    <input id="extended-search" type="checkbox">
    <span>概要・帰属・ATT&amp;CK・最近の動向も検索対象にする</span>
  `;

  const statsNode = document.getElementById("stats");
  if (statsNode && statsNode.parentNode === panel) {
    panel.insertBefore(wrapper, statsNode);
  } else {
    panel.appendChild(wrapper);
  }

  extendedSearchEl = document.getElementById("extended-search");
  extendedSearchEl.addEventListener("change", () => {
    state.extendedSearch = extendedSearchEl.checked;
    render();
  });
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

function fieldMatchScore(value, query) {
  const q = normalize(query);
  const n = normalize(value);
  if (!q || !n) return 0;
  if (n === q) return 100;
  if (n.startsWith(q)) return 80;
  if (n.includes(q)) return 50;
  return 0;
}

function collectBasicSearchFields(actor) {
  return [
    { value: actor.canonical_name, reason: "代表名" },
    { value: actor.mitre_id, reason: "MITRE ID" },
    { value: actor.misp_uuid, reason: "MISP UUID" },
    ...((actor.search_names || []).map(value => ({ value, reason: "名称・別称" }))),
    ...((actor.source_ids || []).map(value => ({ value, reason: "データソースID" })))
  ].filter(item => item.value);
}

function collectExtendedSearchFields(actor) {
  const attributionData = actor.reported_attribution || {};
  const attributionFields = [
    ...((attributionData.countries || []).flatMap(item => [
      { value: item.value, reason: "推定帰属" },
      { value: item.display_value, reason: "推定帰属" },
      { value: item.country_code, reason: "推定帰属" },
      ...((item.sources || []).map(source => ({ value: source.source_name || source.source_id, reason: "推定帰属の出典" })))
    ])),
    ...((attributionData.classifications || []).flatMap(item => [
      { value: item.type, reason: "分類・動機" },
      { value: item.value, reason: "分類・動機" },
      { value: item.display_value, reason: "分類・動機" },
      ...((item.sources || []).map(source => ({ value: source.source_name || source.source_id, reason: "分類・動機の出典" })))
    ]))
  ];

  const techniqueFields = [
    ...(((actor.observed_techniques || {}).items || []).flatMap(item => [
      { value: item.technique_id, reason: "ATT&CK Technique" },
      { value: item.name, reason: "ATT&CK Technique" },
      ...((item.tactics || []).map(tactic => ({ value: tactic, reason: "ATT&CK Tactic" })))
    ])),
    ...(((actor.observed_techniques || {}).tactic_groups || []).map(group => ({ value: labelForTactic(group.tactic), reason: "ATT&CK Tactic" })))
  ];

  const activityFields = (actor.recent_activity || []).flatMap(item => [
    { value: item.title, reason: "最近の動向" },
    { value: item.publisher, reason: "最近の動向の発行元" },
    ...((item.matched_names || []).map(value => ({ value, reason: "最近の動向の一致名" })))
  ]);

  return [
    { value: actor.overview?.text, reason: "概要" },
    ...((actor.naming_sources || []).map(value => ({ value, reason: "呼称確認元" }))),
    ...attributionFields,
    ...techniqueFields,
    ...activityFields
  ].filter(item => item.value);
}

function getMatchReasons(actor, query, includeExtended) {
  const seen = new Set();
  const reasons = [];

  const basicFields = collectBasicSearchFields(actor);
  const extendedFields = includeExtended ? collectExtendedSearchFields(actor) : [];

  for (const field of [...basicFields, ...extendedFields]) {
    const score = fieldMatchScore(field.value, query);
    if (!score) continue;
    const key = `${field.reason}:${normalize(field.value)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    reasons.push({
      reason: field.reason,
      value: field.value,
      score
    });
  }

  return reasons.sort((a, b) => b.score - a.score || a.reason.localeCompare(b.reason)).slice(0, 5);
}

function scoreActor(actor, query, includeExtended) {
  const fields = includeExtended
    ? [...collectBasicSearchFields(actor), ...collectExtendedSearchFields(actor)]
    : collectBasicSearchFields(actor);

  let score = 0;
  for (const field of fields) {
    score = Math.max(score, fieldMatchScore(field.value, query));
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


function flagFromCountryCode(countryCode) {
  const code = String(countryCode || "").toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return "";
  return Array.from(code).map(char => String.fromCodePoint(127397 + char.charCodeAt(0))).join("");
}

function fallbackCountryFlag(value) {
  const normalized = normalize(value);
  const map = {
    "russia": "🇷🇺",
    "russian federation": "🇷🇺",
    "china": "🇨🇳",
    "north korea": "🇰🇵",
    "dprk": "🇰🇵",
    "iran": "🇮🇷",
    "vietnam": "🇻🇳",
    "india": "🇮🇳",
    "pakistan": "🇵🇰",
    "turkey": "🇹🇷",
    "israel": "🇮🇱",
    "lebanon": "🇱🇧",
    "syria": "🇸🇾",
    "belarus": "🇧🇾",
    "ukraine": "🇺🇦",
    "united states": "🇺🇸",
    "usa": "🇺🇸",
    "united kingdom": "🇬🇧",
    "uk": "🇬🇧"
  };
  return map[normalized] || "";
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
    if (source.source_relations && source.source_relations.length) {
      titleParts.push(source.source_relations.join(", "));
    }
    if (sourceUrls.length) {
      titleParts.push(sourceUrls.slice(0, 3).join("\n"));
    }

    const title = titleParts.length ? ` title="${escapeHtml(titleParts.join("\n"))}"` : "";
    return `<span class="source-badge"${title}>${escapeHtml(labelForSourceOrg(source.naming_org || "Unknown"))}</span>`;
  }).join("");
}

function isMatchedName(name, matchedNames) {
  const normalizedName = normalize(name.name);
  return matchedNames.some(match => match.normalized_name === normalizedName);
}

function renderMatchedSummary(actor, matchedNames, matchReasons) {
  if (!state.query) {
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

  const suppressReasons = new Set(["代表名", "名称・別称"]);
  const filteredReasons = (matchReasons || []).filter(reason => {
    if (!matchedNames.length) return true;
    return !suppressReasons.has(reason.reason);
  });

  const reasonBadges = filteredReasons.map(reason => {
    return `
      <span class="match-reason-badge">
        ${escapeHtml(reason.reason)}: ${escapeHtml(reason.value)}
      </span>
    `;
  }).join("");

  const canonicalNote = displayMatches.length && normalize(actor.canonical_name) !== normalize(displayMatches[0]?.name)
    ? `<div class="matched-note">この検索語は代表名ではなく、このアクターの別称として登録されています。</div>`
    : "";

  if (!matchBadges && !reasonBadges) {
    return "";
  }

  return `
    <div class="matched-summary">
      <div class="matched-label">検索一致</div>
      ${matchBadges ? `<div class="matched-values">${matchBadges}</div>` : ""}
      ${reasonBadges ? `<div class="match-reasons">${reasonBadges}</div>` : ""}
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
  const data = actor.reported_attribution || {};
  const countries = data.countries || [];
  const classifications = data.classifications || [];

  if (!countries.length && !classifications.length) {
    return "";
  }

  function renderSourceList(sources) {
    return (sources || []).map(source => {
      const urls = source.source_urls || [];
      const name = source.source_name || source.source_id || "不明";
      if (urls.length) {
        return `<a href="${escapeHtml(urls[0])}" target="_blank" rel="noopener noreferrer">${escapeHtml(name)}</a>`;
      }
      return escapeHtml(name);
    }).join(" / ");
  }

  const countryItems = countries.map(item => {
    const resolvedFlag = item.flag || flagFromCountryCode(item.country_code) || fallbackCountryFlag(item.display_value || item.value);
    const flag = resolvedFlag ? `<span class="attr-flag">${escapeHtml(resolvedFlag)}</span>` : "";
    const code = item.country_code ? `<span class="attr-code">${escapeHtml(item.country_code)}</span>` : "";
    return `
      <li class="country-row">
        <span class="attr-country">${flag}<span class="attr-value">${escapeHtml(item.display_value || item.value)}</span>${code}</span>
        <span class="attr-source">${renderSourceList(item.sources)}</span>
      </li>
    `;
  }).join("");

  const classificationItems = classifications.map(item => {
    return `
      <li>
        <span class="attr-type">${escapeHtml(labelForAttributionType(item.type))}</span>
        <span class="attr-value">${escapeHtml(item.display_value || item.value)}</span>
        <span class="attr-source">${renderSourceList(item.sources)}</span>
      </li>
    `;
  }).join("");

  return `
    <section class="card-section attribution">
      <h3>推定帰属</h3>
      ${countryItems ? `<ul class="country-list">${countryItems}</ul>` : ""}
      ${classificationItems ? `<div class="classification-heading">分類・動機</div><ul>${classificationItems}</ul>` : ""}
      <p class="section-note">出典に記載された情報を値単位で集約して表示しています。本DBは帰属を独自に断定しません。</p>
    </section>
  `;
}

function renderObservedTechniques(actor) {
  const data = actor.observed_techniques || {};
  const groups = data.tactic_groups || [];
  const summary = data.tactics || [];

  if (!groups.length && !(data.items || []).length) {
    return "";
  }

  const actorKey = normalize(actor.actor_id || actor.canonical_name).replace(/\s+/g, "-");

  const tacticSummary = summary.slice(0, 8).map(tactic => {
    const groupId = `technique-group-${actorKey}-${normalize(tactic.tactic).replace(/\s+/g, "-")}`;
    const tacticLabel = labelForTactic(tactic.tactic);
    const tacticId = tactic.tactic_id ? `<span class="tactic-id">${escapeHtml(tactic.tactic_id)}</span>` : "";
    return `
      <button class="tactic-badge tactic-jump" type="button" data-target="${escapeHtml(groupId)}">
        ${tacticId}
        <span>${escapeHtml(tacticLabel)}</span>
        <strong>${escapeHtml(tactic.count)}</strong>
      </button>
    `;
  }).join("");

  const groupItems = groups.map((group, index) => {
    const groupId = `technique-group-${actorKey}-${normalize(group.tactic).replace(/\s+/g, "-")}`;
    const itemList = (group.items || []).map(item => {
      const label = `${item.technique_id || ""} ${item.name || ""}`.trim();
      const link = item.url
        ? `<a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`
        : escapeHtml(label);
      return `<li><span class="technique-name">${link}</span></li>`;
    }).join("");

    const openAttr = index === 0 ? " open" : "";
    const tacticId = group.tactic_id ? `<span class="technique-group-id">${escapeHtml(group.tactic_id)}</span>` : "";
    const title = `${group.tactic_id ? group.tactic_id + " " : ""}${labelForTactic(group.tactic)}`;

    return `
      <details id="${escapeHtml(groupId)}" class="technique-group"${openAttr}>
        <summary>
          <span class="technique-group-title">${tacticId}${escapeHtml(labelForTactic(group.tactic))}</span>
          <span class="technique-group-count">${escapeHtml(group.count)}件</span>
        </summary>
        ${group.url ? `<div class="technique-group-link"><a href="${escapeHtml(group.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(title)} をATT&CKで開く</a></div>` : ""}
        <ul>${itemList}</ul>
      </details>
    `;
  }).join("");

  return `
    <section class="card-section techniques">
      <h3>観測された主な攻撃手法</h3>
      ${tacticSummary ? `<div class="tactic-summary">${tacticSummary}</div>` : ""}
      <div class="technique-groups">${groupItems}</div>
      ${data.total ? `<div class="section-note">MITRE ATT&amp;CKにおける関連Technique ${data.total}件をTactic別に表示しています。上部のラベルをクリックすると該当Tacticへ移動します。</div>` : ""}
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

function renderActor(actor, matchedNames, matchReasons) {
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

      ${renderMatchedSummary(actor, matchedNames, matchReasons)}

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
  state.extendedSearch = !!(extendedSearchEl && extendedSearchEl.checked);

  if (!query) {
    const mode = state.extendedSearch ? "拡張検索" : "通常検索";
    statsEl.textContent = `${state.index.length}件のアクター情報を読み込みました。${mode}では${state.extendedSearch ? "概要、帰属、ATT&CK、最近の動向も検索対象です。" : "名称、別称、IDを検索対象にします。"}`;
    resultsEl.innerHTML = `<div class="empty">検索語を入力してください。</div>`;
    return;
  }

  const matches = state.index
    .map(actor => ({
      actor,
      score: scoreActor(actor, query, state.extendedSearch),
      matchedNames: getMatchedNames(actor, query),
      matchReasons: getMatchReasons(actor, query, state.extendedSearch)
    }))
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score || a.actor.canonical_name.localeCompare(b.actor.canonical_name))
    .slice(0, 50);

  const modeLabel = state.extendedSearch ? "拡張検索" : "通常検索";
  statsEl.textContent = `「${query}」の検索結果: ${matches.length}件（${modeLabel}）`;

  if (!matches.length) {
    resultsEl.innerHTML = `<div class="empty">一致するアクターは見つかりませんでした。</div>`;
    return;
  }

  resultsEl.innerHTML = matches.map(item => renderActor(item.actor, item.matchedNames, item.matchReasons)).join("");
}

async function loadIndex() {
  try {
    makeExtendedSearchControl();
    const response = await fetch("data/search-index.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    state.index = await response.json();
    render();
  } catch (error) {
    statsEl.textContent = `検索インデックスの読み込みに失敗しました: ${error.message}`;
    resultsEl.innerHTML = `<div class="empty">更新スクリプトまたはGitHub Actionsを実行して docs/data/search-index.json を生成してください。</div>`;
  }
}

document.addEventListener("click", event => {
  const button = event.target.closest(".tactic-jump");
  if (!button) return;

  const targetId = button.getAttribute("data-target");
  if (!targetId) return;

  const target = document.getElementById(targetId);
  if (!target) return;

  target.open = true;
  target.classList.add("technique-group-highlight");
  target.scrollIntoView({ behavior: "smooth", block: "center" });

  window.setTimeout(() => {
    target.classList.remove("technique-group-highlight");
  }, 1600);
});

queryEl.addEventListener("input", render);
loadIndex();
