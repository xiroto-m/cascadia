// src/main.js - Core application logic, routing, search, and quiz engine

// Note: Imports removed to run correctly on local file:// protocol via global window scope.

// DOM Elements
const sidebarToggle = document.getElementById('sidebarToggle');
const sidebar = document.getElementById('sidebar');
const hamburgerBtn = document.getElementById('hamburgerBtn');
const searchInput = document.getElementById('searchInput');
const sidebarNav = document.getElementById('sidebarNav');
const currentPath = document.getElementById('currentPath');
const contentArea = document.getElementById('contentArea');
const statusBadge = document.getElementById('statusBadge');
const logoLink = document.getElementById('logoLink');

// Navigation state
let activePage = 'home';

// Quiz local state
let quizState = JSON.parse(localStorage.getItem('cascadia_quiz') || 'null') || {
  xp: 0, totalCorrect: 0, totalAnswered: 0, streak: 0, maxStreak: 0,
  chapterScores: {}, achievements: []
};

let ALL_QUIZZES = [];

let curQuiz = null;
let curIdx = 0;
let curCorrect = 0;
let quizAnswered = false;
let pendingChId = null;

// 有識者確認モードおよびチェックリストのグローバル状態（確認モードは常にONに固定）
let expertVerifyModeActive = true;
let verifiedItems = JSON.parse(localStorage.getItem('cascadia_verified_items') || '[]');

// Initialize app after auth verification
document.addEventListener('DOMContentLoaded', () => {
  if (checkSession()) {
    initApp();
  } else {
    showLogin(initApp);
  }
});

function initApp() {
  ALL_QUIZZES = [...(window.SALES_QUIZ || []), ...(window.OPS_QUIZ || [])];
  generateNavTree();
  setupEventListeners();
  updateExpertVerifyModeUI();
  navigateTo('home');
  updateProgress();
}

function updateExpertVerifyModeUI() {
  // 有識者確認モードは常にONに固定されるため、常にクラスを追加
  document.body.classList.add('sme-mode-active');
}

// Generate the sidebar navigation dynamically
function generateNavTree() {
  let navHtml = `
    <!-- General -->
    <div class="nav-section">
      <div class="nav-section-title open" data-section="general">
        <svg class="chevron" viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg>
        はじめに
      </div>
      <div class="nav-section-items show">
        <a class="nav-item" data-page="home">
          <span class="nav-dot"></span>ポータルホーム
        </a>
      </div>
    </div>

    <!-- Sales Manual -->
    <div class="nav-section">
      <div class="nav-section-title" data-section="sales">
        <svg class="chevron" viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg>
        営業部マニュアル
      </div>
      <div class="nav-section-items">
        <a class="nav-item" data-page="ch1"><span class="nav-dot"></span>第1章 フィロソフィー</a>
        <a class="nav-item" data-page="ch2"><span class="nav-dot"></span>第2章 牛の基礎知識</a>
        <a class="nav-item" data-page="ch2-lactation"><span class="nav-dot"></span>├ 泌乳曲線と管理</a>
        <a class="nav-item" data-page="ch2-milk"><span class="nav-dot"></span>├ 牛乳の成分合成</a>
        <a class="nav-item" data-page="ch2-fatcalcium"><span class="nav-dot"></span>├ 脂肪酸Caバイパス</a>
        <a class="nav-item" data-page="ch2-analysis"><span class="nav-dot"></span>├ 飼料分析値の読み方</a>
        <a class="nav-item" data-page="ch2-vitmin"><span class="nav-dot"></span>└ ビタミン・ミネラル</a>
        <a class="nav-item" data-page="ch3"><span class="nav-dot"></span>第3章 逆引きインデックス</a>
        <a class="nav-item" data-page="ch4"><span class="nav-dot"></span>第4章 商品カタログ</a>
        <a class="nav-item" data-page="ch4-hay"><span class="nav-dot"></span>├ 乾草（牧草）</a>
        <a class="nav-item" data-page="ch4-sil"><span class="nav-dot"></span>├ サイレージ</a>
        <a class="nav-item" data-page="ch4-byp"><span class="nav-dot"></span>├ バイパス脂肪・蛋白</a>
        <a class="nav-item" data-page="ch4-comp"><span class="nav-dot"></span>├ 混合・代用乳</a>
        <a class="nav-item" data-page="ch4-px"><span class="nav-dot"></span>├ プレミックス・添加剤</a>
        <a class="nav-item" data-page="ch4-eqp"><span class="nav-dot"></span>├ 酪農機器・資材</a>
        <a class="nav-item" data-page="ch4-mowment"><span class="nav-dot"></span>├ 繁殖管理 @mowment</a>
        <a class="nav-item" data-page="ch4-mowment-inv"><span class="nav-dot"></span>├ @mowment 機材・在庫管理</a>
        <a class="nav-item" data-page="ch4-makiba"><span class="nav-dot"></span>├ 牛群管理 まきばノート</a>
        <a class="nav-item" data-page="ch4-food"><span class="nav-dot"></span>├ 飼料（その他）</a>
        <a class="nav-item" data-page="ch4-svc"><span class="nav-dot"></span>├ サービス・コンサル</a>
        <a class="nav-item" data-page="ch4-fat"><span class="nav-dot"></span>└ 脂肪酸の機能使い分け</a>
        <a class="nav-item" data-page="appendix"><span class="nav-dot"></span>業界用語・辞書</a>
        <a class="nav-item" data-page="app-pack"><span class="nav-dot"></span>荷姿・物流・単位</a>
        <a class="nav-item" data-page="ch5"><span class="nav-dot"></span>第5章 バックオフィス関連</a>
        <a class="nav-item" data-page="ch5-car"><span class="nav-dot"></span>├ 総務：社用車トラブル・事故対応</a>
        <a class="nav-item" data-page="ch5-hr"><span class="nav-dot"></span>├ 人事：貸与物品借用書の申請</a>
        <a class="nav-item" data-page="ch4-mowment-inv"><span class="nav-dot"></span>├ LAT事業：@mowment 機材・在庫管理</a>
        <a class="nav-item" data-page="ch5-acct"><span class="nav-dot"></span>└ 経理：準備中</a>
      </div>
    </div>

    <!-- Operations Manual -->
    <div class="nav-section">
      <div class="nav-section-title" data-section="ops">
        <svg class="chevron" viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg>
        業務部マニュアル
      </div>
      <div class="nav-section-items">
        <a class="nav-item" data-page="dom-buy"><span class="nav-dot"></span>01-1 買継取引（国内）</a>
        <a class="nav-item" data-page="dom-stock"><span class="nav-dot"></span>01-2 在庫取引（国内）</a>
        <a class="nav-item" data-page="imp-buy"><span class="nav-dot"></span>02-1 買継取引（輸入）</a>
        <a class="nav-item" data-page="expense"><span class="nav-dot"></span>03-1 諸掛処理</a>
        <a class="nav-item" data-page="warehouse"><span class="nav-dot"></span>03-2 倉庫移動</a>
        <a class="nav-item" data-page="returns"><span class="nav-dot"></span>04 返品処理</a>
        <a class="nav-item" data-page="billing"><span class="nav-dot"></span>05 請求〜回収</a>
        <a class="nav-item" data-page="pay-dom"><span class="nav-dot"></span>06-1 支払〜出金（国内）</a>
        <a class="nav-item" data-page="pay-intl"><span class="nav-dot"></span>06-2 支払〜出金（海外）</a>
        <a class="nav-item" data-page="accounting"><span class="nav-dot"></span>07 会計連携</a>
      </div>
    </div>

    <!-- Utility Tools -->
    <div class="nav-section">
      <div class="nav-section-title" data-section="tools">
        <svg class="chevron" viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg>
        実務便利ツール
      </div>
      <div class="nav-section-items">
        <a class="nav-item" data-page="date-calculator"><span class="nav-dot"></span>営業日・デマレージ計算</a>
        <a class="nav-item" data-page="schedule-assistant"><span class="nav-dot"></span>得意先スケジュール支援</a>
        <a class="nav-item" data-page="flexcon-inventory"><span class="nav-dot"></span>フレコンバッグ在庫・金額管理</a>
      </div>
    </div>

    <!-- Quiz game -->
    <div class="nav-section">
      <div class="nav-section-title" data-section="quiz">
        <svg class="chevron" viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg>
        営業力チェック
      </div>
      <div class="nav-section-items">
        <a class="nav-item" data-page="quiz-dashboard"><span class="nav-dot"></span>理解度クイズ</a>
      </div>
    </div>
  `;

  sidebarNav.innerHTML = navHtml;

  // Bind nav toggle listeners
  document.querySelectorAll('.nav-section-title').forEach(title => {
    title.addEventListener('click', () => {
      title.classList.toggle('open');
      title.nextElementSibling.classList.toggle('show');
    });
  });

  // Bind nav item click listeners
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      navigateTo(item.dataset.page);
    });
  });
}

function setupEventListeners() {
  // Sidebar toggle for desktop/tablet
  sidebarToggle.addEventListener('click', () => {
    sidebar.classList.toggle('open');
  });

  // Hamburger button for mobile
  hamburgerBtn.addEventListener('click', () => {
    sidebar.classList.add('open');
  });

  // Close sidebar on mobile clicking background or logo
  logoLink.addEventListener('click', (e) => {
    e.preventDefault();
    navigateTo('home');
  });

  // Search input event
  searchInput.addEventListener('input', handleGlobalSearch);

  // Bind keydown escapes
  document.getElementById('btnCloseModal').addEventListener('click', closeModal);
  document.getElementById('quizModal').addEventListener('click', (e) => {
    if (e.target.id === 'quizModal') closeModal();
  });

  // Screen preview modal event bindings
  document.getElementById('btnClosePreviewModal').addEventListener('click', closePreviewModal);
  document.getElementById('previewModal').addEventListener('click', (e) => {
    if (e.target.id === 'previewModal') closePreviewModal();
  });

  // 有識者確認モードは常にONに固定されるため、トグルのバインドは不要
}

// Router to handle page switches
function navigateTo(pageId, highlightSearch = null) {
  activePage = pageId;
  const content = contentArea;

  // Clear focus / close sidebar on mobile
  if (window.innerWidth <= 1024) {
    sidebar.classList.remove('open');
  }

  // Update sidebar active classes
  document.querySelectorAll('.nav-item').forEach(item => {
    if (item.dataset.page === pageId) {
      item.classList.add('active');
      // Ensure the parent section is expanded
      const parentItems = item.closest('.nav-section-items');
      const parentTitle = parentItems.previousElementSibling;
      parentItems.classList.add('show');
      parentTitle.classList.add('open');
    } else {
      item.classList.remove('active');
    }
  });

  // Scroll to top
  window.scrollTo({ top: 0, behavior: 'instant' });

  // 1. Home Portal Rendering
  if (pageId === 'home') {
    currentPath.textContent = 'ホーム';
    statusBadge.textContent = 'ポータル';
    statusBadge.className = 'status-badge';
    renderPortalHome();
    return;
  }

  // 2. Quiz Dashboard Rendering
  if (pageId === 'quiz-dashboard') {
    currentPath.textContent = '営業力チェック';
    statusBadge.textContent = '学習ゲーム';
    statusBadge.className = 'status-badge status-sales-approved';
    renderQuizDashboard();
    return;
  }

  // 2.5 Utility Tools Rendering
  if (pageId === 'date-calculator') {
    currentPath.textContent = '便利ツール ＞ 営業日・デマレージ計算';
    statusBadge.textContent = 'ツール';
    statusBadge.className = 'status-badge status-sales-approved';
    renderDateCalculator();
    return;
  }

  if (pageId === 'schedule-assistant') {
    currentPath.textContent = '便利ツール ＞ 得意先スケジュール支援';
    statusBadge.textContent = 'ツール';
    statusBadge.className = 'status-badge status-sales-approved';
    renderScheduleAssistant();
    return;
  }

  if (pageId === 'lat-inventory-tool') {
    currentPath.textContent = '実務便利ツール ＞ LAT機材・在庫金額計算ツール';
    statusBadge.textContent = '実務ツール';
    statusBadge.className = 'status-badge status-sales-approved';
    renderLatInventoryTool();
    return;
  }

  if (pageId === 'flexcon-inventory') {
    currentPath.textContent = '便利ツール ＞ フレコンバッグ在庫・金額管理';
    statusBadge.textContent = 'ツール';
    statusBadge.className = 'status-badge status-sales-approved';
    renderFlexconInventory();
    return;
  }

  // 3. Sales Department Manual Rendering
  if (SALES_PAGES[pageId]) {
    currentPath.textContent = `営業部 ＞ ${getSalesPageTitle(pageId)}`;
    statusBadge.textContent = '承認済';
    statusBadge.className = 'status-badge status-sales-approved';
    content.innerHTML = `<div class="sales-manual-content">${SALES_PAGES[pageId].html}</div>`;
    bindInteractiveElements();
    injectSalesDiagrams(pageId);
    
    if (highlightSearch) {
      highlightTextOnPage(highlightSearch);
    }
    return;
  }

  // 4. Operations Department Manual Rendering
  if (OPS_PAGES[pageId]) {
    currentPath.textContent = `業務部 ＞ ${OPS_PAGES[pageId].breadcrumb}`;
    statusBadge.textContent = '有識者確認待ち';
    statusBadge.className = 'status-badge status-ops-draft';
    content.innerHTML = OPS_PAGES[pageId].html;
    bindInteractiveElements();
    setupOperationsFeatures(pageId);

    if (highlightSearch) {
      highlightTextOnPage(highlightSearch);
    }
    return;
  }

  // Custom pages or search page
  if (pageId === 'search-results') {
    currentPath.textContent = '検索結果';
    statusBadge.textContent = '検索';
    statusBadge.className = 'status-badge';
    return;
  }
}

// Get clean titles for breadcrumbs
function getSalesPageTitle(pageId) {
  const titles = {
    'ch1': '第1章 フィロソフィー',
    'ch2': '第2章 牛の基礎知識',
    'ch2-lactation': '泌乳曲線と管理',
    'ch2-milk': '牛乳の成分合成',
    'ch2-fatcalcium': '脂肪酸Caバイパス',
    'ch2-analysis': '飼料分析値の読み方',
    'ch2-vitmin': 'ビタミン・ミネラル',
    'ch3': '第3章 逆引きインデックス',
    'ch4': '第4章 商品カタログ',
    'ch4-hay': '乾草（牧草）',
    'ch4-sil': 'サイレージ',
    'ch4-byp': 'バイパス脂肪・蛋白',
    'ch4-comp': '混合・代用乳',
    'ch4-px': 'プレミックス・添加剤',
    'ch4-eqp': '酪農機器・資材',
    'ch4-mowment': '繁殖管理 @mowment',
    'ch4-mowment-inv': '@mowment 機材・在庫管理',
    'ch4-makiba': '牛群管理 まきばノート',
    'ch4-food': '飼料（その他）',
    'ch4-svc': 'サービス・コンサル',
    'ch4-fat': '脂肪酸の機能使い分け',
    'appendix': '業界用語・辞書',
    'app-pack': '荷姿・物流・単位',
    'ch5': '第5章 バックオフィス関連',
    'ch5-car': '総務：社用車トラブル・事故対応',
    'ch5-hr': '人事：貸与物品借用書の申請',
    'ch5-acct': '経理：準備中'
  };
  return titles[pageId] || pageId;
}

// Global search mechanism
function handleGlobalSearch(e) {
  const query = e.target.value.trim().toLowerCase();
  if (!query) {
    if (activePage === 'search-results') {
      navigateTo('home');
    } else {
      generateNavTree(); // Reset navigation highlights
    }
    return;
  }

  // Navigate to custom search results screen
  activePage = 'search-results';
  currentPath.textContent = '横断検索結果';
  statusBadge.textContent = '検索中';
  statusBadge.className = 'status-badge';

  const matches = [];

  // Search in Sales Pages
  Object.keys(SALES_PAGES).forEach(key => {
    const pageText = stripHtml(SALES_PAGES[key].html).toLowerCase();
    const title = getSalesPageTitle(key);
    if (pageText.includes(query) || title.toLowerCase().includes(query)) {
      const snippet = getSearchSnippet(pageText, query);
      matches.push({
        type: 'sales',
        key: key,
        title: `営業部マニュアル: ${title}`,
        snippet: snippet
      });
    }
  });

  // Search in Operations Pages
  Object.keys(OPS_PAGES).forEach(key => {
    const pageText = stripHtml(OPS_PAGES[key].html).toLowerCase();
    const title = OPS_PAGES[key].breadcrumb;
    if (pageText.includes(query) || title.toLowerCase().includes(query)) {
      const snippet = getSearchSnippet(pageText, query);
      matches.push({
        type: 'ops',
        key: key,
        title: `業務部マニュアル: ${title}`,
        snippet: snippet
      });
    }
  });

  renderSearchResults(query, matches);
}

function stripHtml(html) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  return doc.body.textContent || "";
}

function getSearchSnippet(text, query) {
  const idx = text.indexOf(query);
  if (idx === -1) return text.substring(0, 140) + '...';
  const start = Math.max(0, idx - 40);
  const end = Math.min(text.length, idx + query.length + 80);
  let snippet = text.substring(start, end);
  if (start > 0) snippet = '...' + snippet;
  if (end < text.length) snippet = snippet + '...';
  
  // Wrap matching query in mark tag
  const regex = new RegExp(`(${escapeRegExp(query)})`, 'gi');
  return snippet.replace(regex, '<mark>$1</mark>');
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function renderSearchResults(query, matches) {
  let html = `
    <h1 class="page-title">「${query}」の横断検索結果</h1>
    <p class="page-subtitle">営業・業務マニュアルの全データから ${matches.length} 件がヒットしました。</p>
  `;

  if (matches.length === 0) {
    html += `
      <div class="alert alert-note" style="margin-top: 30px;">
        <div class="alert-title">🔍 該当する項目が見つかりません</div>
        キーワードの綴りが正しいか確認するか、他の業界用語（例: 「アラジン」「ルーメン」「Richfat」など）でお試しください。
      </div>
    `;
  } else {
    html += `<div class="card-grid" style="grid-template-columns: 1fr; margin-top: 24px;">`;
    matches.forEach(match => {
      const badgeClass = match.type === 'sales' ? 'tag tag-manual' : 'tag tag-system';
      const label = match.type === 'sales' ? '営業' : '業務';
      html += `
        <div class="card search-result-card" data-key="${match.key}" style="padding: 20px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;">
            <span class="${badgeClass}" style="margin-bottom:0;">${label}</span>
            <span style="font-size:11px; color:var(--text-muted);">クリックで移動 ➔</span>
          </div>
          <h4 style="font-size:15px; font-weight:700; color:var(--accent-blue); margin-bottom: 6px;">${match.title}</h4>
          <p class="search-snippet" style="font-size:13px; color:var(--text-secondary); margin-bottom:0; line-height:1.6;">${match.snippet}</p>
        </div>
      `;
    });
    html += `</div>`;
  }

  contentArea.innerHTML = html;

  // Bind click event to matches
  document.querySelectorAll('.search-result-card').forEach(card => {
    card.addEventListener('click', () => {
      navigateTo(card.dataset.key, query);
    });
  });
}

function highlightTextOnPage(query) {
  const walker = document.createTreeWalker(contentArea, NodeFilter.SHOW_TEXT, null, false);
  const nodes = [];
  while(walker.nextNode()) {
    nodes.push(walker.currentNode);
  }

  nodes.forEach(node => {
    const parent = node.parentNode;
    if (parent.tagName === 'SCRIPT' || parent.tagName === 'STYLE' || parent.tagName === 'MARK') return;
    
    const val = node.nodeValue;
    const lowerVal = val.toLowerCase();
    const idx = lowerVal.indexOf(query);
    
    if (idx !== -1) {
      const frag = document.createDocumentFragment();
      let lastIdx = 0;
      
      const regex = new RegExp(`(${escapeRegExp(query)})`, 'gi');
      let match;
      
      while ((match = regex.exec(val)) !== null) {
        const textNode = document.createTextNode(val.substring(lastIdx, match.index));
        frag.appendChild(textNode);
        
        const mark = document.createElement('mark');
        mark.textContent = match[0];
        mark.style.background = 'rgba(251, 191, 36, 0.3)';
        mark.style.color = '#fff';
        mark.style.padding = '0 2px';
        mark.style.borderRadius = '3px';
        frag.appendChild(mark);
        
        lastIdx = regex.lastIndex;
      }
      
      if (lastIdx < val.length) {
        frag.appendChild(document.createTextNode(val.substring(lastIdx)));
      }
      
      parent.replaceChild(frag, node);
    }
  });
}

// Bind interactivity for timeline step ticks, checkboxes, tabs, accordions
function bindInteractiveElements() {
  // 1. Checkboxes
  document.querySelectorAll('.check-box').forEach(box => {
    box.addEventListener('click', (e) => {
      e.stopPropagation();
      box.classList.toggle('checked');
      box.closest('li').classList.toggle('checked-item');
    });
  });

  // Make list items trigger checklist box
  document.querySelectorAll('.checklist li').forEach(li => {
    li.addEventListener('click', () => {
      const box = li.querySelector('.check-box');
      if(box) {
        box.classList.toggle('checked');
        li.classList.toggle('checked-item');
      }
    });
  });

  // 2. Pattern Tabs (for Operations Manual tabs)
  document.querySelectorAll('.pattern-tab').forEach(tab => {
    tab.addEventListener('click', (e) => {
      const tabs = tab.closest('.pattern-tabs');
      tabs.querySelectorAll('.pattern-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const pattern = tab.dataset.pattern;
      // Filter visible blocks depending on the pattern
      // (Custom logic for manual layouts showing specific steps or tables)
      // Usually the tabs show/hide specific headers or tables
      const content = tab.closest('.content-area') || document;
      
      // Look for the next siblings in steps or tables and filter
      // (This matches the behavior of custom demo tabs)
      filterStepsByPattern(tab, pattern);
    });
  });

  // 3. Dynamic accordions in manual.html
  document.querySelectorAll('.accordion-header').forEach(header => {
    header.addEventListener('click', () => {
      const item = header.closest('.accordion-item');
      item.classList.toggle('open');
    });
  });

  // 4. Screen Preview Triggers
  document.querySelectorAll('.preview-trigger').forEach(trigger => {
    trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      openPreviewModal(trigger.dataset.previewType, trigger.dataset.previewDetail);
    });
  });
}

// Custom tabs switcher helper
function filterStepsByPattern(clickedTab, pattern) {
  // Get all subsection-titles or step-lists within the section container
  // For safety, let's look for sibling step elements and filter.
  // In our imported html, we have headers like Pattern A / B / C.
  // When tabs are clicked, we can show/hide divs based on their name matching the pattern.
  const parent = clickedTab.parentNode;
  
  // Custom simple tab filter for our pages
  const contentParent = parent.parentNode;
  const children = Array.from(contentParent.children);
  const tabIdx = children.indexOf(parent);
  
  let currentGroup = [];
  let isCollecting = false;
  
  // Collect all elements after the tabs up to the next major section header
  for (let i = tabIdx + 1; i < children.length; i++) {
    const child = children[i];
    if (child.classList.contains('section-header')) {
      break; // Stop at next section
    }
    
    // Check if it's a sub-title matching our patterns
    if (child.classList.contains('subsection-title') || child.tagName === 'H4') {
      const text = child.textContent.toLowerCase();
      if (text.includes('パターン') || text.includes('pattern') || text.includes('フェーズ') || text.includes('phase')) {
        const matchesA = text.includes('a') || text.includes('通常') || text.includes('1') || text.includes('他社');
        const matchesB = text.includes('b') || text.includes('輸入') || text.includes('2') || text.includes('直送');
        const matchesC = text.includes('c') || text.includes('前払') || text.includes('3') || text.includes('複数');
        const matchesD = text.includes('d') || text.includes('4') || text.includes('引取');
        
        isCollecting = false;
        
        if (pattern === 'a' && matchesA) isCollecting = true;
        if (pattern === 'b' && matchesB) isCollecting = true;
        if (pattern === 'c' && matchesC) isCollecting = true;
        if (pattern === 'd' && matchesD) isCollecting = true;
        
        if (isCollecting) {
          child.style.display = 'block';
          child.classList.remove('tab-fade-in');
          void child.offsetWidth; // reflowをトリガーしてアニメーションを最初から実行させる
          child.classList.add('tab-fade-in');
        } else {
          child.style.display = 'none';
          child.classList.remove('tab-fade-in');
        }
        continue;
      }
    }
    
    // Hide/show the steps list or table content after a matching subtitle
    if (child.classList.contains('step-list') || child.classList.contains('table-wrapper') || child.classList.contains('alert') || child.classList.contains('checklist-container')) {
      if (isCollecting) {
        child.style.display = 'block';
        child.classList.remove('tab-fade-in');
        void child.offsetWidth; // reflowをトリガー
        child.classList.add('tab-fade-in');
      } else {
        child.style.display = 'none';
        child.classList.remove('tab-fade-in');
      }
    }
  }
}

// --- ダッシュボード統計集計用ヘルパー関数 ---
function getOverallVerificationStats() {
  let total = 0;
  let resolved = 0;
  
  const tempDiv = document.createElement('div');
  Object.keys(OPS_PAGES).forEach(pageId => {
    tempDiv.innerHTML = OPS_PAGES[pageId].html;
    const cautions = tempDiv.querySelectorAll('.alert-caution, .alert-warning');
    total += cautions.length;
    
    cautions.forEach((_, index) => {
      const elementId = `${pageId}-caution-${index}`;
      if (verifiedItems.includes(elementId)) {
        resolved++;
      }
    });
  });
  
  return { total, resolved, pct: total > 0 ? Math.round(resolved / total * 100) : 0 };
}

function getOverallChecklistStats() {
  let total = 0;
  let checked = 0;
  
  const tempDiv = document.createElement('div');
  Object.keys(OPS_PAGES).forEach(pageId => {
    tempDiv.innerHTML = OPS_PAGES[pageId].html;
    const checklists = tempDiv.querySelectorAll('.checklist');
    checklists.forEach((ul, index) => {
      const checklistId = `${pageId}-checklist-${index}`;
      const lis = ul.querySelectorAll('li');
      total += lis.length;
      
      lis.forEach((_, liIndex) => {
        const itemKey = `${checklistId}-item-${liIndex}`;
        if (localStorage.getItem(itemKey) === 'true') {
          checked++;
        }
      });
    });
  });
  
  return { total, checked };
}

function getQuizProgressStats() {
  let total = ALL_QUIZZES.length;
  let completed = 0;
  
  ALL_QUIZZES.forEach(ch => {
    const sc = quizState.chapterScores[ch.id];
    if (sc && sc.best === ch.questions.length) {
      completed++;
    }
  });
  
  return { total, completed };
}

// 業務マニュアル全体から、未解決の「有識者確認必須事項」を動的に抽出する
function getPendingVerificationItems() {
  const pendingItems = [];
  const tempDiv = document.createElement('div');
  
  Object.keys(OPS_PAGES).forEach(pageId => {
    tempDiv.innerHTML = OPS_PAGES[pageId].html;
    const cautions = tempDiv.querySelectorAll('.alert-caution, .alert-warning');
    
    // パンくず情報から適切なマニュアル名を取得
    const breadcrumb = OPS_PAGES[pageId].breadcrumb || '';
    const cleanBreadcrumb = breadcrumb.replace(/\s*＞\s*/g, ' ＞ ');
    
    // マニュアルの h1 タイトルを取得
    const pageTitle = OPS_PAGES[pageId].html.match(/<h1 class="page-title">(.*?)<\/h1>/)?.[1] || pageId;
    
    cautions.forEach((element, index) => {
      const elementId = `${pageId}-caution-${index}`;
      const isResolved = verifiedItems.includes(elementId);
      
      if (!isResolved) {
        let textContent = "";
        const lis = element.querySelectorAll('li');
        if (lis.length > 0) {
          textContent = Array.from(lis).map(li => li.textContent.trim()).join(' / ');
        } else {
          // タイトルを除去して本文だけを抽出
          const clone = element.cloneNode(true);
          const title = clone.querySelector('.alert-title');
          if (title) title.remove();
          textContent = clone.textContent.trim();
        }
        
        pendingItems.push({
          id: elementId,
          pageId: pageId,
          pageTitle: `${cleanBreadcrumb} ＞ ${pageTitle}`,
          text: textContent
        });
      }
    });
  });
  
  return pendingItems;
}

// ホーム一覧から該当マニュアルページの該当確認箇所へダイレクトにジャンプ＆ハイライト表示する
window.navigateToAndHighlight = function(pageId, elementId) {
  navigateTo(pageId);
  
  // ページレンダリングの完了を待って、該当要素へスクロール＆一時フラッシュ
  setTimeout(() => {
    const targetElement = document.querySelector(`[data-caution-id="${elementId}"]`);
    if (targetElement) {
      targetElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
      
      // 一時的なオレンジのフチ取りで強調表示（3秒間）
      targetElement.style.outline = '3px solid var(--accent-amber)';
      targetElement.style.outlineOffset = '4px';
      targetElement.style.borderRadius = '12px';
      targetElement.style.transition = 'outline 0.3s ease';
      
      setTimeout(() => {
        targetElement.style.outline = 'none';
      }, 3000);
    }
  }, 150);
};

// Render Portal Home Page
function renderPortalHome() {
  // 未確定の有識者確認待ち項目をすべて動的に抽出
  const pendingItems = getPendingVerificationItems();
  let pendingVerifyHtml = '';
  
  if (pendingItems.length === 0) {
    pendingVerifyHtml = `
      <div style="color: var(--accent-green); font-weight: 600; display: flex; align-items: center; gap: 8px; font-size: 13.5px;">
        <span>✅ 現在、すべての要確認項目が有識者確認を通過し、実務に適用されています。</span>
      </div>
    `;
  } else {
    pendingVerifyHtml = `
      <div style="margin-bottom: 12px; font-size: 12.5px; color: var(--text-muted);">
        ※各項目をクリックすると、該当マニュアルの確認箇所へ直接移動できます。
      </div>
      <div style="display: flex; flex-direction: column; gap: 10px; max-height: 400px; overflow-y: auto; padding-right: 4px;">
        ${pendingItems.map((item, idx) => `
          <div class="pending-verify-item" onclick="navigateToAndHighlight('${item.pageId}', '${item.id}')" style="cursor: pointer; padding: 12px 16px; border: 1px solid var(--border-subtle); border-radius: 12px; background: var(--bg-primary); transition: all 0.2s; display: flex; flex-direction: column; gap: 6px;">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
              <span style="font-size: 11px; font-weight: 700; color: var(--accent-blue); background: rgba(30, 58, 138, 0.08); padding: 2px 8px; border-radius: 20px;">
                ${item.pageTitle}
              </span>
              <span style="font-size: 11px; font-weight: 700; color: var(--accent-amber); background: rgba(180, 83, 9, 0.08); padding: 2px 8px; border-radius: 20px;">
                要確認 [No.${idx + 1}]
              </span>
            </div>
            <div style="font-size: 13.5px; font-weight: 600; color: var(--text-primary); line-height: 1.6;">
              ${item.text}
            </div>
          </div>
        `).join('')}
      </div>
    `;
  }

  contentArea.innerHTML = `
    <div class="page-hero" style="display: flex; flex-direction: column; gap: 16px; align-items: flex-start;">
      <div class="hero-logo-wrapper" style="background: #ffffff; padding: 12px 24px; border-radius: 16px; display: inline-flex; align-items: center; justify-content: center;">
        <img src="https://cascadiact.com/wp-content/uploads/2021/10/logo-1.png" alt="Cascadia Trading Logo" style="height: 48px; width: auto;">
      </div>
      <h1 class="page-title" style="margin-top: 8px;">Cascadia Trading 総合ナレッジポータル</h1>
      <p class="page-subtitle">営業マニュアルと業務マニュアルを共有するポータルです。</p>
    </div>

    <div class="alert alert-note">
      <div class="alert-title">📘 統合ポータルの使い方</div>
      左側のサイドバーメニューのほか、<b>本画面の各カードから目的の章や手順書へダイレクトにアクセス可能</b>です。
      上部の検索窓からは、営業マニュアルと業務手順書を横断的にキーワード検索できます。
    </div>

    <h3 class="portal-section-title" style="display: flex; align-items: center; gap: 8px; margin-top: 32px;">
      <span style="font-size: 20px;">🔴</span> 有識者への要確認事項（確認待ちリスト）
    </h3>
    <div class="pending-verifications-list" style="background: var(--bg-card); border: 1px solid var(--border-medium); border-radius: 16px; padding: 20px; margin: 16px 0 32px; box-shadow: var(--shadow-sm);">
      ${pendingVerifyHtml}
    </div>

    <h3 class="portal-section-title">👑 営業部マニュアル</h3>
    <div class="mini-card-grid">
      <div class="mini-card mini-card-sales" data-target="ch1">
        <div class="mini-card-icon">🌍</div>
        <div class="mini-card-title">第1章 フィロソフィー</div>
        <div class="mini-card-desc">使命と向き合い方の根本</div>
        <span class="mini-card-badge tag-manual">営業</span>
      </div>
      <div class="mini-card mini-card-sales" data-target="ch2">
        <div class="mini-card-icon">🐮</div>
        <div class="mini-card-title">第2章 牛の基礎知識</div>
        <div class="mini-card-desc">消化・生理・ストレス</div>
        <span class="mini-card-badge tag-manual">営業</span>
      </div>
      <div class="mini-card mini-card-sales" data-target="ch3">
        <div class="mini-card-icon">🔍</div>
        <div class="mini-card-title">第3章 逆引き索引</div>
        <div class="mini-card-desc">課題から解決策を引き出す</div>
        <span class="mini-card-badge tag-manual">営業</span>
      </div>
      <div class="mini-card mini-card-sales" data-target="ch4">
        <div class="mini-card-icon">📦</div>
        <div class="mini-card-title">第4章 商品カタログ</div>
        <div class="mini-card-desc">主力商品群の特長と導入効果</div>
        <span class="mini-card-badge tag-manual">営業</span>
      </div>
      <div class="mini-card mini-card-sales" data-target="appendix">
        <div class="mini-card-icon">📎</div>
        <div class="mini-card-title">業界用語・辞書</div>
        <div class="mini-card-desc">TMR・BCS・CIFなど解説</div>
        <span class="mini-card-badge tag-manual">営業</span>
      </div>
      <div class="mini-card mini-card-sales" data-target="quiz-dashboard">
        <div class="mini-card-icon">🎯</div>
        <div class="mini-card-title">理解度クイズゲーム</div>
        <div class="mini-card-desc">ゲーム感覚で知識力をテスト！</div>
        <span class="mini-card-badge tag-manual" style="background:var(--accent-amber); color:var(--text-inverse);">学習</span>
      </div>
    </div>

    <h3 class="portal-section-title">⚙️ 業務部マニュアル</h3>
    <div class="mini-card-grid">
      <div class="mini-card mini-card-ops" data-target="dom-buy">
        <div class="mini-card-icon">🚚</div>
        <div class="mini-card-title">01-1 国内買継取引</div>
        <div class="mini-card-desc">受発注同時計上・荷渡指図</div>
        <span class="mini-card-badge tag-system">業務</span>
      </div>
      <div class="mini-card mini-card-ops" data-target="dom-stock">
        <div class="mini-card-icon">📦</div>
        <div class="mini-card-title">01-2 国内在庫取引</div>
        <div class="mini-card-desc">倉庫出庫・複数倉庫出荷</div>
        <span class="mini-card-badge tag-system">業務</span>
      </div>
      <div class="mini-card mini-card-ops" data-target="imp-buy">
        <div class="mini-card-icon">🚢</div>
        <div class="mini-card-title">02-1 輸入買継取引</div>
        <div class="mini-card-desc">SO発注・船積管理・為替予約</div>
        <span class="mini-card-badge tag-system">業務</span>
      </div>
      <div class="mini-card mini-card-ops" data-target="expense">
        <div class="mini-card-icon">💰</div>
        <div class="mini-card-title">03-1 諸掛処理</div>
        <div class="mini-card-desc">輸入諸掛入力・配賦・原価洗替</div>
        <span class="mini-card-badge tag-system">業務</span>
      </div>
      <div class="mini-card mini-card-ops" data-target="warehouse">
        <div class="mini-card-icon">🏢</div>
        <div class="mini-card-title">03-2 倉庫移動</div>
        <div class="mini-card-desc">港・営業倉庫間の移動指示</div>
        <span class="mini-card-badge tag-system">業務</span>
      </div>
      <div class="mini-card mini-card-ops" data-target="returns">
        <div class="mini-card-icon">🔄</div>
        <div class="mini-card-title">04 返品処理</div>
        <div class="mini-card-desc">仕入先返品・得意先返品3種</div>
        <span class="mini-card-badge tag-system">業務</span>
      </div>
      <div class="mini-card mini-card-ops" data-target="billing">
        <div class="mini-card-icon">📝</div>
        <div class="mini-card-title">05 請求〜回収</div>
        <div class="mini-card-desc">請求締切・回収消込・残高確認</div>
        <span class="mini-card-badge tag-system">業務</span>
      </div>
      <div class="mini-card mini-card-ops" data-target="pay-dom">
        <div class="mini-card-icon">💵</div>
        <div class="mini-card-title">06-1 支払(国内)</div>
        <div class="mini-card-desc">営業事務照合・経理出金</div>
        <span class="mini-card-badge tag-system">業務</span>
      </div>
      <div class="mini-card mini-card-ops" data-target="pay-intl">
        <div class="mini-card-icon">💱</div>
        <div class="mini-card-title">06-2 支払(海外)</div>
        <div class="mini-card-desc">外貨TT送金・出金計上処理</div>
        <span class="mini-card-badge tag-system">業務</span>
      </div>
      <div class="mini-card mini-card-ops" data-target="accounting">
        <div class="mini-card-icon">📊</div>
        <div class="mini-card-title">07 会計連携</div>
        <div class="mini-card-desc">売上仕入データ連携・自動仕訳</div>
        <span class="mini-card-badge tag-system">業務</span>
      </div>
    </div>

    <h3 class="portal-section-title">🛠️ 実務便利ツール</h3>
    <div class="mini-card-grid">
      <div class="mini-card" data-target="date-calculator" style="background: linear-gradient(135deg, rgba(30,58,138,0.06), rgba(59,130,246,0.04)); border: 1px solid rgba(59,130,246,0.2);">
        <div class="mini-card-icon">🗓️</div>
        <div class="mini-card-title">営業日・デマレージ計算</div>
        <div class="mini-card-desc">日本の祝日対応。デマレージ期間の起算日計算に。</div>
        <span class="mini-card-badge" style="background:var(--accent-blue); color:#fff;">ツール</span>
      </div>
      <div class="mini-card" data-target="schedule-assistant" style="background: linear-gradient(135deg, rgba(5,150,105,0.06), rgba(16,185,129,0.04)); border: 1px solid rgba(5,150,105,0.2);">
        <div class="mini-card-icon">📊</div>
        <div class="mini-card-title">得意先スケジュール支援</div>
        <div class="mini-card-desc">ExcelからコピペしてETA基準の植検日を自動推算。</div>
        <span class="mini-card-badge" style="background:var(--accent-green); color:#fff;">ツール</span>
      </div>
      <div class="mini-card" data-target="flexcon-inventory" style="background: linear-gradient(135deg, rgba(139,92,246,0.06), rgba(168,85,247,0.04)); border: 1px solid rgba(139,92,246,0.2);">
        <div class="mini-card-icon">📦</div>
        <div class="mini-card-title">フレコン資材 在庫・金額管理</div>
        <div class="mini-card-desc">拠点別のフレコンバッグ在庫枚数と金額評価、安全在庫アラート。</div>
        <span class="mini-card-badge" style="background:var(--accent-violet); color:#fff;">新ツール</span>
      </div>
    </div>
  `;

  // Bind click listeners dynamically for all mini-cards
  document.querySelectorAll('.mini-card').forEach(card => {
    card.addEventListener('click', () => {
      navigateTo(card.dataset.target);
    });
  });
}

// ==========================================
//           QUIZ GAME ENGINE
// ==========================================

function renderQuizDashboard() {
  let completedCount = 0;
  ALL_QUIZZES.forEach(ch => {
    const sc = quizState.chapterScores[ch.id];
    if (sc && sc.best === ch.questions.length) {
      completedCount++;
    }
  });

  let r = RANKS[0];
  let nxt = RANKS[1];
  for (let i = RANKS.length - 1; i >= 0; i--) {
    if (quizState.xp >= RANKS[i].xp) {
      r = RANKS[i];
      nxt = RANKS[i + 1] || null;
      break;
    }
  }
  const lv = RANKS.indexOf(r) + 1;

  contentArea.innerHTML = `
    <div class="header-quiz">
      <h1>🎓 カスケディア・ナレッジクイズ</h1>
      <p>営業・業務マニュアルの理解度をゲーム感覚でテストして、スキルアップを目指そう！</p>
    </div>

    <div class="stats-bar" style="margin-bottom: 24px;">
      <div class="stat"><div class="val" id="sXP">${quizState.xp}</div><div class="lbl">総合XP</div></div>
      <div class="stat"><div class="val" id="sStreak">${quizState.streak}</div><div class="lbl">🔥 連続</div></div>
      <div class="stat"><div class="val" id="sCorrect">${quizState.totalCorrect}</div><div class="lbl">✅ 正解</div></div>
      <div class="stat"><div class="val" id="sTotal">${quizState.totalAnswered}</div><div class="lbl">📝 回答</div></div>
    </div>

    <div class="xp-wrap">
      <div class="xp-info"><span id="rankLabel">${r.icon} ${r.name}</span><span id="xpLabel"></span></div>
      <div class="xp-bar"><div class="xp-fill" id="xpFill"></div></div>
    </div>
    <div class="rank-badge"><span id="rankBadge">Lv.${lv} ${r.name}</span></div>

    <!-- Screen Home -->
    <div class="quiz-screen active" id="scrHome">
      <p style="font-size:12px; color:var(--text-muted); margin-bottom: 16px;">各章をクリアしてXPを獲得し、ランクを上げよう！</p>

      <!-- 営業部セクション -->
      <div class="quiz-dept-section">
        <div class="quiz-dept-header quiz-dept-header--sales">
          <span class="quiz-dept-icon">👑</span>
          <span class="quiz-dept-title">営業部クイズ</span>
          <span class="quiz-dept-badge">Sales</span>
        </div>
        <div class="ch-grid" id="chGridSales"></div>
      </div>

      <!-- 業務部セクション -->
      <div class="quiz-dept-section" style="margin-top: 28px;">
        <div class="quiz-dept-header quiz-dept-header--ops">
          <span class="quiz-dept-icon">⚙️</span>
          <span class="quiz-dept-title">業務部クイズ</span>
          <span class="quiz-dept-badge">Operations</span>
        </div>
        <div class="ch-grid" id="chGridOps"></div>
      </div>

      <div class="btn-row" style="margin-top:28px">
        <button class="btn btn-secondary" id="btnShowAchievements">🏆 解除実績</button>
        <button class="btn btn-primary" id="btnRandomQuiz">🎲 ランダム10問</button>
      </div>
      
      <div style="text-align:center; margin-top:40px;">
        <button class="btn btn-muted" id="btnResetHistory" style="border: 1px solid rgba(251,113,133,0.2); color:var(--accent-rose); font-size:11.5px; padding:6px 16px;">🗑️ 学習履歴をリセット</button>
      </div>
    </div>

    <!-- Screen Quiz (Question Area) -->
    <div class="quiz-screen" id="scrQuiz">
      <div class="q-header">
        <span class="q-chapter" id="qChapter"></span>
        <span class="q-count" id="qCount"></span>
      </div>
      <div class="q-progress"><div id="qProg"></div></div>
      <div id="qArea"></div>
      <div class="btn-row" id="qBtns"></div>
    </div>

    <!-- Screen Result -->
    <div class="quiz-screen" id="scrResult">
      <div class="result-card">
        <div class="result-emoji" id="rEmoji"></div>
        <div class="result-title" id="rTitle"></div>
        <div class="result-score" id="rScore"></div>
        <div class="result-sub" id="rSub"></div>
        <div class="result-xp"><span id="rXP">+0</span> XP獲得！</div>
        <div class="growth-vision" id="rVision">
          <div class="growth-title">🌟 獲得した成長の証（獲得スキル）</div>
          <div class="growth-text" id="rVisionText"></div>
        </div>
      </div>
      <div class="btn-row">
        <button class="btn btn-secondary" id="btnBackToHome">🏠 クイズホームへ</button>
        <button class="btn btn-primary" id="btnRetryQuiz">🔄 もう一度挑戦</button>
      </div>
    </div>

    <!-- Screen Achievements -->
    <div class="quiz-screen" id="scrAchiev">
      <h2 style="font-size:16px; font-weight:700; margin-bottom:4px">🏆 獲得バッジ・解除実績</h2>
      <p style="font-size:12px; color:var(--text-muted); margin-bottom:16px">挑戦をクリアして特別なバッジを獲得しよう！</p>
      <div class="achiev-grid" id="achievGrid"></div>
      <div class="btn-row"><button class="btn btn-secondary" id="btnBackToHomeFromAch">← 戻る</button></div>
    </div>
  `;

  // Bind Quiz specific actions
  document.getElementById('btnShowAchievements').addEventListener('click', () => showQuizScreen('scrAchiev'));
  document.getElementById('btnRandomQuiz').addEventListener('click', startRandomQuiz);
  document.getElementById('btnResetHistory').addEventListener('click', resetQuizHistory);
  document.getElementById('btnBackToHome').addEventListener('click', () => { showQuizScreen('scrHome'); renderChaptersList(); });
  document.getElementById('btnBackToHomeFromAch').addEventListener('click', () => { showQuizScreen('scrHome'); renderChaptersList(); });

  updateXPBar(r, nxt, lv);
  renderChaptersList();
  renderAchievementsList();
}

function updateXPBar(r, nxt, lv) {
  const xpFill = document.getElementById('xpFill');
  const xpLabel = document.getElementById('xpLabel');
  
  if (nxt) {
    const pct = ((quizState.xp - r.xp) / (nxt.xp - r.xp) * 100);
    xpFill.style.width = pct + '%';
    xpLabel.textContent = `${quizState.xp} / ${nxt.xp} XP`;
  } else {
    xpFill.style.width = '100%';
    xpLabel.textContent = `${quizState.xp} XP (MAX)`;
  }
}

function showQuizScreen(screenId) {
  document.querySelectorAll('.quiz-screen').forEach(s => s.classList.remove('active'));
  document.getElementById(screenId).classList.add('active');
}

function renderChaptersList() {
  const salesGrid = document.getElementById('chGridSales');
  const opsGrid = document.getElementById('chGridOps');
  if (!salesGrid || !opsGrid) return;
  salesGrid.innerHTML = '';
  opsGrid.innerHTML = '';

  const salesQuizzes = (window.SALES_QUIZ || []);
  const opsQuizzes   = (window.OPS_QUIZ || []);

  function buildCard(ch, grid) {
    const sc = quizState.chapterScores[ch.id];
    const best = sc ? sc.best : 0;
    const total = ch.questions.length;
    const pct = sc ? Math.round(sc.best / total * 100) : 0;
    const stars = best === total ? '⭐⭐⭐' : best >= total * 0.7 ? '⭐⭐' : best >= total * 0.4 ? '⭐' : '☆☆☆';
    const completed = best === total;

    const d = document.createElement('div');
    d.className = 'ch-card' + (completed ? ' completed' : '');
    d.innerHTML = `
      <div class="emoji">${ch.emoji}</div>
      <div class="title">${ch.title}</div>
      <div class="desc">${ch.desc}（${total}問）</div>
      <div class="stars">${stars}</div>
      <div class="progress-mini"><div style="width:${pct}%"></div></div>
    `;
    d.onclick = () => openQuizModal(ch.id);
    grid.appendChild(d);
  }

  salesQuizzes.forEach(ch => buildCard(ch, salesGrid));
  opsQuizzes.forEach(ch => buildCard(ch, opsGrid));
}

function openQuizModal(chId) {
  pendingChId = chId;
  const ch = ALL_QUIZZES.find(c => c.id === chId);
  if (!ch) return;
  
  document.getElementById('modalQuizTitle').textContent = `${ch.emoji} ${ch.title}`;
  document.getElementById('modalQuizPurpose').textContent = ch.purpose;
  document.getElementById('modalQuizVision').textContent = ch.vision;
  
  // Configure preview manual button dynamically
  const previewBtn = document.getElementById('btnPreviewManual');
  previewBtn.onclick = () => {
    closeModal();
    let targetPage = chId;
    if (chId === 'ops-ch1') targetPage = 'imp-buy';
    else if (chId === 'ops-ch2') targetPage = 'warehouse';
    else if (chId === 'ops-ch3') targetPage = 'returns';
    navigateTo(targetPage); // Direct link to corresponding manual page
  };

  const startBtn = document.getElementById('btnStartQuiz');
  startBtn.onclick = () => {
    closeModal();
    startChapter(chId);
  };
  
  document.getElementById('quizModal').classList.add('active');
}

function closeModal() {
  document.getElementById('quizModal').classList.remove('active');
  pendingChId = null;
}

function startChapter(chId) {
  const ch = ALL_QUIZZES.find(c => c.id === chId);
  if (!ch) return;
  
  curQuiz = {
    chId: ch.id,
    title: ch.title,
    emoji: ch.emoji,
    questions: shuffle([...ch.questions])
  };
  
  curIdx = 0;
  curCorrect = 0;
  quizAnswered = false;
  
  showQuizScreen('scrQuiz');
  document.getElementById('qChapter').textContent = `${ch.emoji} ${ch.title}`;
  renderQuestion();
}

function startRandomQuiz() {
  let all = [];
  ALL_QUIZZES.forEach(ch => {
    ch.questions.forEach(q => {
      all.push({ ...q, _ch: ch.title });
    });
  });
  
  all = shuffle(all).slice(0, 10);
  
  curQuiz = {
    chId: 'random',
    title: '🎲 ランダム10問',
    emoji: '🎲',
    questions: all
  };
  
  curIdx = 0;
  curCorrect = 0;
  quizAnswered = false;
  
  showQuizScreen('scrQuiz');
  document.getElementById('qChapter').textContent = '🎲 ランダムチャレンジ';
  renderQuestion();
}

function renderQuestion() {
  const qs = curQuiz.questions;
  const q = qs[curIdx];
  
  document.getElementById('qCount').textContent = `${curIdx + 1} / ${qs.length}`;
  document.getElementById('qProg').style.width = ((curIdx) / qs.length * 100) + '%';
  quizAnswered = false;
  
  let html = `<div class="q-card"><div class="q-num">Q${curIdx + 1}</div>`;
  
  if (q.ref) {
    html += `<button class="hint-btn" id="btnQuizHint">📖 マニュアルで調べる</button>`;
  }
  
  html += `<div class="q-text">${q.q}</div><div class="q-opts">`;
  
  q.o.forEach((o, i) => {
    html += `<div class="q-opt" data-i="${i}">${o}</div>`;
  });
  
  html += `</div><div class="q-explain" id="qEx"></div></div>`;
  
  document.getElementById('qArea').innerHTML = html;
  document.getElementById('qBtns').innerHTML = '';

  // Bind Hint Click
  if (q.ref) {
    document.getElementById('btnQuizHint').addEventListener('click', () => {
      // Open manual inside integration portal
      navigateTo(q.ref);
    });
  }

  // Bind Option Clicks
  document.querySelectorAll('.q-opt').forEach(opt => {
    opt.addEventListener('click', () => {
      selectAnswer(parseInt(opt.dataset.i));
    });
  });
}

function selectAnswer(i) {
  if (quizAnswered) return;
  quizAnswered = true;
  
  const q = curQuiz.questions[curIdx];
  const correct = i === q.a;
  
  const opts = document.querySelectorAll('.q-opt');
  opts.forEach(o => {
    o.classList.add('disabled');
    const oi = parseInt(o.dataset.i);
    if (oi === q.a) o.classList.add('correct');
    if (oi === i && !correct) o.classList.add('wrong');
  });
  
  quizState.totalAnswered++;
  let earnedXP = 0;
  
  if (correct) {
    curCorrect++;
    quizState.totalCorrect++;
    quizState.streak++;
    
    if (quizState.streak > quizState.maxStreak) {
      quizState.maxStreak = quizState.streak;
    }
    
    earnedXP = 10 + (quizState.streak >= 5 ? 5 : 0) + (quizState.streak >= 10 ? 10 : 0);
    quizState.xp += earnedXP;
    
    showGlobalToast('✅', `正解！ +${earnedXP} XP`);
    
    if (quizState.streak >= 5) unlockAchievement('streak5');
    if (quizState.streak >= 10) unlockAchievement('streak10');
  } else {
    quizState.streak = 0;
    quizState.xp += 2; // XP for learning from mistakes
    showGlobalToast('❌', `不正解... 正解は: ${q.o[q.a]}`);
  }
  
  // Show combo display
  const combo = document.getElementById('combo');
  const comboNum = document.getElementById('comboNum');
  if (quizState.streak >= 3) {
    comboNum.textContent = quizState.streak;
    combo.classList.add('show');
  } else {
    combo.classList.remove('show');
  }

  // Render Explanatory details
  const ex = document.getElementById('qEx');
  ex.className = 'q-explain show ' + (correct ? 'ok-bg' : 'ng-bg');
  
  let wrongFeedback = '';
  if (!correct && q.we && q.we[i]) {
    wrongFeedback = `<div style="margin-top:6px; color:var(--accent-rose); font-weight:600;">⚠️ 間違えた原因: ${q.we[i]}</div>`;
  }
  
  ex.innerHTML = `
    <strong>${correct ? '🎉 正解です！' : '💡 解説:'}</strong><br>
    ${q.ex}
    ${wrongFeedback}
  `;

  // Save progress
  saveQuizState();
  
  // Generate next button
  const btns = document.getElementById('qBtns');
  const nextBtn = document.createElement('button');
  nextBtn.className = 'btn btn-primary';
  const isLast = curIdx === curQuiz.questions.length - 1;
  nextBtn.textContent = isLast ? '🏁 結果を見る' : '次へ進む ➔';
  nextBtn.onclick = () => {
    if (isLast) {
      finishQuiz();
    } else {
      curIdx++;
      renderQuestion();
    }
  };
  btns.appendChild(nextBtn);
}

function finishQuiz() {
  document.getElementById('combo').classList.remove('show');
  showQuizScreen('scrResult');
  
  const total = curQuiz.questions.length;
  const pct = Math.round(curCorrect / total * 100);
  
  let emoji = '🎉';
  let title = '素晴らしい！';
  let sub = 'この調子で営業マニュアルをマスターしましょう！';
  
  if (pct === 100) {
    emoji = '👑';
    title = '完全無欠！パーフェクト！';
    sub = '完璧なナレッジです！現場でも絶対的な自信を持って活かしましょう！';
    if (curQuiz.chId !== 'random') {
      unlockAchievement('perfect');
    }
  } else if (pct >= 70) {
    emoji = '✨';
    title = '合格点達成！';
    sub = '十分な知識が身についています。例外や細かい仕様も振り返りましょう。';
  } else if (pct >= 40) {
    emoji = '📝';
    title = 'もう少し頑張りましょう';
    sub = 'マニュアルを再度読み返して、正しい対応方法を確認してみてください。';
  } else {
    emoji = '💪';
    title = '伸び代がいっぱいです！';
    sub = '基礎から焦らず、マニュアルを見ながらじっくり挑戦し直しましょう！';
  }

  // Chapter clear scoring
  let addedXP = 0;
  if (curQuiz.chId !== 'random') {
    const prev = quizState.chapterScores[curQuiz.chId] || { best: 0 };
    if (curCorrect > prev.best) {
      addedXP = (curCorrect - prev.best) * 15; // 15 XP per improved correct answer
      quizState.chapterScores[curQuiz.chId] = { best: curCorrect, last: curCorrect };
      quizState.xp += addedXP;
      
      if (curCorrect === total) {
        quizState.xp += 50; // Perfect bonus
        addedXP += 50;
      }
    }
    
    // First clear badge
    unlockAchievement('first');

    // Verify all chapters cleared
    let allCleared = true;
    ALL_QUIZZES.forEach(ch => {
      const score = quizState.chapterScores[ch.id];
      if(!score || score.best < ch.questions.length * 0.4) {
        allCleared = false;
      }
    });
    if(allCleared) unlockAchievement('all_ch');
  } else {
    // Random bonus
    addedXP = curCorrect * 5;
    quizState.xp += addedXP;
  }

  if (quizState.xp >= 500) unlockAchievement('xp500');
  if (quizState.xp >= 1000) unlockAchievement('xp1000');
  if (quizState.totalAnswered >= 50) unlockAchievement('ans50');

  saveQuizState();

  // Populate results
  document.getElementById('rEmoji').textContent = emoji;
  document.getElementById('rTitle').textContent = title;
  document.getElementById('rScore').textContent = `${curCorrect} / ${total} 正解 (${pct}%)`;
  document.getElementById('rSub').textContent = sub;
  document.getElementById('rXP').textContent = `+${addedXP}`;

  // Populate Skill Growth card
  const rVision = document.getElementById('rVision');
  const rVisionText = document.getElementById('rVisionText');
  const chInfo = ALL_QUIZZES.find(c => c.id === curQuiz.chId);
  
  if (chInfo && curCorrect >= total * 0.6) {
    rVision.classList.add('show');
    rVisionText.innerHTML = `<strong>獲得スキル:</strong> ${chInfo.vision}`;
  } else {
    rVision.classList.remove('show');
  }

  // Setup retry buttons
  const retryBtn = document.getElementById('btnRetryQuiz');
  retryBtn.onclick = () => {
    if (curQuiz.chId === 'random') {
      startRandomQuiz();
    } else {
      startChapter(curQuiz.chId);
    }
  };
}

function unlockAchievement(id) {
  if (!quizState.achievements.includes(id)) {
    quizState.achievements.push(id);
    saveQuizState();
    const a = ACHIEVEMENTS.find(x => x.id === id);
    if (a) showGlobalToast(a.icon, `実績解除: ${a.name}`);
  }
}

function showGlobalToast(emoji, text) {
  const t = document.getElementById('toast');
  t.querySelector('.toast-emoji').textContent = emoji;
  t.querySelector('.toast-text').textContent = text;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2200);
}

function renderAchievementsList() {
  const g = document.getElementById('achievGrid');
  if (!g) return;
  g.innerHTML = '';
  
  ACHIEVEMENTS.forEach(a => {
    const unlocked = quizState.achievements.includes(a.id);
    const d = document.createElement('div');
    d.className = 'achiev-item' + (unlocked ? ' unlocked' : '');
    d.innerHTML = `
      <div class="a-icon">${a.icon}</div>
      <div class="a-name">${a.name}</div>
      <div class="a-desc">${a.desc}</div>
    `;
    g.appendChild(d);
  });
}

function resetQuizHistory() {
  if (confirm('学習履歴、累計XP、バッジの獲得記録をすべて削除し初期化します。よろしいですか？')) {
    quizState = {
      xp: 0, totalCorrect: 0, totalAnswered: 0, streak: 0, maxStreak: 0,
      chapterScores: {}, achievements: []
    };
    saveQuizState();
    navigateTo('quiz-dashboard');
    showGlobalToast('🗑️', 'すべての記録を初期化しました');
  }
}

function saveQuizState() {
  localStorage.setItem('cascadia_quiz', JSON.stringify(quizState));
}

// Global Progress Bar helper
function updateProgress() {
  const bar = document.getElementById('progressBar');
  window.addEventListener('scroll', () => {
    const winScroll = document.documentElement.scrollTop || document.body.scrollTop;
    const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    const scrolled = height > 0 ? (winScroll / height) * 100 : 0;
    bar.style.width = scrolled + '%';
  });
}

// Fisher-Yates shuffle
function shuffle(array) {
  let currentIndex = array.length, randomIndex;
  while (currentIndex !== 0) {
    randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;
    [array[currentIndex], array[randomIndex]] = [
      array[randomIndex], array[currentIndex]];
  }
  return array;
}

// =========================================================================
//   業務有識者確認モード ＆ 実務チェックリスト永続化・エビデンス印刷ロジック
// =========================================================================

function setupOperationsFeatures(pageId) {
  // --- 1. 有識者確認モードの適用ロジック ---
  const cautions = document.querySelectorAll('.alert-caution, .alert-warning');
  let totalCautions = cautions.length;
  let resolvedCautionsCount = 0;

  cautions.forEach((el, index) => {
    // 一意のIDを付与
    const elementId = `${pageId}-caution-${index}`;
    el.setAttribute('data-caution-id', elementId);

    // 解決済みかをチェック
    const isResolved = verifiedItems.includes(elementId);
    if (isResolved) {
      el.classList.add('alert-sme-resolved');
      resolvedCautionsCount++;
    }

    // 解決アクションバーを挿入 (無ければ作成)
    if (!el.querySelector('.verify-action-bar')) {
      const actionBar = document.createElement('div');
      actionBar.className = 'verify-action-bar';
      
      const resolveBtn = document.createElement('button');
      resolveBtn.className = 'btn-verify-resolve';
      resolveBtn.textContent = isResolved ? '未確認に戻す' : '実務で確認済み';
      
      resolveBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const currentId = el.getAttribute('data-caution-id');
        const currentlyResolved = verifiedItems.includes(currentId);

        if (currentlyResolved) {
          // 解決済みから未解決に戻す
          verifiedItems = verifiedItems.filter(id => id !== currentId);
          el.classList.remove('alert-sme-resolved');
          resolveBtn.textContent = '実務で確認済み';
          showGlobalToast('↩️', '未確認の状態に戻しました');
        } else {
          // 解決済みにする
          verifiedItems.push(currentId);
          el.classList.add('alert-sme-resolved');
          resolveBtn.textContent = '未確認に戻す';
          showGlobalToast('✅', '実務確認済みに設定しました');
        }
        
        localStorage.setItem('cascadia_verified_items', JSON.stringify(verifiedItems));
        // 再評価してステータスバッジを更新
        updatePageVerificationStatus(pageId);
      });

      actionBar.appendChild(resolveBtn);
      el.appendChild(actionBar);
    }
  });

  // ページの初期検証ステータス更新
  updatePageVerificationStatus(pageId);

  // --- 2. 実務チェックリスト永続化・操作盤挿入 ---
  const checklists = document.querySelectorAll('.checklist');
  checklists.forEach((ul, index) => {
    // すでに操作盤で囲まれているかチェック
    if (ul.closest('.checklist-container')) return;

    const checklistId = `${pageId}-checklist-${index}`;
    ul.setAttribute('data-checklist-id', checklistId);

    // 各 li 要素に対して、保存されたチェック状態を復元
    const lis = ul.querySelectorAll('li');
    lis.forEach((li, liIndex) => {
      const itemKey = `${checklistId}-item-${liIndex}`;
      const isChecked = localStorage.getItem(itemKey) === 'true';
      const box = li.querySelector('.check-box');
      
      if (isChecked) {
        li.classList.add('checked-item');
        if (box) box.classList.add('checked');
      }

      // クリックイベントで localStorage に保存する処理
      li.addEventListener('click', () => {
        setTimeout(() => {
          const currentlyChecked = li.classList.contains('checked-item');
          localStorage.setItem(itemKey, currentlyChecked);
        }, 50);
      });
    });

    // チェックリストを囲むコンテナと操作パネルの動的構築
    const container = document.createElement('div');
    container.className = 'checklist-container';
    
    // ヘッダー
    const header = document.createElement('div');
    header.className = 'checklist-header';
    
    const title = document.createElement('div');
    title.className = 'checklist-title-label';
    title.textContent = '📋 ミス防止ダブルチェック盤';
    
    const actions = document.createElement('div');
    actions.className = 'checklist-actions';
    
    const clearBtn = document.createElement('button');
    clearBtn.className = 'btn-check-action btn-clear-checks';
    clearBtn.innerHTML = '🧹 クリア';
    clearBtn.addEventListener('click', () => {
      if (confirm('このチェックリストの選択状態をすべてリセットしますか？')) {
        lis.forEach((li, liIndex) => {
          const itemKey = `${checklistId}-item-${liIndex}`;
          li.classList.remove('checked-item');
          const box = li.querySelector('.check-box');
          if (box) box.classList.remove('checked');
          localStorage.removeItem(itemKey);
        });
        showGlobalToast('🧹', 'チェック状態をリセットしました');
      }
    });

    const printBtn = document.createElement('button');
    printBtn.className = 'btn-check-action btn-print';
    printBtn.innerHTML = '🖨️ エビデンス印刷 / PDF出力';
    printBtn.addEventListener('click', () => {
      exportChecklistEvidence(pageId, ul);
    });

    actions.appendChild(clearBtn);
    actions.appendChild(printBtn);
    header.appendChild(title);
    header.appendChild(actions);
    
    // 要素をコンテナ内に配置
    ul.parentNode.insertBefore(container, ul);
    container.appendChild(header);
    container.appendChild(ul);
  });
}

function updatePageVerificationStatus(pageId) {
  const cautions = document.querySelectorAll('.alert-caution, .alert-warning');
  const badge = document.getElementById('statusBadge');
  if (!badge) return;

  if (cautions.length === 0) return;

  let allResolved = true;
  cautions.forEach((el) => {
    const currentId = el.getAttribute('data-caution-id');
    if (!verifiedItems.includes(currentId)) {
      allResolved = false;
    }
  });

  if (allResolved) {
    badge.textContent = '実務適用（確認済）';
    badge.className = 'status-badge status-ops-approved';
  } else {
    badge.textContent = '有識者確認待ち';
    badge.className = 'status-badge status-ops-draft';
  }
}

function exportChecklistEvidence(pageId, ulElement) {
  const pageTitle = currentPath.textContent;
  const lis = ulElement.querySelectorAll('li');
  
  let itemsHtml = '';
  lis.forEach((li) => {
    const isChecked = li.classList.contains('checked-item');
    const text = li.querySelector('span') ? li.querySelector('span').textContent : li.textContent;
    const marker = isChecked ? '<span class="check-marker">☑</span>' : '<span class="uncheck-marker">☐</span>';
    const textStyle = isChecked ? 'color: #111; font-weight: 500;' : 'color: #999; text-decoration: line-through;';
    
    itemsHtml += `
      <div class="checklist-item">
        ${marker}
        <span style="${textStyle}">${text}</span>
      </div>
    `;
  });

  const printWindow = window.open('', '_blank');
  printWindow.document.write(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>業務チェックエビデンス - Cascadia Trading</title>
      <style>
        body { font-family: 'Noto Sans JP', 'Helvetica Neue', Arial, sans-serif; color: #333; padding: 50px; line-height: 1.6; background: #fff; }
        .header { border-bottom: 3px solid #111; padding-bottom: 12px; margin-bottom: 30px; position: relative; }
        .title { font-size: 26px; font-weight: 800; color: #111; letter-spacing: -0.01em; }
        .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 15px; font-size: 13px; color: #555; background: #f5f7fa; padding: 12px 18px; border-radius: 6px; }
        .meta-item strong { color: #111; }
        .evidence-title { font-size: 16px; font-weight: 700; color: #111; margin: 30px 0 15px; border-left: 4px solid #111; padding-left: 10px; }
        .evidence-box { border: 1px solid #e1e8ed; border-radius: 8px; overflow: hidden; margin-bottom: 40px; box-shadow: 0 2px 8px rgba(0,0,0,0.02); }
        .checklist-item { padding: 12px 20px; border-bottom: 1px solid #f0f3f5; display: flex; align-items: center; font-size: 14.5px; }
        .checklist-item:last-child { border-bottom: none; }
        .check-marker { color: #10b981; margin-right: 12px; font-size: 20px; font-weight: bold; line-height: 1; }
        .uncheck-marker { color: #cbd5e1; margin-right: 12px; font-size: 20px; font-weight: bold; line-height: 1; }
        .sig-area { display: flex; justify-content: space-between; margin-top: 60px; page-break-inside: avoid; }
        .sig-box { width: 45%; border-top: 1px solid #111; padding-top: 12px; text-align: center; font-size: 13px; font-weight: 600; color: #444; }
        .footer-note { text-align: center; margin-top: 80px; font-size: 11px; color: #999; border-top: 1px dashed #e1e8ed; padding-top: 15px; }
        @media print {
          body { padding: 20px; }
          .evidence-box { box-shadow: none; border-color: #333; }
          .checklist-item { border-bottom-color: #ccc; }
        }
      </style>
    </head>
    <body>
      <div class="header">
        <div class="title">📋 業務実施チェック完了エビデンス</div>
        <div class="meta-grid">
          <div class="meta-item"><strong>対象業務:</strong> ${pageTitle}</div>
          <div class="meta-item"><strong>実施日時:</strong> ${new Date().toLocaleString()}</div>
          <div class="meta-item"><strong>提供元システム:</strong> Cascadia Trading 総合ナレッジポータル</div>
          <div class="meta-item"><strong>検証ステータス:</strong> 正常完了</div>
        </div>
      </div>
      
      <div class="evidence-title">【ダブルチェック項目 実施結果】</div>
      <div class="evidence-box">
        ${itemsHtml}
      </div>
      
      <div class="sig-area">
        <div class="sig-box">実施担当者 署名欄</div>
        <div class="sig-box">承認責任者 署名欄</div>
      </div>
      
      <div class="footer-note">
        ※本紙は株式会社カスケディア・トレーディングの業務プロセスに基づき、マニュアルに準拠して業務が実施されたことを証明するものです。
      </div>
      
      <script>
        window.onload = function() {
          setTimeout(function() {
            window.print();
          }, 300);
        };
      </script>
    </body>
    </html>
  `);
  printWindow.document.close();
}

// --- 営業部マニュアル用 動的プレミアムSVG図解注入ロジック ---
function injectSalesDiagrams(pageId) {
  // 1. 第2章 牛の基礎知識 ── 四つの胃の仕組み (stomachs)
  if (pageId === 'ch2') {
    const digestDiagramEl = document.querySelector('.digest-diagram');
    if (digestDiagramEl) {
      const stomachsSvg = `
        <svg viewBox="0 0 800 350" width="100%" height="auto" class="diagram-svg stomachs-svg">
          <defs>
            <linearGradient id="grad-rumen" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#10b981" stop-opacity="0.85"/>
              <stop offset="100%" stop-color="#047857" stop-opacity="0.95"/>
            </linearGradient>
            <linearGradient id="grad-reticulum" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.85"/>
              <stop offset="100%" stop-color="#1d4ed8" stop-opacity="0.95"/>
            </linearGradient>
            <linearGradient id="grad-omasum" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#fbbf24" stop-opacity="0.85"/>
              <stop offset="100%" stop-color="#d97706" stop-opacity="0.95"/>
            </linearGradient>
            <linearGradient id="grad-abomasum" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#ef4444" stop-opacity="0.85"/>
              <stop offset="100%" stop-color="#b91c1c" stop-opacity="0.95"/>
            </linearGradient>
            <filter id="shadow-stomach" x="-5%" y="-5%" width="110%" height="110%">
              <feDropShadow dx="2" dy="4" stdDeviation="4" flood-color="#000" flood-opacity="0.12"/>
            </filter>
            <marker id="arrow" markerWidth="10" markerHeight="10" refX="6" refY="3" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L0,6 L6,3 Z" fill="var(--text-muted, #94a3b8)" />
            </marker>
            <marker id="arrow-blue" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L0,6 L6,3 Z" fill="#2563eb" />
            </marker>
            <marker id="arrow-orange" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L0,6 L6,3 Z" fill="#d97706" />
            </marker>
            <marker id="arrow-red" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L0,6 L6,3 Z" fill="#dc2626" />
            </marker>
          </defs>

          <!-- 背景ベース -->
          <rect width="800" height="350" rx="16" fill="var(--bg-card, #ffffff)" stroke="var(--border-subtle, #e2e8f0)" stroke-width="1.5"/>

          <!-- 牛のシルエット：破線を細く・薄くしてプロフェッショナルな見た目へ -->
          <path d="M 50,150 C 70,120 100,100 130,100 C 160,100 180,120 200,110 C 220,100 230,80 250,80 C 270,80 290,100 300,120 C 310,140 310,160 320,170 C 340,190 380,180 420,180 C 460,180 500,170 540,160 C 580,150 620,140 650,150 C 680,160 700,200 720,240 C 730,260 740,280 750,290 L 730,300 C 700,300 680,260 670,250 C 650,270 610,280 570,290 C 530,300 480,300 440,290 C 400,280 380,270 360,260 L 320,280 L 300,290 C 280,290 260,260 250,240 C 240,220 200,210 180,200 C 160,190 140,200 120,210 C 100,220 80,230 60,230 Z" 
                fill="none" stroke="var(--border-subtle, rgba(226, 232, 240, 0.5))" stroke-width="1.5" stroke-dasharray="4,4" opacity="0.12" />

          <!-- ラベルテキスト要素の定義（線より手前に描画） -->
          <text x="40" y="30" fill="var(--text-primary, #1e293b)" font-size="13" font-weight="800">🌾 食べる (粗飼料・濃厚飼料)</text>
          <text x="165" y="152" fill="#d97706" font-size="11" font-weight="800" text-anchor="middle">🔄 反芻 (口に戻して再咀嚼)</text>

          <!-- 4つの胃のビジュアル要素 (重ね順を考慮してフロー線の前に記述することで、すべての接続線・矢印が上に描画され隠れるのを完全解決) -->
          <!-- 第一胃 (ルーメン)：サイズとx座標を微調整し左右に十分な余白を確保 -->
          <g transform="translate(250, 65)" filter="url(#shadow-stomach)" class="stomach-node" style="cursor: pointer;">
            <rect width="225" height="110" rx="14" fill="url(#grad-rumen)" stroke="#047857" stroke-width="2" />
            <text x="15" y="32" fill="#fff" font-size="14.5" font-weight="800">🟢 第一胃 (ルーメン)</text>
            <text x="15" y="58" fill="#ecfdf5" font-size="11.5" font-weight="700">容量: 150〜200L (巨大な発酵タンク)</text>
            <text x="15" y="78" fill="#ecfdf5" font-size="10.5" font-weight="700">・数十兆の微生物が繊維を発酵分解</text>
            <text x="15" y="94" fill="#ecfdf5" font-size="10.5" font-weight="700">・エネルギー源の約70% (VFA) を生成</text>
          </g>

          <!-- 第二胃 (網胃)：y座標を調整して第一胃・第三胃と美しく調和。右に20pxシフトして間隔を最適化 -->
          <g transform="translate(530, 50)" filter="url(#shadow-stomach)" class="stomach-node">
            <rect width="210" height="75" rx="12" fill="url(#grad-reticulum)" stroke="#1d4ed8" stroke-width="2" />
            <text x="15" y="28" fill="#fff" font-size="13.5" font-weight="800">🔵 第二胃 (網胃)</text>
            <text x="15" y="48" fill="#eff6ff" font-size="10.5" font-weight="700">異物除去フィルター</text>
            <text x="15" y="64" fill="#dbeafe" font-size="10" font-weight="700">・蜂の巣状の壁で金属等の異物を捕獲</text>
          </g>

          <!-- 第三胃 (葉胃)：高コントラストなテキスト色を採用。第二胃と揃えて右に20pxシフト -->
          <g transform="translate(530, 165)" filter="url(#shadow-stomach)" class="stomach-node">
            <rect width="210" height="75" rx="12" fill="url(#grad-omasum)" stroke="#b45309" stroke-width="2" />
            <text x="15" y="28" fill="#fff" font-size="13.5" font-weight="800">🟡 第三胃 (葉胃)</text>
            <text x="15" y="48" fill="#fffbeb" font-size="10.5" font-weight="700">水分とミネラルの吸収</text>
            <text x="15" y="64" fill="#fef3c7" font-size="10" font-weight="700">・何百枚もの葉状のひだで水分を吸収</text>
          </g>

          <!-- 第四胃 (皺胃) -->
          <g transform="translate(270, 235)" filter="url(#shadow-stomach)" class="stomach-node">
            <rect width="220" height="75" rx="12" fill="url(#grad-abomasum)" stroke="#b91c1c" stroke-width="2" />
            <text x="15" y="28" fill="#fff" font-size="13.5" font-weight="800">🔴 第四胃 (皺胃)</text>
            <text x="15" y="48" fill="#fef2f2" font-size="10.5" font-weight="700">ヒトの胃と同等 (真胃)</text>
            <text x="15" y="64" fill="#fee2e2" font-size="10" font-weight="700">・強酸性の胃液で微生物をタンパク質分解</text>
          </g>

          <!-- 全フロー線 (カードの上に乗るように最後に一括描画、隠れを完全防止し、線と三角の進行方向・進入角を数学的に一致させて完璧に融合) -->
          <!-- 口から第一胃へ (自然な約24度傾斜のまま直線的に進入し、三角と線の傾きを完全に一致) -->
          <path d="M 40,45 L 140,45 C 175,45 205,73 243,90" fill="none" stroke="var(--text-muted, #94a3b8)" stroke-width="3" stroke-dasharray="5,5" marker-end="url(#arrow)" />
          
          <!-- 反芻のループ (口 ↔ 第一胃) (左右の進入角を完全な0度水平にして結合部のカクつきを100%排除) -->
          <path d="M 246,110 C 190,90 135,105 106,105" fill="none" stroke="#fbbf24" stroke-width="2.2" stroke-dasharray="3,3" marker-end="url(#arrow-orange)" />
          <path d="M 105,105 C 135,120 205,120 243,120" fill="none" stroke="#fbbf24" stroke-width="2.2" stroke-dasharray="3,3" marker-end="url(#arrow-orange)" />

          <!-- 第一胃 → 第二胃 (ベジェ曲線と直線Lを組み合わせ、終点手前19pxを完全な水平直線Lにすることで、マーカー底辺との幾何学的結合ズレを数学的に完全ゼロへ解消) -->
          <path d="M 475,120 C 485,120 495,87.5 505,87.5 L 524,87.5" fill="none" stroke="#2563eb" stroke-width="2.5" marker-end="url(#arrow-blue)" />
          
          <!-- 第二胃 → 第三胃 (右シフトに追従し、新しい中心軸 635 上を綺麗に垂直下落) -->
          <path d="M 635,125 L 635,159" fill="none" stroke="#d97706" stroke-width="2.5" marker-end="url(#arrow-orange)" />
          
          <!-- 第三胃 → 第四胃 (右シフトに伴う十分な距離により、さらに滑らかな弧を描きながら第四胃の右上 483,231 に斜めアプローチ) -->
          <path d="M 530,202.5 C 500,202.5 488,222.5 483,231" fill="none" stroke="#dc2626" stroke-width="2.5" marker-end="url(#arrow-red)" />
          
          <!-- 第四胃 → 十二指腸・小腸 -->
          <path d="M 268,272.5 C 210,272.5 170,305 125,305" fill="none" stroke="var(--text-muted, #94a3b8)" stroke-width="3" stroke-dasharray="3,3" marker-end="url(#arrow)" />
          <text x="120" y="325" fill="var(--text-primary, #1e293b)" font-size="11.5" font-weight="800" text-anchor="middle">小腸へ ➔ 消化物・栄養吸収</text>
        </svg>
      `;
      digestDiagramEl.innerHTML = stomachsSvg;
      digestDiagramEl.className = 'digest-diagram-svg-container';
    }
  }

  // 2. 泌乳曲線と管理 (lactation)
  if (pageId === 'ch2-lactation') {
    const contentContainer = document.querySelector('.sales-manual-content');
    if (contentContainer) {
      // 最初のh2要素を見つけて、その直前に挿入する
      const firstH2 = contentContainer.querySelector('h2');
      if (firstH2) {
        const diagWrapper = document.createElement('div');
        diagWrapper.className = 'diagram-container-wrapper lactation-diagram-wrapper';
        
        const lactationSvg = `
          <svg viewBox="0 0 800 420" width="100%" height="auto" class="diagram-svg lactation-svg">
            <defs>
              <linearGradient id="neg-energy-grad" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stop-color="#ef4444" stop-opacity="0.14"/>
                <stop offset="100%" stop-color="#ef4444" stop-opacity="0.0"/>
              </linearGradient>
            </defs>

            <rect width="800" height="420" rx="16" fill="var(--bg-card, #ffffff)" stroke="var(--border-subtle, #e2e8f0)" stroke-width="1.5"/>

            <!-- グリッド背景：y軸数値を30px下へずらして視認性アップ -->
            <g stroke="var(--border-subtle, #e2e8f0)" stroke-width="1" stroke-dasharray="4,4">
              <line x1="80" y1="110" x2="740" y2="110" />
              <line x1="80" y1="170" x2="740" y2="170" />
              <line x1="80" y1="230" x2="740" y2="230" />
              <line x1="80" y1="290" x2="740" y2="290" />
              <line x1="80" y1="350" x2="740" y2="350" />
              
              <line x1="180" y1="90" x2="180" y2="360" stroke="#f87171" stroke-dasharray="none" stroke-width="1.5" />
              <line x1="300" y1="90" x2="300" y2="360" />
              <line x1="480" y1="90" x2="480" y2="360" />
              <line x1="660" y1="90" x2="660" y2="360" stroke="#60a5fa" stroke-dasharray="none" stroke-width="1.5" />
            </g>

            <!-- 負のエネルギーバランス期 (NEB) の視認性向上 -->
            <rect x="180" y="90" width="160" height="270" fill="url(#neg-energy-grad)" />
            <text x="200" y="325" fill="#dc2626" font-size="12" font-weight="900" letter-spacing="0.05em">⚠️ 負のエネルギーバランス期 (NEB)</text>
            <text x="200" y="342" fill="#e11d48" font-size="10.5" font-weight="800">（少量で高エネなバイパス脂肪酸・Caが最も重要！）</text>

            <!-- 左右の縦軸ラベル -->
            <text x="80" y="60" fill="var(--text-primary, #0f172a)" font-size="12.5" font-weight="800" text-anchor="middle">乳量/DMI</text>
            <text x="740" y="60" fill="var(--text-primary, #0f172a)" font-size="12.5" font-weight="800" text-anchor="middle">体重/BCS</text>

            <!-- 左側縦軸数値 -->
            <text x="40" y="115" fill="var(--text-muted, #64748b)" font-size="11" text-anchor="end">50 kg</text>
            <text x="40" y="175" fill="var(--text-muted, #64748b)" font-size="11" text-anchor="end">40 kg</text>
            <text x="40" y="235" fill="var(--text-muted, #64748b)" font-size="11" text-anchor="end">30 kg</text>
            <text x="40" y="295" fill="var(--text-muted, #64748b)" font-size="11" text-anchor="end">20 kg</text>
            <text x="40" y="355" fill="var(--text-muted, #64748b)" font-size="11" text-anchor="end">10 kg</text>

            <!-- 右側縦軸数値 (BCS) (枠内にはみ出しなく美しく収めるため、右端から20pxの余白を確保して右寄せ text-anchor="end" に最適化) -->
            <text x="780" y="115" fill="var(--text-muted, #64748b)" font-size="11" text-anchor="end">高 (BCS 3.5)</text>
            <text x="780" y="235" fill="var(--text-muted, #64748b)" font-size="11" text-anchor="end">中 (BCS 3.0)</text>
            <text x="780" y="355" fill="var(--text-muted, #64748b)" font-size="11" text-anchor="end">低 (BCS 2.5)</text>

            <!-- 横軸 (ステージラベル) -->
            <text x="130" y="385" fill="var(--text-secondary, #475569)" font-size="11.5" font-weight="800" text-anchor="middle">乾乳期 (-60〜0日)</text>
            <text x="180" y="402" fill="#b91c1c" font-size="13" font-weight="900" text-anchor="middle">分娩 (0日)</text>
            <text x="240" y="385" fill="var(--text-secondary, #475569)" font-size="11" text-anchor="middle">4週</text>
            <text x="300" y="385" fill="var(--text-secondary, #475569)" font-size="11.5" font-weight="800" text-anchor="middle">泌乳初期 (〜80日)</text>
            <text x="400" y="385" fill="var(--text-secondary, #475569)" font-size="11" text-anchor="middle">120日</text>
            <text x="480" y="385" fill="var(--text-secondary, #475569)" font-size="11.5" font-weight="800" text-anchor="middle">泌乳中期 (〜200日)</text>
            <text x="580" y="385" fill="var(--text-secondary, #475569)" font-size="11" text-anchor="middle">280日</text>
            <text x="660" y="385" fill="var(--text-secondary, #475569)" font-size="11.5" font-weight="800" text-anchor="middle">乾乳 (305日〜)</text>

            <!-- グラフ上部に完璧に分離された凡例：もう絶対線やピーク文字と重ならない -->
            <g transform="translate(130, 25)">
              <line x1="0" y1="5" x2="20" y2="5" stroke="#2563eb" stroke-width="4.5" />
              <text x="28" y="9" fill="var(--text-primary, #0f172a)" font-size="11.5" font-weight="800">🥛 乳量 (Milk)</text>
            </g>
            <g transform="translate(290, 25)">
              <line x1="0" y1="5" x2="20" y2="5" stroke="#d97706" stroke-width="4.5" />
              <text x="28" y="9" fill="var(--text-primary, #0f172a)" font-size="11.5" font-weight="800">🌾 乾物摂取量 (DMI)</text>
            </g>
            <g transform="translate(480, 25)">
              <line x1="0" y1="5" x2="20" y2="5" stroke="#e11d48" stroke-width="3" stroke-dasharray="3,3" />
              <text x="28" y="9" fill="var(--text-primary, #0f172a)" font-size="11.5" font-weight="800">⚖️ 体重 / BCS</text>
            </g>

            <!-- グラフ曲線：y座標を+30px補正して余裕のある描画へ -->
            <!-- 1. 乳量曲線 ── 青色 -->
            <path d="M 80,290 C 130,280 180,260 180,250 C 190,210 220,120 260,120 C 300,120 380,155 480,190 C 580,225 660,265 660,275" 
                  fill="none" stroke="#2563eb" stroke-width="4.5" stroke-linecap="round" />
            
            <!-- 2. DMI（食い込み）曲線 ── オレンジ色 -->
            <path d="M 80,320 C 130,325 180,300 180,295 C 195,280 250,200 320,200 C 380,200 480,215 580,235 C 660,255 660,290" 
                  fill="none" stroke="#d97706" stroke-width="4.5" stroke-linecap="round" />

            <!-- 3. 体重 / BCS 曲線 ── 赤破線 (U字) -->
            <path d="M 80,160 C 130,150 180,170 180,180 C 200,215 240,260 270,260 C 320,260 380,225 480,190 C 580,165 660,145 660,140" 
                  fill="none" stroke="#e11d48" stroke-width="3" stroke-dasharray="3,3" stroke-linecap="round" />

            <!-- 各種ピークインジケーター：十分な距離を保ちクリーンに配置 -->
            <circle cx="260" cy="120" r="6" fill="#2563eb" stroke="#fff" stroke-width="2.5" />
            <text x="260" y="96" fill="#1e3a8a" font-size="11" font-weight="900" text-anchor="middle">乳量ピーク (4〜8週)</text>

            <circle cx="320" cy="200" r="6" fill="#d97706" stroke="#fff" stroke-width="2.5" />
            <text x="330" y="186" fill="#b45309" font-size="11" font-weight="900" text-anchor="middle">食い込みピーク (10〜12週)</text>

            <circle cx="270" cy="260" r="6" fill="#e11d48" stroke="#fff" stroke-width="2.5" />
            <text x="270" y="282" fill="#be123c" font-size="11" font-weight="900" text-anchor="middle">体重の底 (BCS最低)</text>
          </svg>
        `;
        
        diagWrapper.innerHTML = `
          <div class="diagram-header-wrapper" style="margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
            <h3 style="margin: 0; font-size: 16px; font-weight: 800; color: var(--accent-blue);">📈 泌乳サイクル・食い込み・体重（BCS）の推移相関図</h3>
          </div>
        ` + lactationSvg;
        
        firstH2.parentNode.insertBefore(diagWrapper, firstH2);
      }
    }
  }

  // 3. 飼料分析項目の基本 ── タンパク質画分 (protein-fraction)
  if (pageId === 'ch2-analysis') {
    const h3Elements = document.querySelectorAll('.sales-manual-content h3');
    let targetH3 = null;
    h3Elements.forEach(h3 => {
      if (h3.textContent.includes('タンパク質')) {
        targetH3 = h3;
      }
    });

    if (targetH3) {
      const diagWrapper = document.createElement('div');
      diagWrapper.className = 'diagram-container-wrapper protein-diagram-wrapper';
      
      const proteinFractionSvg = `
        <svg viewBox="0 0 800 360" width="100%" height="auto" class="diagram-svg protein-svg">
          <defs>
            <linearGradient id="grad-cp" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#475569" stop-opacity="1"/>
              <stop offset="100%" stop-color="#1e293b" stop-opacity="1"/>
            </linearGradient>
            <linearGradient id="grad-sip" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#f87171" stop-opacity="0.9"/>
              <stop offset="100%" stop-color="#ef4444" stop-opacity="0.95"/>
            </linearGradient>
            <linearGradient id="grad-dip" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#60a5fa" stop-opacity="0.9"/>
              <stop offset="100%" stop-color="#2563eb" stop-opacity="0.95"/>
            </linearGradient>
            <linearGradient id="grad-uip" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#34d399" stop-opacity="0.9"/>
              <stop offset="100%" stop-color="#059669" stop-opacity="0.95"/>
            </linearGradient>
            <linearGradient id="grad-bp" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#a1a1aa" stop-opacity="0.9"/>
              <stop offset="100%" stop-color="#71717a" stop-opacity="0.95"/>
            </linearGradient>
            <filter id="shadow-soft" x="-5%" y="-5%" width="110%" height="110%">
              <feDropShadow dx="1" dy="3" stdDeviation="3" flood-color="#000" flood-opacity="0.12"/>
            </filter>
            <marker id="arrow-red-p" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L0,6 L6,3 Z" fill="#ef4444" />
            </marker>
            <marker id="arrow-blue-p" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L0,6 L6,3 Z" fill="#2563eb" />
            </marker>
            <marker id="arrow-green-p" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L0,6 L6,3 Z" fill="#059669" />
            </marker>
            <marker id="arrow-gray-p" markerWidth="8" markerHeight="8" refX="5" refY="3" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L0,6 L6,3 Z" fill="#71717a" />
            </marker>
          </defs>

          <rect width="800" height="360" rx="16" fill="var(--bg-card, #ffffff)" stroke="var(--border-subtle, #e2e8f0)" stroke-width="1.5"/>

          <!-- エリア枠 -->
          <rect x="150" y="45" width="350" height="280" rx="12" fill="none" stroke="var(--border-subtle, rgba(226, 232, 240, 0.4))" stroke-width="2" stroke-dasharray="6,6" />
          <text x="325" y="32" fill="var(--text-muted, #64748b)" font-size="12" font-weight="800" text-anchor="middle">第一胃（ルーメン）内での消化挙動</text>

          <rect x="520" y="45" width="250" height="280" rx="12" fill="none" stroke="var(--border-subtle, rgba(226, 232, 240, 0.4))" stroke-width="2" stroke-dasharray="6,6" />
          <text x="645" y="32" fill="var(--text-muted, #64748b)" font-size="12" font-weight="800" text-anchor="middle">第四胃・小腸での栄養吸収</text>

          <!-- 粗蛋白質 (CP) 全体 -->
          <g transform="translate(20, 80)" filter="url(#shadow-soft)">
            <rect width="100" height="200" rx="10" fill="url(#grad-cp)" stroke="#0f172a" stroke-width="2" />
            <text x="50" y="90" fill="#fff" font-size="15" font-weight="800" text-anchor="middle">粗蛋白質</text>
            <text x="50" y="115" fill="#94a3b8" font-size="20" font-weight="900" text-anchor="middle">CP</text>
            <text x="50" y="145" fill="#cbd5e1" font-size="11" font-weight="700" text-anchor="middle">(100%)</text>
          </g>

          <!-- 分配パイプ -->
          <path d="M 120,120 L 165,95" fill="none" stroke="#ef4444" stroke-width="2.5" />
          <path d="M 120,150 L 165,150" fill="none" stroke="#2563eb" stroke-width="2.5" />
          <path d="M 120,180 L 165,225" fill="none" stroke="#059669" stroke-width="2.5" />
          <path d="M 120,210 L 165,290" fill="none" stroke="#71717a" stroke-width="2.5" />

          <!-- 1. SIP -->
          <g transform="translate(170, 60)" filter="url(#shadow-soft)">
            <rect width="160" height="60" rx="8" fill="url(#grad-sip)" stroke="#b91c1c" stroke-width="1.5" />
            <text x="12" y="24" fill="#fff" font-size="12" font-weight="800">溶解性タンパク (SIP)</text>
            <text x="12" y="44" fill="#fecaca" font-size="10.5">・ルーメンで「超急速」に分解</text>
          </g>
          <path d="M 330,90 L 375,90" fill="none" stroke="#ef4444" stroke-width="2" stroke-dasharray="3,3" marker-end="url(#arrow-red-p)" />
          <text x="340" y="83" fill="#dc2626" font-size="9.5" font-weight="700" text-anchor="start">⚠️ 多すぎるとアンモニアが過剰に（ロス）</text>

          <!-- 2. DIP -->
          <g transform="translate(170, 130)" filter="url(#shadow-soft)">
            <rect width="160" height="60" rx="8" fill="url(#grad-dip)" stroke="#1d4ed8" stroke-width="1.5" />
            <text x="12" y="24" fill="#fff" font-size="12" font-weight="800">分解性タンパク (DIP)</text>
            <text x="12" y="44" fill="#bfdbfe" font-size="10.5">・微生物がゆっくり分解・利用</text>
          </g>
          <path d="M 330,160 L 380,160 C 410,160 420,135 440,135 L 530,135" fill="none" stroke="#2563eb" stroke-width="2.5" marker-end="url(#arrow-blue-p)" />
          <text x="340" y="153" fill="#2563eb" font-size="9.5" font-weight="800" text-anchor="start">微生物のエサに 🦠</text>

          <!-- 3. UIP -->
          <g transform="translate(170, 200)" filter="url(#shadow-soft)">
            <rect width="160" height="60" rx="8" fill="url(#grad-uip)" stroke="#047857" stroke-width="1.5" />
            <text x="12" y="24" fill="#fff" font-size="12" font-weight="800">非分解性タンパク (UIP)</text>
            <text x="12" y="44" fill="#ecfdf5" font-size="10.5" font-weight="700">・ルーメンを完全にスルー！</text>
          </g>
          <path d="M 330,230 L 530,230" fill="none" stroke="#059669" stroke-width="4" marker-end="url(#arrow-green-p)" />
          <text x="340" y="222" fill="#047857" font-size="9.5" font-weight="900" text-anchor="start">✨ 最も重要：バイパスプロテイン</text>

          <!-- 4. BP -->
          <g transform="translate(170, 270)" filter="url(#shadow-soft)">
            <rect width="160" height="50" rx="8" fill="url(#grad-bp)" stroke="#52525b" stroke-width="1.5" />
            <text x="12" y="22" fill="#fff" font-size="12" font-weight="800">結合タンパク (BP)</text>
            <text x="12" y="38" fill="#e4e4e7" font-size="10">・繊維と結合して消化不可</text>
          </g>
          <path d="M 330,295 L 430,295 C 460,295 470,305 490,305 L 530,305" fill="none" stroke="#71717a" stroke-width="2" marker-end="url(#arrow-gray-p)" />
          <text x="340" y="288" fill="#71717a" font-size="9.5" text-anchor="start">そのまま糞として排出 💩</text>

          <!-- 右側：最終消化・合流 -->
          <!-- DIP ➔ BCP -->
          <g transform="translate(540, 100)" filter="url(#shadow-soft)">
            <rect width="210" height="55" rx="8" fill="url(#grad-dip)" stroke="#1d4ed8" stroke-width="1.5" />
            <text x="12" y="22" fill="#fff" font-size="11.5" font-weight="800">微生物体蛋白 (BCP)</text>
            <text x="12" y="40" fill="#eff6ff" font-size="9.5">微生物自体が良質なアミノ酸源として小腸へ</text>
          </g>
          
          <!-- UIP ➔ 直接小腸へ -->
          <g transform="translate(540, 195)" filter="url(#shadow-soft)">
            <rect width="210" height="55" rx="8" fill="url(#grad-uip)" stroke="#047857" stroke-width="1.5" />
            <text x="12" y="22" fill="#fff" font-size="11.5" font-weight="800">バイパス蛋白 (UIP)</text>
            <text x="12" y="40" fill="#ecfdf5" font-size="9.5">飼料の優れたアミノ酸をダイレクトに小腸へ</text>
          </g>

          <!-- アミノ酸吸収 -->
          <g transform="translate(540, 270)" filter="url(#shadow-soft)">
            <rect width="210" height="40" rx="8" fill="var(--bg-primary, #f8fafc)" stroke="var(--border-medium, #cbd5e1)" stroke-width="1.5" />
            <text x="105" y="25" fill="var(--text-primary, #0f172a)" font-size="12.5" font-weight="800" text-anchor="middle">🎯 小腸でアミノ酸として効率吸収</text>
          </g>

          <!-- BCPからアミノ酸吸収へ：中間にあるUIPカードを右側に大きく美しく迂回する新規ライン（被りを100%解決） -->
          <path d="M 645,155 L 645,175 L 765,175 L 765,260 L 735,268" fill="none" stroke="#2563eb" stroke-width="2.2" marker-end="url(#arrow-blue-p)" />

          <!-- UIPからアミノ酸吸収へ -->
          <path d="M 645,250 L 645,270" fill="none" stroke="#059669" stroke-width="2.5" marker-end="url(#arrow-green-p)" />
        </svg>
      `;
      
      diagWrapper.innerHTML = `
        <div class="diagram-header-wrapper" style="margin: 20px 0 12px; display: flex; align-items: center; gap: 8px;">
          <h4 style="margin: 0; font-size: 15px; font-weight: 800; color: var(--accent-blue);">🧬 粗タンパク質（CP）の画分分類とルーメン内外での挙動フロー</h4>
        </div>
      ` + proteinFractionSvg + `
        <div class="so-what-section" style="margin-top: 25px;">
          <div class="so-what-header">
            <span>📢</span> 酪農営業の「提案への活かし方（勘所）」── 飼料分析のタンパク質画分をどう提案に活かすか？
          </div>
          <p class="so-what-intro">
            農家から「CP（粗タンパク質）が高いエサをあげているのに乳量が伸びない」「乳中尿素窒素（MUN）が高い」と言われた時こそ、この画分フローの出番です。単なるタンパク質の「量」ではなく、「ルーメン内での挙動（質とタイミング）」を紐解くことで、他社と次元の違う飼料コンサルティングが可能になります。
          </p>
          <div class="so-what-grid">
            <!-- 勘所① -->
            <div class="so-what-card type-1">
              <div class="so-what-title-container">
                <span class="so-what-number">勘所①</span>
                <span class="so-what-title">SIP（溶解性タンパク）の「無駄遣い」と「エネルギーロス」を突く</span>
              </div>
              <div class="so-what-body">
                SIPはルーメン内で「超急速」に分解されますが、微生物の利用スピードを超えるとアンモニアとして血液に吸収され、肝臓で尿素に変換されて尿や乳（BUN/MUN）として排出されます。これは高価なタンパク質をドブに捨てているだけでなく、<span class="marker-highlight">肝臓での尿素合成に余計なエネルギーを浪費し、牛の痩せ（NEB）を悪化させる最悪のロス</span>です。
              </div>
              <div class="action-box">
                <div class="action-icon">👉</div>
                <div class="action-content">
                  <span class="action-label">営業のアクション</span>
                  「MUNが高い」農家に対し、「タンパク質がルーメン内で利用しきれずロスになっており、さらに牛の体力を奪っています。SIPの低い高品質アルファルファやバイパス製品に切り替えて、<strong>窒素利用効率（コストパフォーマンス）を最大化</strong>しましょう」と提案します。
                </div>
              </div>
            </div>

            <!-- 勘所② -->
            <div class="so-what-card type-2">
              <div class="so-what-title-container">
                <span class="so-what-number">勘所②</span>
                <span class="so-what-title">安価で極上なタンパク源「BCP（微生物蛋白）」を最大化する「同期」提案</span>
              </div>
              <div class="so-what-body">
                牛にとって最もアミノ酸バランスが良い理想のタンパク源は、ルーメン微生物の死骸である「BCP（微生物体蛋白）」です。微生物がDIP（分解性タンパク）を材料に自分の体（BCP）を作るには、<span class="marker-highlight">同時に「燃料」となるでんぷん・糖などの発酵性炭水化物が必要</span>です。エネルギーが足りないと、せっかくのタンパクがBCPに合成されずロスになります。
              </div>
              <div class="action-box">
                <div class="action-icon">👉</div>
                <div class="action-content">
                  <span class="action-label">営業のアクション</span>
                  「タンパクを与えているのに乳量が伸びない」農家に対し、「タンパクとでんぷんのタイミングが『同期』していません。<strong>発酵性エネルギー飼料（コーンサイレージや加熱加工麦等）をセットで給与</strong>し、ルーメン内での極上BCP合成量を最大化させましょう」と、飼料全体のバランス設計を提案します。
                </div>
              </div>
            </div>

            <!-- 勘所③ -->
            <div class="so-what-card type-3">
              <div class="so-what-title-container">
                <span class="so-what-number">勘所③</span>
                <span class="so-what-title">高泌乳牛の「限界突破」にはバイパス蛋白（UIP）が絶対必須</span>
              </div>
              <div class="so-what-body">
                乳量が1日40kgを超えるような高泌乳牛は、ルーメン微生物（BCP）が作るアミノ酸だけでは絶対に足りません。しかし、これ以上濃厚飼料（DIP等）を増やすとルーメンアシドーシスの危険が高まります。そこで、ルーメンを完全にスルーして小腸へ直行する<span class="marker-highlight">「UIP（バイパス蛋白）」をダイレクトに送り込むこと</span>が、安全に乳量を伸ばす唯一の手段になります。
              </div>
              <div class="action-box">
                <div class="action-icon">👉</div>
                <div class="action-content">
                  <span class="action-label">営業のアクション</span>
                  「これ以上エサを増やすと胃が心配、でも乳量を伸ばしたい」農家に対し、「ルーメンに一切負担をかけず小腸で100%吸収される<strong>バイパス大豆製品や高品質アルファルファ</strong>の給与が唯一の解決策です。安全に乳量と乳タンパク質の上限を突破しましょう」と提案します。
                </div>
              </div>
            </div>
          </div>
        </div>`;
      
      // h3 の次の要素（通常は説明のpタグ）を見つけて、その後に挿入する
      const nextSibling = targetH3.nextElementSibling;
      if (nextSibling) {
        nextSibling.parentNode.insertBefore(diagWrapper, nextSibling.nextSibling);
      } else {
        targetH3.parentNode.insertBefore(diagWrapper, targetH3.nextSibling);
      }
    }
  }
}

// =========================================================================
//   日本の祝日判定ロジック ＆ 各種実務便利ツール（日付計算・スケジュール支援）
// =========================================================================

// 2023年〜2027年の日本の祝日（振替休日含む）を動的算出する関数
function getJapanHolidays(year) {
  const holidays = {};
  function add(month, day, name) {
    const mStr = String(month).padStart(2, '0');
    const dStr = String(day).padStart(2, '0');
    holidays[`${year}-${mStr}-${dStr}`] = name;
  }
  
  // 1. 固定祝日
  add(1, 1, "元日");
  add(2, 11, "建国記念の日");
  add(2, 23, "天皇誕生日");
  add(4, 29, "昭和の日");
  add(5, 3, "憲法記念日");
  add(5, 4, "みどりの日");
  add(5, 5, "こどもの日");
  add(8, 11, "山の日");
  add(11, 3, "文化の日");
  add(11, 23, "勤労感謝の日");

  // 2. ハッピーマンデー（1月第2月曜、7月第3月曜、10月第2月曜、9月第3月曜）
  function getHappyMonday(month, nth) {
    const firstDay = new Date(year, month - 1, 1).getDay();
    let firstMondayDay = 1;
    if (firstDay !== 1) {
      firstMondayDay = 1 + (8 - firstDay) % 7;
    }
    return firstMondayDay + (nth - 1) * 7;
  }
  add(1, getHappyMonday(1, 2), "成人の日");
  add(7, getHappyMonday(7, 3), "海の日");
  add(10, getHappyMonday(10, 2), "スポーツの日");
  add(9, getHappyMonday(9, 3), "敬老の日");

  // 3. 春分・秋分の日（天文近似計算値）
  const vernal = Math.floor(20.8431 + 0.242194 * (year - 1980) - Math.floor((year - 1980) / 4));
  add(3, vernal, "春分の日");

  const autumnal = Math.floor(23.2488 + 0.242194 * (year - 1980) - Math.floor((year - 1980) / 4));
  add(9, autumnal, "秋分の日");

  // 4. 振替休日（祝日が日曜の場合、翌日以降の祝日でない日を休日とする）
  const baseKeys = Object.keys(holidays);
  baseKeys.forEach(dateStr => {
    const [y, m, d] = dateStr.split('-').map(Number);
    const dateObj = new Date(y, m - 1, d);
    if (dateObj.getDay() === 0) { // 日曜日
      let checkDate = new Date(y, m - 1, d + 1);
      let checkStr = `${checkDate.getFullYear()}-${String(checkDate.getMonth() + 1).padStart(2, '0')}-${String(checkDate.getDate()).padStart(2, '0')}`;
      while (holidays[checkStr]) {
        checkDate.setDate(checkDate.getDate() + 1);
        checkStr = `${checkDate.getFullYear()}-${String(checkDate.getMonth() + 1).padStart(2, '0')}-${String(checkDate.getDate()).padStart(2, '0')}`;
      }
      holidays[checkStr] = `振替休日 (${holidays[dateStr]}の振替)`;
    }
  });

  // 5. 国民の休日（祝日と祝日に挟まれた平日を休日とする）
  const finalKeys = Object.keys(holidays).sort();
  for (let i = 0; i < finalKeys.length - 1; i++) {
    const d1 = new Date(finalKeys[i]);
    const d2 = new Date(finalKeys[i+1]);
    const diffDays = Math.round((d2 - d1) / (1000 * 60 * 60 * 24));
    if (diffDays === 2) {
      const sandwiched = new Date(d1);
      sandwiched.setDate(sandwiched.getDate() + 1);
      if (sandwiched.getDay() !== 0) { // 日曜でなければ
        const sandStr = `${sandwiched.getFullYear()}-${String(sandwiched.getMonth() + 1).padStart(2, '0')}-${String(sandwiched.getDate()).padStart(2, '0')}`;
        if (!holidays[sandStr]) holidays[sandStr] = "国民の休日";
      }
    }
  }

  return holidays;
}

// 営業日・カレンダー日の加算計算関数
function calculateBusinessDays(startDateStr, days, calcMode, includeStart) {
  const mode = typeof calcMode === 'string' ? calcMode : (calcMode ? 'business' : 'calendar');
  const startD = new Date(startDateStr);
  const startYear = startD.getFullYear();
  
  // 必要な範囲の祝日カレンダーを用意（年またぎ対応として3カ年分取得）
  const holidays = {
    ...getJapanHolidays(startYear - 1),
    ...getJapanHolidays(startYear),
    ...getJapanHolidays(startYear + 1)
  };

  let currentDate = new Date(startDateStr);
  let daysCounted = 0;
  const skipped = [];
  let isFirst = true;

  while (daysCounted < days) {
    if (!isFirst || !includeStart) {
      currentDate.setDate(currentDate.getDate() + 1);
    }
    isFirst = false;

    const dateStr = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}-${String(currentDate.getDate()).padStart(2, '0')}`;
    const dayOfWeek = currentDate.getDay(); // 0=Sun, 6=Sat

    const isHoliday = holidays[dateStr];
    let shouldSkip = false;
    let type = '';

    if (mode === 'business') {
      if (dayOfWeek === 0 || dayOfWeek === 6 || isHoliday) {
        shouldSkip = true;
        type = dayOfWeek === 0 ? "日曜日" : dayOfWeek === 6 ? "土曜日" : isHoliday;
      }
    } else if (mode === 'sun_holidays') {
      if (dayOfWeek === 0 || isHoliday) {
        shouldSkip = true;
        type = dayOfWeek === 0 ? "日曜日" : isHoliday;
      }
    }

    if (shouldSkip) {
      skipped.push(`${dateStr} (${type})`);
    } else {
      daysCounted++;
    }
  }

  const resultStr = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}-${String(currentDate.getDate()).padStart(2, '0')}`;
  return {
    resultDateStr: resultStr,
    skipped
  };
}

// デマレージ/ディテンション段階料金プリセット
const CHARGE_PRESETS = {
  demurrage_standard: {
    name: "デマレージ汎用標準 (1-7日: ¥1,000 / 8-14日: ¥3,000 / 15日~: ¥6,000)",
    type: "demurrage",
    tiers: [
      { startDay: 1, endDay: 7, rate: 1000 },
      { startDay: 8, endDay: 14, rate: 3000 },
      { startDay: 15, endDay: 999, rate: 6000 }
    ]
  },
  detention_standard: {
    name: "ディテンション汎用標準 (1-4日: ¥4,400 / 5-9日: ¥6,600 / 10日~: ¥10,900)",
    type: "detention",
    tiers: [
      { startDay: 1, endDay: 4, rate: 4400 },
      { startDay: 5, endDay: 9, rate: 6600 },
      { startDay: 10, endDay: 999, rate: 10900 }
    ]
  },
  whl_demurrage: {
    name: "WHL (Wan Hai Lines) デマレージ参考 (1-3日: ¥5,000 / 4-7日: ¥10,000 / 8日~: ¥20,000)",
    type: "demurrage",
    tiers: [
      { startDay: 1, endDay: 3, rate: 5000 },
      { startDay: 4, endDay: 7, rate: 10000 },
      { startDay: 8, endDay: 999, rate: 20000 }
    ]
  },
  yangming_detention: {
    name: "YANG MING ディテンション参考 (40HQ: ¥7,500/日)",
    type: "detention",
    tiers: [
      { startDay: 1, endDay: 999, rate: 7500 }
    ]
  }
};

let currentTiers = [...CHARGE_PRESETS.demurrage_standard.tiers];

// -------------------------------------------------------------------------
//  1. 日付・デマレージ計算ツールの描画 & イベント処理
// -------------------------------------------------------------------------
function renderDateCalculator() {
  contentArea.innerHTML = `
    <div class="page-hero" style="padding: 24px; margin-bottom: 24px;">
      <h1 class="page-title">🗓️ 営業日・デマレージ日数＆費用計算機</h1>
      <p class="page-subtitle">日本の祝日・日祝除外に対応し、フリータイム限界日およびフリータイム超過後のデマレージ・ディテンション料金（段階単価対応）を正確に計算します。</p>
    </div>

    <div class="tool-grid">
      <div class="tool-card">
        <h3>⚡ 計算条件の指定</h3>
        <div class="tool-form">
          <div class="tool-group">
            <label for="calcStartDate">起算日（開始日）</label>
            <input type="date" id="calcStartDate" value="${new Date().toISOString().split('T')[0]}">
          </div>
          <div class="tool-group">
            <label for="calcDays">フリータイム（F/T）加算日数</label>
            <input type="number" id="calcDays" value="10" min="1" max="999">
          </div>
          <div class="tool-group">
            <label for="calcMode">カウント方法</label>
            <select id="calcMode">
              <option value="business" selected>営業日のみカウント（土日・日本の祝日を除外）</option>
              <option value="sun_holidays">日祝のみ除外（土曜日はカウント、日曜・祝日を除外）</option>
              <option value="calendar">カレンダー日カウント（暦通り全てカウント）</option>
            </select>
          </div>
          <label class="tool-checkbox-group">
            <input type="checkbox" id="calcIncludeStart" checked>
            <span>起算日（開始日）を1日目としてカウントに含める</span>
          </label>

          <hr style="border: none; border-top: 1px dashed var(--border-subtle); margin: 16px 0;">

          <div class="tool-group">
            <label for="calcPickupDate">搬出日 / 返却予定日（任意入力・超過料金計算用）</label>
            <input type="date" id="calcPickupDate" value="">
            <span style="font-size: 11px; color: var(--text-muted); margin-top: 4px; display: block;">
              ※フリータイム終了後に搬出・返却する場合、超過日数およびデマレージ/ディテンション料金が試算されます。
            </span>
          </div>
        </div>
      </div>

      <div class="tool-card">
        <h3>🎯 フリータイム計算結果</h3>
        <div class="result-box">
          <div class="result-lbl" id="resultLabelText">フリータイム終了日（荷渡し・デマレージ限界日）</div>
          <div class="result-date" id="resultDateText">YYYY年MM月DD日(曜)</div>
          <div class="result-lbl" id="resultSummaryText">営業日10日間を加算</div>
        </div>

        <div class="result-details" style="margin-top: 14px;">
          <div id="overdueSummaryBadge" style="display: none; padding: 10px 14px; border-radius: 8px; font-weight: 600; font-size: 13px; margin-bottom: 12px; background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.2);">
            ⚠️ フリータイム超過: <span id="overdueDaysCount">0</span> 日間
          </div>

          <h4>🚫 スキップ（除外）された週末・祝日一覧</h4>
          <ul class="skipped-list" id="skippedList">
            <li>除外日はありません。</li>
          </ul>
        </div>
      </div>
    </div>

    <!-- 超過料金計算セクション -->
    <div class="tool-card" style="margin-top: 24px;" id="feeCalcCard">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 16px;">
        <h3 style="margin: 0;">💰 デマレージ・ディテンション超過料金シミュレーター</h3>
        <div style="display: flex; gap: 8px; align-items: center;">
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary);">料金プリセット:</label>
          <select id="presetSelect" style="padding: 6px 12px; font-size: 12px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-primary); color: var(--text-primary);">
            <option value="demurrage_standard" selected>デマレージ汎用標準 (1-7日: ¥1,000 / 8-14日: ¥3,000 / 15日~: ¥6,000)</option>
            <option value="detention_standard">ディテンション汎用標準 (1-4日: ¥4,400 / 5-9日: ¥6,600 / 10日~: ¥10,900)</option>
            <option value="whl_demurrage">WHL (Wan Hai Lines) デマレージ参考</option>
            <option value="yangming_detention">YANG MING ディテンション参考 (40HQ: ¥7,500/日)</option>
            <option value="custom">カスタム設定</option>
          </select>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;" class="fee-calc-grid">
        <div>
          <h4 style="font-size: 13px; margin: 0 0 10px; color: var(--text-secondary);">⚙️ 段階別料金設定（日額単価）</h4>
          <table class="assistant-table" style="font-size: 12px; width: 100%; border-collapse: collapse; margin-bottom: 10px;" id="tierTable">
            <thead>
              <tr style="background: var(--bg-primary); text-align: left;">
                <th style="padding: 8px;">超過日数範囲</th>
                <th style="padding: 8px;">1日あたり単価（税抜）</th>
                <th style="padding: 8px; width: 50px; text-align: center;">操作</th>
              </tr>
            </thead>
            <tbody id="tierTableBody">
              <!-- 動的描画 -->
            </tbody>
          </table>
          <button class="btn btn-secondary" id="btnAddTierBtn" style="padding: 4px 12px; font-size: 12px;">+ 段階を追加</button>
        </div>

        <div>
          <h4 style="font-size: 13px; margin: 0 0 10px; color: var(--text-secondary);">📊 超過料金計算サマリー</h4>
          <div style="background: var(--bg-primary); border: 1px solid var(--border-medium); border-radius: 12px; padding: 16px;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 13px;">
              <span style="color: var(--text-secondary);">超過日数:</span>
              <strong id="feeOverdueDaysText" style="color: #ef4444;">0 日間</strong>
            </div>

            <div style="border-top: 1px dashed var(--border-subtle); padding-top: 10px; margin-top: 10px;" id="tierBreakdownList">
              <!-- 段階別の小計計算内訳 -->
              <span style="font-size: 12px; color: var(--text-muted);">搬出日/返却予定日を入力すると内訳が表示されます。</span>
            </div>

            <div style="border-top: 2px solid var(--border-medium); padding-top: 12px; margin-top: 12px; display: flex; justify-content: space-between; align-items: baseline;">
              <span style="font-size: 14px; font-weight: 700;">合計超過料金:</span>
              <div style="text-align: right;">
                <span id="feeTotalAmountText" style="font-size: 22px; font-weight: 800; color: var(--accent-blue);">¥0</span>
                <div style="font-size: 11px; color: var(--text-muted);" id="feeTaxInclusiveText">（税込 10%: ¥0）</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- カレンダープレビュー -->
    <div class="tool-card" style="margin-top: 24px;">
      <h3>📅 計算月のカレンダープレビュー（月跨ぎ対応）</h3>
      <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 16px; display: flex; flex-wrap: wrap; gap: 14px; align-items: center;">
        <span><span style="display:inline-block; width:12px; height:12px; background:rgba(37,99,235,0.12); border-radius:3px; vertical-align:middle;"></span> カウント対象</span>
        <span><span style="display:inline-block; width:12px; height:12px; background:#ef4444; opacity:0.3; border-radius:3px; vertical-align:middle;"></span> 除外（週末・祝日スキップ）</span>
        <span><span style="display:inline-block; width:12px; height:12px; background:var(--accent-blue); border-radius:3px; vertical-align:middle;"></span> F/T終了日</span>
        <span><span style="display:inline-block; width:12px; height:12px; background:rgba(239,68,68,0.25); border: 1px solid #ef4444; border-radius:3px; vertical-align:middle;"></span> デマレージ/ディテンション超過期間</span>
        <span><span style="display:inline-block; width:12px; height:12px; background:#8b5cf6; border-radius:3px; vertical-align:middle;"></span> 搬出・返却日</span>
      </p>
      <div id="calendarContainer"></div>
    </div>
  `;

  const startDateInput = document.getElementById('calcStartDate');
  const daysInput = document.getElementById('calcDays');
  const modeSelect = document.getElementById('calcMode');
  const includeStartCheck = document.getElementById('calcIncludeStart');
  const pickupDateInput = document.getElementById('calcPickupDate');
  const presetSelect = document.getElementById('presetSelect');
  const addTierBtn = document.getElementById('btnAddTierBtn');

  function renderTierRows() {
    const tbody = document.getElementById('tierTableBody');
    tbody.innerHTML = '';

    currentTiers.forEach((tier, idx) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="padding: 6px 8px;">
          <div style="display: flex; align-items: center; gap: 4px;">
            <input type="number" min="1" max="999" value="${tier.startDay}" class="tier-input-start" data-idx="${idx}" style="width: 55px; padding: 4px; border: 1px solid var(--border-medium); border-radius: 4px; background: var(--bg-card); color: var(--text-primary);">
            日目 〜 
            <input type="number" min="1" max="999" value="${tier.endDay >= 999 ? '' : tier.endDay}" placeholder="以降" class="tier-input-end" data-idx="${idx}" style="width: 55px; padding: 4px; border: 1px solid var(--border-medium); border-radius: 4px; background: var(--bg-card); color: var(--text-primary);">
            日目
          </div>
        </td>
        <td style="padding: 6px 8px;">
          <div style="display: flex; align-items: center; gap: 4px;">
            ¥ <input type="number" step="100" min="0" value="${tier.rate}" class="tier-input-rate" data-idx="${idx}" style="width: 100px; padding: 4px; border: 1px solid var(--border-medium); border-radius: 4px; background: var(--bg-card); color: var(--text-primary);">
          </div>
        </td>
        <td style="padding: 6px 8px; text-align: center;">
          ${currentTiers.length > 1 ? `<button class="btn-delete-tier" data-idx="${idx}" style="background: none; border: none; color: #ef4444; cursor: pointer; font-size: 14px;">✕</button>` : ''}
        </td>
      `;
      tbody.appendChild(tr);
    });

    // 行入力イベントのバインド
    document.querySelectorAll('.tier-input-start').forEach(input => {
      input.addEventListener('change', (e) => {
        const idx = parseInt(e.target.dataset.idx);
        currentTiers[idx].startDay = parseInt(e.target.value) || 1;
        presetSelect.value = 'custom';
        updateCalculation();
      });
    });

    document.querySelectorAll('.tier-input-end').forEach(input => {
      input.addEventListener('change', (e) => {
        const idx = parseInt(e.target.dataset.idx);
        currentTiers[idx].endDay = e.target.value === '' ? 999 : parseInt(e.target.value) || 999;
        presetSelect.value = 'custom';
        updateCalculation();
      });
    });

    document.querySelectorAll('.tier-input-rate').forEach(input => {
      input.addEventListener('change', (e) => {
        const idx = parseInt(e.target.dataset.idx);
        currentTiers[idx].rate = parseInt(e.target.value) || 0;
        presetSelect.value = 'custom';
        updateCalculation();
      });
    });

    document.querySelectorAll('.btn-delete-tier').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const idx = parseInt(e.target.dataset.idx);
        currentTiers.splice(idx, 1);
        presetSelect.value = 'custom';
        renderTierRows();
        updateCalculation();
      });
    });
  }

  presetSelect.addEventListener('change', (e) => {
    const val = e.target.value;
    if (val !== 'custom' && CHARGE_PRESETS[val]) {
      currentTiers = JSON.parse(JSON.stringify(CHARGE_PRESETS[val].tiers));
      renderTierRows();
      updateCalculation();
    }
  });

  addTierBtn.addEventListener('click', () => {
    const lastTier = currentTiers[currentTiers.length - 1];
    const newStart = lastTier ? (lastTier.endDay < 999 ? lastTier.endDay + 1 : lastTier.startDay + 7) : 1;
    currentTiers.push({ startDay: newStart, endDay: 999, rate: 5000 });
    presetSelect.value = 'custom';
    renderTierRows();
    updateCalculation();
  });

  function updateCalculation() {
    const startVal = startDateInput.value;
    const daysVal = parseInt(daysInput.value) || 0;
    const calcMode = modeSelect.value;
    const includeStart = includeStartCheck.checked;
    const pickupVal = pickupDateInput.value;

    if (!startVal || daysVal <= 0) return;

    // 計算を実行
    const calcResult = calculateBusinessDays(startVal, daysVal, calcMode, includeStart);
    
    // 日本語曜日表示
    const targetDate = new Date(calcResult.resultDateStr);
    const dayNames = ["日", "月", "火", "水", "木", "金", "土"];
    const dayName = dayNames[targetDate.getDay()];
    
    document.getElementById('resultDateText').textContent = 
      `${targetDate.getFullYear()}年${targetDate.getMonth() + 1}月${targetDate.getDate()}日 (${dayName})`;
    
    let modeText = '営業日';
    if (calcMode === 'sun_holidays') modeText = '日祝除外';
    if (calcMode === 'calendar') modeText = 'カレンダー日';

    document.getElementById('resultSummaryText').textContent = 
      `${modeText} ${daysVal}日間を${includeStart ? '起算日を含めて' : '翌日から'}加算`;

    // 除外リストの描画
    const list = document.getElementById('skippedList');
    list.innerHTML = '';
    if (calcResult.skipped.length === 0) {
      list.innerHTML = '<li>スキップされた曜日はありません。</li>';
    } else {
      calcResult.skipped.forEach(skip => {
        const li = document.createElement('li');
        li.textContent = skip.replace(/-/g, '/');
        list.appendChild(li);
      });
    }

    // 超過日数と料金計算
    let overdueDays = 0;
    if (pickupVal) {
      const pDate = new Date(pickupVal);
      const tDate = new Date(calcResult.resultDateStr);
      const diffMs = pDate.getTime() - tDate.getTime();
      if (diffMs > 0) {
        overdueDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      }
    }

    const badge = document.getElementById('overdueSummaryBadge');
    if (overdueDays > 0) {
      badge.style.display = 'block';
      document.getElementById('overdueDaysCount').textContent = overdueDays;
    } else {
      badge.style.display = 'none';
    }

    // 料金の計算
    document.getElementById('feeOverdueDaysText').textContent = `${overdueDays} 日間`;
    const breakdownContainer = document.getElementById('tierBreakdownList');
    breakdownContainer.innerHTML = '';

    let totalFee = 0;

    if (overdueDays > 0) {
      currentTiers.sort((a, b) => a.startDay - b.startDay);

      currentTiers.forEach((tier) => {
        if (overdueDays < tier.startDay) return;

        const effectiveEnd = Math.min(overdueDays, tier.endDay);
        const daysInTier = effectiveEnd - tier.startDay + 1;

        if (daysInTier > 0) {
          const subtotal = daysInTier * tier.rate;
          totalFee += subtotal;

          const row = document.createElement('div');
          row.style.cssText = 'display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; color: var(--text-secondary);';
          const endLabel = tier.endDay >= 999 ? '〜' : `${tier.endDay}日目`;
          row.innerHTML = `
            <span>${tier.startDay}〜${endLabel} (${daysInTier}日間 × ¥${tier.rate.toLocaleString()}):</span>
            <strong>¥${subtotal.toLocaleString()}</strong>
          `;
          breakdownContainer.appendChild(row);
        }
      });
    } else {
      breakdownContainer.innerHTML = '<span style="font-size: 12px; color: var(--text-muted);">超過なし（デマレージ/ディテンション費用 ￥0）</span>';
    }

    document.getElementById('feeTotalAmountText').textContent = `¥${totalFee.toLocaleString()}`;
    const taxInc = Math.round(totalFee * 1.10);
    document.getElementById('feeTaxInclusiveText').textContent = `（税込 10%: ¥${taxInc.toLocaleString()}）`;

    // カレンダーの描画（マルチ月対応）
    const calContainer = document.getElementById('calendarContainer');
    const startYear = new Date(startVal).getFullYear();
    const holidays = {
      ...getJapanHolidays(startYear - 1),
      ...getJapanHolidays(startYear),
      ...getJapanHolidays(startYear + 1)
    };
    drawCalendarVisualizer(calContainer, startVal, calcResult.resultDateStr, calcMode, includeStart, holidays, pickupVal);
  }

  // 初期化とイベントバインド
  renderTierRows();

  startDateInput.addEventListener('input', updateCalculation);
  daysInput.addEventListener('input', updateCalculation);
  modeSelect.addEventListener('change', updateCalculation);
  includeStartCheck.addEventListener('change', updateCalculation);
  pickupDateInput.addEventListener('input', updateCalculation);

  // 初期計算
  updateCalculation();
}

function drawCalendarVisualizer(container, startDateStr, targetDateStr, calcMode, includeStart, holidays, pickupDateStr = null) {
  container.innerHTML = '';
  
  const startD = new Date(startDateStr);
  const targetD = new Date(targetDateStr);
  const pickupD = pickupDateStr ? new Date(pickupDateStr) : null;
  
  const maxD = (pickupD && pickupD > targetD) ? pickupD : targetD;

  let currentYear = startD.getFullYear();
  let currentMonth = startD.getMonth();

  const endYear = maxD.getFullYear();
  const endMonth = maxD.getMonth();

  const wrapper = document.createElement('div');
  wrapper.className = 'multi-calendar-wrapper';

  const startMs = startD.getTime();
  const targetMs = targetD.getTime();
  const pickupMs = pickupD ? pickupD.getTime() : null;

  while (currentYear < endYear || (currentYear === endYear && currentMonth <= endMonth)) {
    const monthCard = document.createElement('div');
    monthCard.className = 'month-block';

    const monthTitle = document.createElement('div');
    monthTitle.className = 'month-title';
    monthTitle.textContent = `🗓️ ${currentYear}年 ${currentMonth + 1}月`;
    monthCard.appendChild(monthTitle);

    const calGrid = document.createElement('div');
    calGrid.className = 'calendar-visualizer-grid';

    const headers = ['日', '月', '火', '水', '木', '金', '土'];
    headers.forEach(h => {
      const el = document.createElement('div');
      el.className = 'cal-day-name';
      el.textContent = h;
      calGrid.appendChild(el);
    });

    const firstDayIndex = new Date(currentYear, currentMonth, 1).getDay();
    const totalDays = new Date(currentYear, currentMonth + 1, 0).getDate();

    for (let i = 0; i < firstDayIndex; i++) {
      const el = document.createElement('div');
      el.className = 'cal-day-cell other-month';
      calGrid.appendChild(el);
    }

    for (let day = 1; day <= totalDays; day++) {
      const cellDateStr = `${currentYear}-${String(currentMonth + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
      const cellDate = new Date(currentYear, currentMonth, day);
      const cellMs = cellDate.getTime();
      const dayOfWeek = cellDate.getDay();
      const isHoliday = holidays[cellDateStr];

      const cell = document.createElement('div');
      cell.className = 'cal-day-cell';
      cell.textContent = day;

      if (dayOfWeek === 6) cell.classList.add('weekend-sat');
      if (dayOfWeek === 0) cell.classList.add('weekend-sun');
      if (isHoliday) {
        cell.classList.add('holiday');
        cell.title = isHoliday;
      }

      if (cellDateStr === startDateStr) {
        cell.classList.add('start-date');
        cell.title = "起算日 (開始日)";
      }

      if (cellDateStr === targetDateStr) {
        cell.classList.add('target');
        cell.title = "フリータイム終了日 / 計算結果日";
      } else if (pickupDateStr && cellDateStr === pickupDateStr) {
        cell.classList.add('pickup-target');
        cell.title = "搬出日 / 返却日";
      }

      if (cellMs >= startMs && cellMs <= targetMs) {
        let isWeekend = false;
        if (calcMode === 'business') {
          isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
        } else if (calcMode === 'sun_holidays') {
          isWeekend = dayOfWeek === 0;
        }

        if ((calcMode === 'business' || calcMode === 'sun_holidays') && (isWeekend || isHoliday)) {
          cell.classList.add('skipped');
        } else {
          cell.classList.add('counted');
        }
      } else if (pickupMs && cellMs > targetMs && cellMs <= pickupMs) {
        cell.classList.add('overdue');
        cell.title = "超過保管料（デマレージ/ディテンション）発生日";
      }

      calGrid.appendChild(cell);
    }

    monthCard.appendChild(calGrid);
    wrapper.appendChild(monthCard);

    currentMonth++;
    if (currentMonth > 11) {
      currentMonth = 0;
      currentYear++;
    }
  }

  container.appendChild(wrapper);
}

// -------------------------------------------------------------------------
//  2. 得意先スケジュール表 更新支援ツールの描画 & Excelコピペ操作ロジック
// -------------------------------------------------------------------------
let scheduleDataRows = [];

function renderScheduleAssistant() {
  contentArea.innerHTML = `
    <div class="page-hero" style="padding: 24px; margin-bottom: 24px;">
      <h1 class="page-title">📊 得意先船積スケジュール表 更新アシスタント</h1>
      <p class="page-subtitle">Excelのスケジュール表をコピー＆ペーストして、ETA（入港日）に基づく植検日・荷渡し日の自動推定、日付誤入力のダブルチェックを自動化します。</p>
    </div>

    <div class="tool-card" style="margin-bottom: 20px;">
      <h3>📥 スケジュールデータの貼り付け</h3>
      <p style="font-size:12px; color:var(--text-muted); margin-top:0; margin-bottom:12px;">
        Excelの「契約番号」から「サーチャージ」までの行（ヘッダー行を含むと自動列判定します）をコピーし、下の枠に貼り付け（Ctrl+V / Cmd+V）て「読み込む」をクリックしてください。
      </p>
      <textarea class="input-paste-area" id="pasteArea" placeholder="ここにExcelからコピーしたデータを貼り付けてください..."></textarea>
      
      <div class="btn-row" style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:10px;">
        <div>
          <button class="btn btn-secondary" id="btnLoadSample" style="border-color:var(--accent-blue); color:var(--accent-blue);">岩崎清七商店様の見本データを読込</button>
        </div>
        <div style="display:flex; gap:10px;">
          <button class="btn btn-primary" id="btnLoadPaste">📋 データを読み込んで編集</button>
        </div>
      </div>
    </div>

    <div class="tool-card" id="assistantGridCard" style="display:none;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; flex-wrap:wrap; gap:10px;">
        <h3 style="margin:0;">📝 スケジュール表データ編集グリッド</h3>
        <div style="display:flex; gap:10px;">
          <button class="btn btn-secondary" id="btnApplyAllProposed" style="border-color:var(--accent-green); color:var(--accent-green); padding:6px 14px; font-size:12px;">⚡ 全ての推奨日付を自動適用</button>
          <button class="btn btn-primary" id="btnExportTsv" style="background:linear-gradient(135deg,var(--accent-green),#107c41); border-color:#107c41; color:#fff; padding:6px 16px; font-size:12px;">🖨️ 編集結果をExcel用形式でコピー</button>
        </div>
      </div>

      <div class="alert alert-note" style="margin-bottom:16px; font-size:12px; padding:10px 16px;">
        💡 <b>日付自動計算機能:</b> ETAを変更すると、翌営業日の「推奨植検日/荷渡し日」を自動計算します。Excelデータの値と食い違う場合は黄色で警告表示されます。<br>
        🚫 <b>日付エラーチェック:</b> ETAがETD（出港予定日）より過去になっている箇所は、年の入力ミス等の危険性があるため赤くハイライトされます。
      </div>

      <div class="assistant-grid-wrapper">
        <table class="assistant-table" id="assistantTable">
          <!-- JSで動的にテーブル描画 -->
        </table>
      </div>
    </div>
  `;

  // イベント登録
  document.getElementById('btnLoadSample').addEventListener('click', loadSampleScheduleData);
  document.getElementById('btnLoadPaste').addEventListener('click', parsePastedScheduleData);
  
  // 編集結果TSVエクスポート
  document.getElementById('btnExportTsv').addEventListener('click', exportGridToClipboard);
  document.getElementById('btnApplyAllProposed').addEventListener('click', applyAllProposedDates);
}

// サンプルデータのロード
function loadSampleScheduleData() {
  const sampleData = `契約番号	シッパー	商品	本数	コンテナ	荷姿	グレード/スタック＃	揚港	船名	ETD	ETA	植検日	荷渡し日	単価	サーチャージ
VIT0013	Viterra/Valley Hay	3	40FT	500KG	DRO MC 	東京	(WW) WESTWOOD VICTORIA	2023-09-09	2023-09-30	2023-10-02	2023-10-02	82000	
VIT0014	Viterra/Valley Hay	2	20FT	Bulk	DRO	東京	(WW) WESTWOOD VICTORIA	2023-09-09	2023-09-30	2023-10-02	2023-10-02	69600	
VIT0015	Viterra/Valley Hay	4	40FT	500KG	DRO MC 	東京	(WW) RAINIER	2023-10-03	2023-10-25	2023-10-26	2023-10-26	84400	
VIT0016	Viterra/Valley Hay	1	20FT	Bulk	DRO	東京	(HYD) YM TRIUMPH	2023-11-06	2023-11-19	2023-11-20	2023-11-20	69200	
VIT0021	Viterra/Valley Hay	2	40FT	500KG	DRO MC	東京	(ONE) ONE MANEUVER 	2023-12-30	2024-01-14	2024-01-16	2024-01-16	83900	
VIT0022	Viterra/Valley Hay	3	40FT	500KG	DRO MC 	東京	(WST) TONGA CHIEF	2023-12-19	2024-01-15	2024-01-15	2024-01-15	84300	
VIT0028	Viterra/Valley Hay	2	40FT	500KG	DRO MC 	東京	(HND) SEASPAN BENEFACTOR	2023-12-30	2023-01-17	2024-01-18	2024-01-18	85600	
VIT0023	Viterra/Valley Hay	1	20FT	バラ	DRO 	東京	(WST) PORT VILA CHIEF	2024-01-24	2024-02-28	2024-02-29	2024-02-29	70900	
VIT0024	Viterra/Valley Hay	3	40FT	500KG	DRO MC 	東京	(WST) WW RAINIER	2024-01-25	2024-02-17	2024-02-19	2024-02-19	86600	
VIT0024A	Viterra/Valley Hay	1	20FT	バラ	DRO 	東京	(WST) TONGA CHIEF	2024-01-31	2024-02-28	2024-02-29	2024-02-29	73000	
VIT0025	Viterra/Valley Hay	2	40FT	500KG	DRO MC 	東京	(WST) GSL MAREN	2024-02-13	2024-03-13	2024-03-14	2024-03-14	84700	
VIT0026	Viterra/Valley Hay	3	40FT	500KG	DRO MC 	東京	(WST) VANUATU CHIEF	2024-02-27	2024-03-26	2024-03-27	2024-03-27	87000	
VIT0027	Viterra/Valley Hay	4	40FT	500KG	DRO MC 	東京	(WST) TONGA CHIEF	2024-03-19	2024-04-14	2024-04-15	2024-04-15	89500	
VIT0029	Viterra/Valley Hay	4	40FT	500KG	DRO MC 	東京	(WST) VANUATU CHIEF	2024-04-14	2024-05-06	2024-05-07	2024-05-07	88900	
VIT0030	Viterra/Valley Hay	4	40FT	500KG	DRO MC 	東京	(WST) TONGA CHIEF	2024-04-30	2024-05-25	2024-05-27	2024-05-27	88800	
VIT0031	Viterra/Valley Hay	4	40FT	500KG	DRO MC 	東京	(WST) WW RAINER	2024-05-13	2024-06-03	2024-06-05	2024-06-05	91200	
VIT0032	Viterra/Valley Hay	4	40FT	500KG	DRO MC 	東京	(SWS) WESTWOOD VICTORIA	2024-06-12	2024-07-02	2024-07-03	2024-07-03	87400	
VIT0040	Viterra/Valley Hay	1	40FT	25KG	TRO SC	東京	(HMM) SEASPAN YANGTZE 	2024-07-09	2024-07-20	2024-07-23	2024-07-23	79300	
VIT0033	Viterra/Valley Hay	4	40FT	500KG	DRO MC 	東京	(SWS) MOTUKEA CHIEF	2024-07-02	2024-07-28	2024-07-29	2024-07-29	87400	`;

  document.getElementById('pasteArea').value = sampleData.trim();
  showGlobalToast('📥', '岩崎清七商店様の見本データを読み込み枠にセットしました');
  parsePastedScheduleData();
}

// コピペテキストのパース
function parsePastedScheduleData() {
  const txt = document.getElementById('pasteArea').value.trim();
  if (!txt) {
    alert('貼り付けエリアにテキストを入力してください。');
    return;
  }

  const lines = txt.split('\n');
  if (lines.length < 2) {
    alert('データが正しくありません。ヘッダー行とデータ行を含めてコピーしてください。');
    return;
  }

  // 1行目をヘッダーとする
  const headers = lines[0].split('\t').map(h => h.trim());
  
  // 各列のインデックスの自動マッピング
  const colMap = {
    contract: headers.findIndex(h => h.includes('契約番号')),
    shipper: headers.findIndex(h => h.includes('シッパー')),
    product: headers.findIndex(h => h.includes('商品')),
    qty: headers.findIndex(h => h.includes('本数')),
    container: headers.findIndex(h => h.includes('コンテナ')),
    packing: headers.findIndex(h => h.includes('荷姿')),
    grade: headers.findIndex(h => h.includes('グレード')),
    port: headers.findIndex(h => h.includes('揚港')),
    vessel: headers.findIndex(h => h.includes('船名')),
    etd: headers.findIndex(h => h.includes('ETD')),
    eta: headers.findIndex(h => h.includes('ETA')),
    inspec: headers.findIndex(h => h.includes('植検')),
    deliv: headers.findIndex(h => h.includes('荷渡し') || h.includes('荷渡')),
    price: headers.findIndex(h => h.includes('単価')),
    surcharge: headers.findIndex(h => h.includes('サーチャージ'))
  };

  // 最低限「契約番号」「ETA」が存在するかチェック
  if (colMap.contract === -1 || colMap.eta === -1) {
    alert('「契約番号」または「ETA」の列が見つかりません。Excelのヘッダー列がコピーされているか確認してください。');
    return;
  }

  scheduleDataRows = [];

  for (let i = 1; i < lines.length; i++) {
    const cells = lines[i].split('\t').map(c => c.trim());
    if (cells.length < 2 || !cells[colMap.contract]) continue;

    function getVal(idx) {
      return idx !== -1 ? cells[idx] || '' : '';
    }

    scheduleDataRows.push({
      contract: getVal(colMap.contract),
      shipper: getVal(colMap.shipper),
      product: getVal(colMap.product),
      qty: getVal(colMap.qty),
      container: getVal(colMap.container),
      packing: getVal(colMap.packing),
      grade: getVal(colMap.grade),
      port: getVal(colMap.port),
      vessel: getVal(colMap.vessel),
      etd: getVal(colMap.etd),
      eta: getVal(colMap.eta),
      inspec: getVal(colMap.inspec),
      deliv: getVal(colMap.deliv),
      price: getVal(colMap.price),
      surcharge: getVal(colMap.surcharge)
    });
  }

  // グリッド表示
  renderGridTable();
  document.getElementById('assistantGridCard').style.display = 'block';
  
  // グリッドへスクロール
  document.getElementById('assistantGridCard').scrollIntoView({ behavior: 'smooth' });
  showGlobalToast('⚙️', `${scheduleDataRows.length}件のデータを読み込みました`);
}

// スケジュールアシスタントテーブルのレンダリング
function renderGridTable() {
  const table = document.getElementById('assistantTable');
  table.innerHTML = '';

  // ヘッダー行作成
  const thead = document.createElement('thead');
  thead.innerHTML = `
    <tr>
      <th>契約番号</th>
      <th>船名</th>
      <th>ETD (出港日)</th>
      <th>ETA (入港日)</th>
      <th>現在の植検日</th>
      <th>現在の荷渡し日</th>
      <th>推奨 植検日/荷渡し</th>
      <th>商品</th>
      <th>単価</th>
    </tr>
  `;
  table.appendChild(thead);

  // データ行作成
  const tbody = document.createElement('tbody');
  
  scheduleDataRows.forEach((row, idx) => {
    const tr = document.createElement('tr');
    tr.id = `row-${idx}`;

    // ETA / ETDの整合性検証 (過去日付や typo の検証)
    let isTypoError = false;
    let typoMsg = '';
    
    if (row.eta && row.etd) {
      const etdTime = new Date(row.etd).getTime();
      const etaTime = new Date(row.eta).getTime();
      if (!isNaN(etdTime) && !isNaN(etaTime)) {
        if (etaTime < etdTime) {
          // ETAが出港日より前になっている（年入力ミスなど）
          isTypoError = true;
          typoMsg = "ETAがETDより前です";
        }
      }
    }

    if (isTypoError) {
      tr.classList.add('row-error-typo');
    }

    // 推奨日の計算 (ETAの翌営業日)
    let proposedInspec = '';
    if (row.eta && !isNaN(new Date(row.eta).getTime())) {
      const calc = calculateBusinessDays(row.eta, 1, true, false); // ETAの翌営業日 (起算日含めず1営業日後)
      proposedInspec = calc.resultDateStr;
    }

    // 値が推奨値と異なるか？ (手動入力のずれチェック)
    const inspecMismatch = row.inspec && row.inspec !== proposedInspec;
    const delivMismatch = row.deliv && row.deliv !== proposedInspec;

    const typoAlertHtml = isTypoError ? `<span class="typo-tag-alert" title="${typoMsg}">⚠️ 年入力ミス懸念</span>` : '';
    const inspecAlertHtml = inspecMismatch ? `<span class="date-badge-mismatch" title="Excel値と計算値が異なります">⚠️ 計算値(${proposedInspec})</span>` : `<span class="date-badge-calc">✓ 一致</span>`;

    tr.innerHTML = `
      <td><strong>${row.contract}</strong>${typoAlertHtml}</td>
      <td>${row.vessel}</td>
      <td>${row.etd}</td>
      <td>
        <input type="date" value="${row.eta}" onchange="updateRowEta(${idx}, this.value)" style="${isTypoError ? 'border-color:var(--accent-rose); background:rgba(224,36,36,0.05);' : ''}">
      </td>
      <td>
        <input type="date" id="inspec-${idx}" value="${row.inspec}" onchange="updateRowInspec(${idx}, this.value)">
      </td>
      <td>
        <input type="date" id="deliv-${idx}" value="${row.deliv}" onchange="updateRowDeliv(${idx}, this.value)">
      </td>
      <td style="vertical-align:middle; text-align:left;">
        <div style="display:flex; align-items:center; gap:6px;">
          <span style="font-weight:700; color:var(--accent-green);">${proposedInspec}</span>
          <button class="aladdin-btn primary" onclick="applyProposedToRow(${idx}, '${proposedInspec}')" style="padding:2px 6px; font-size:10px;">適用</button>
          ${inspecAlertHtml}
        </div>
      </td>
      <td>${row.product} (${row.qty}本)</td>
      <td>${row.price}</td>
    `;
    tbody.appendChild(tr);
  });
  
  table.appendChild(tbody);
}

// 個別行のETAが更新された時の処理
window.updateRowEta = function(idx, val) {
  scheduleDataRows[idx].eta = val;
  // ETAの変更に伴って、植検日と荷渡し日を推奨日に初期更新（ユーザーの負担軽減）
  if (val && !isNaN(new Date(val).getTime())) {
    const calc = calculateBusinessDays(val, 1, true, false);
    scheduleDataRows[idx].inspec = calc.resultDateStr;
    scheduleDataRows[idx].deliv = calc.resultDateStr;
  }
  renderGridTable();
};

window.updateRowInspec = function(idx, val) {
  scheduleDataRows[idx].inspec = val;
};

window.updateRowDeliv = function(idx, val) {
  scheduleDataRows[idx].deliv = val;
};

// 行ごとに推奨日を適用する処理
window.applyProposedToRow = function(idx, dateStr) {
  scheduleDataRows[idx].inspec = dateStr;
  scheduleDataRows[idx].deliv = dateStr;
  renderGridTable();
  showGlobalToast('⚡', `契約 ${scheduleDataRows[idx].contract} に対する推奨日を適用しました`);
};

// すべての行に推奨営業日を自動適用
function applyAllProposedDates() {
  if (confirm('すべてのレコードに対し、ETAから算出した推奨 植検日・荷渡し日（翌営業日換算）を自動適用します。よろしいですか？')) {
    scheduleDataRows.forEach((row, idx) => {
      if (row.eta && !isNaN(new Date(row.eta).getTime())) {
        const calc = calculateBusinessDays(row.eta, 1, true, false);
        row.inspec = calc.resultDateStr;
        row.deliv = calc.resultDateStr;
      }
    });
    renderGridTable();
    showGlobalToast('⚡', 'すべてのレコードに推奨日程を自動適用しました');
  }
}

// 編集済みデータをTSVでクリップボードに出力する
function exportGridToClipboard() {
  const pasteAreaVal = document.getElementById('pasteArea').value.trim();
  const headers = pasteAreaVal.split('\n')[0].split('\t').map(h => h.trim());
  
  const colMap = {
    contract: headers.findIndex(h => h.includes('契約番号')),
    shipper: headers.findIndex(h => h.includes('シッパー')),
    product: headers.findIndex(h => h.includes('商品')),
    qty: headers.findIndex(h => h.includes('本数')),
    container: headers.findIndex(h => h.includes('コンテナ')),
    packing: headers.findIndex(h => h.includes('荷姿')),
    grade: headers.findIndex(h => h.includes('グレード')),
    port: headers.findIndex(h => h.includes('揚港')),
    vessel: headers.findIndex(h => h.includes('船名')),
    etd: headers.findIndex(h => h.includes('ETD')),
    eta: headers.findIndex(h => h.includes('ETA')),
    inspec: headers.findIndex(h => h.includes('植検')),
    deliv: headers.findIndex(h => h.includes('荷渡し') || h.includes('荷渡')),
    price: headers.findIndex(h => h.includes('単価')),
    surcharge: headers.findIndex(h => h.includes('サーチャージ'))
  };

  // TSV文字列の組み立て
  let tsv = headers.join('\t') + '\n';
  
  scheduleDataRows.forEach(row => {
    const lineArr = new Array(headers.length).fill('');
    
    function setCell(idx, val) {
      if (idx !== -1) lineArr[idx] = val;
    }

    setCell(colMap.contract, row.contract);
    setCell(colMap.shipper, row.shipper);
    setCell(colMap.product, row.product);
    setCell(colMap.qty, row.qty);
    setCell(colMap.container, row.container);
    setCell(colMap.packing, row.packing);
    setCell(colMap.grade, row.grade);
    setCell(colMap.port, row.port);
    setCell(colMap.vessel, row.vessel);
    setCell(colMap.etd, row.etd);
    setCell(colMap.eta, row.eta);
    setCell(colMap.inspec, row.inspec);
    setCell(colMap.deliv, row.deliv);
    setCell(colMap.price, row.price);
    setCell(colMap.surcharge, row.surcharge);
    
    tsv += lineArr.join('\t') + '\n';
  });

  navigator.clipboard.writeText(tsv.trim()).then(() => {
    alert('編集後のスケジュール表データをExcel貼り付け用フォーマットでコピーしました！\nExcelを開いて、そのまま貼り付け（Ctrl+V / Cmd+V）してください。');
    showGlobalToast('📋', 'クリップボードにコピーしました');
  }).catch(err => {
    console.error('Copy failed: ', err);
    alert('クリップボードへのコピーに失敗しました。下のテキストエリアから手動でコピーしてください。\n\n' + tsv);
  });
}

// -------------------------------------------------------------------------
//  3. アラジン・Excel 画面見本プレビューモーダルの制御
// -------------------------------------------------------------------------
function openPreviewModal(type, detail) {
  const modal = document.getElementById('previewModal');
  const title = document.getElementById('previewModalTitle');
  const content = document.getElementById('previewModalContent');
  
  if (!modal || !title || !content) return;
  
  title.textContent = type === 'aladdin' ? `🖥️ アラジンオフィス 操作見本: [${detail}]` : `📊 Excel 伝票・シート見本: [${detail}]`;
  
  let html = '';
  
  if (type === 'aladdin') {
    html = `
      <div class="mockup-aladdin">
        <div class="aladdin-title-bar">
          <span>アラジンオフィス - [${detail || '画面見本'}]</span>
          <div class="aladdin-window-controls">
            <span></span><span></span><span></span>
          </div>
        </div>
        <div class="aladdin-menu-bar">
          <span>ファイル(F)</span><span>編集(E)</span><span>表示(V)</span><span>設定(S)</span><span>ヘルプ(H)</span>
        </div>
        <div class="aladdin-toolbar">
          <button class="aladdin-btn primary">💾 登録 (F12)</button>
          <button class="aladdin-btn">🧹 クリア (F5)</button>
          <button class="aladdin-btn">🗑️ 削除 (F9)</button>
          <button class="aladdin-btn">🖨️ 印刷 (F8)</button>
        </div>
        <div class="aladdin-form-container">
          <div class="aladdin-field highlight-field">
            <label>処理区分</label>
            <select disabled><option>新規登録</option></select>
          </div>
          <div class="aladdin-field">
            <label>入力日付</label>
            <input type="text" value="${new Date().toLocaleDateString('ja-JP')}" disabled>
          </div>
          <div class="aladdin-field highlight-field">
            <label>伝票番号</label>
            <input type="text" value="※登録時に自動採番" disabled style="font-style: italic; color:#64748b;">
          </div>
          <div class="aladdin-field highlight-field">
            <label>得意先コード</label>
            <input type="text" value="IWA001" disabled>
          </div>
          <div class="aladdin-field">
            <label>得意先名</label>
            <input type="text" value="株式会社岩崎清七商店" disabled>
          </div>
          <div class="aladdin-field">
            <label>担当者コード</label>
            <input type="text" value="M0438 (水谷)" disabled>
          </div>
        </div>
        <div class="aladdin-grid-section">
          <div class="aladdin-grid-title">📦 入力明細グリッド</div>
          <table class="aladdin-table">
            <thead>
              <tr>
                <th>行</th>
                <th>商品コード</th>
                <th>商品名</th>
                <th>数量</th>
                <th>単位</th>
                <th>単価</th>
                <th>倉庫コード</th>
                <th>備考 / B/L No.</th>
              </tr>
            </thead>
            <tbody>
              <tr class="highlight-row">
                <td>1</td>
                <td>OAT-CAN-500K</td>
                <td>カナダ産 燕麦（DRO MC）</td>
                <td>3</td>
                <td>本</td>
                <td>82,000</td>
                <td>WH-TKY-01 (東京)</td>
                <td>B/L: VIT0013 紐付け</td>
              </tr>
              <tr>
                <td>2</td>
                <td>OAT-CAN-BLK</td>
                <td>カナダ産 燕麦（Bulk）</td>
                <td>2</td>
                <td>本</td>
                <td>69,600</td>
                <td>WH-TKY-01 (東京)</td>
                <td>B/L: VIT0014 紐付け</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 12px; line-height: 1.6;">
        ※上記の画面は、アラジンオフィスにおける「${detail}」時の操作画面見本（シミュレーション）です。オレンジ色で強調された項目が実務上の重要な入力および確認箇所となります。
      </div>
    `;
  } else if (type === 'excel') {
    html = `
      <div class="mockup-excel">
        <div class="excel-header-ribbon">
          <span>Excel - 岩崎清七商店様　スケジュール表.xlsx</span>
        </div>
        <div class="excel-tabs">
          <span class="active">ホーム</span><span>挿入</span><span>数式</span><span>データ</span><span>校閲</span>
        </div>
        <div class="excel-formula-bar">
          <span style="font-weight: 700; color:#107c41; margin-right: 8px;">fx</span>
          <div class="excel-formula-box">=WORKDAY(J12, 1, 祝日リスト!A$1:A$20)</div>
        </div>
        <div style="overflow-x:auto;">
          <table class="excel-grid">
            <thead>
              <tr>
                <th></th>
                <th>A</th>
                <th>B</th>
                <th>C</th>
                <th>D</th>
                <th>E</th>
                <th>F</th>
                <th>G</th>
                <th>H</th>
                <th>I</th>
                <th>J</th>
                <th>K</th>
                <th>L</th>
              </tr>
            </thead>
            <tbody>
              <tr class="excel-table-header">
                <td class="excel-row-num">1</td>
                <td colspan="12">株式会社岩崎清七商店　御中　成約・船積スケジュール一覧表</td>
              </tr>
              <tr class="excel-table-header-sub">
                <td class="excel-row-num">9</td>
                <td>契約番号</td>
                <td>シッパー</td>
                <td>商品</td>
                <td>本数</td>
                <td>コンテナ</td>
                <td>荷姿</td>
                <td>揚港</td>
                <td>船名</td>
                <td>ETD</td>
                <td>ETA</td>
                <td>植検日</td>
                <td>荷渡し日</td>
              </tr>
              <tr>
                <td class="excel-row-num">10</td>
                <td>VIT0013</td>
                <td>Viterra</td>
                <td>燕麦（カナダ）</td>
                <td>3</td>
                <td>40FT</td>
                <td>500KG</td>
                <td>東京</td>
                <td>WESTWOOD VICTORIA</td>
                <td>2026-06-09</td>
                <td>2026-06-20</td>
                <td class="highlight-cell">2026-06-22</td>
                <td class="highlight-cell">2026-06-22</td>
              </tr>
              <tr>
                <td class="excel-row-num">11</td>
                <td>VIT0014</td>
                <td>Viterra</td>
                <td>燕麦（カナダ）</td>
                <td>2</td>
                <td>20FT</td>
                <td>Bulk</td>
                <td>東京</td>
                <td>WESTWOOD VICTORIA</td>
                <td>2026-06-09</td>
                <td>2026-06-20</td>
                <td class="highlight-cell">2026-06-22</td>
                <td class="highlight-cell">2026-06-22</td>
              </tr>
              <tr style="background:#fff2f2;">
                <td class="excel-row-num">12</td>
                <td>VIT0028</td>
                <td>Viterra</td>
                <td>燕麦（カナダ）</td>
                <td>2</td>
                <td>40FT</td>
                <td>500KG</td>
                <td>東京</td>
                <td>SEASPAN BENEFACTOR</td>
                <td>2026-06-09</td>
                <td class="error-cell" style="color:#ef4444; font-weight:700;" title="年数の入力間違いの警告例">2025-06-20</td>
                <td>2026-06-22</td>
                <td>2026-06-22</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 12px; line-height: 1.6;">
        ※上記のグリッドは、得意先スケジュールExcel（${detail}）のフォーマットおよびエラー警告の見本です。<br>
        黄色いセルはETAから営業日計算で自動提案される日付、赤いセルはETAとETDの前後関係や年次誤りを検知した警告のシミュレーション例です。
      </div>
    `;
  }
  
  content.innerHTML = html;
  modal.classList.add('active');
}

function closePreviewModal() {
  document.getElementById('previewModal').classList.remove('active');
}

// -------------------------------------------------------------------------
//  3. フレコンバッグ資材 在庫数・在庫金額確認ツール
// -------------------------------------------------------------------------

const FLEXCON_LOCATIONS = [
  "上組 福岡支店",
  "八代サイロ（上組福岡支店八代出張所）",
  "熊本南関工場",
  "志布志倉庫",
  "門司倉庫",
  "本社倉庫"
];

const FLEXCON_ITEMS = [
  { id: "SNS-1", name: "フレコンワンウェイバッグ SNS-1 (上下全開型 φ1100×1200)", defaultPrice: 1150, safetyStock: 300 },
  { id: "BTNR-1000C", name: "フレコンワンウェイバッグ BTNR-1000C (投入口全開型 φ1100×1100H)", defaultPrice: 1000, safetyStock: 200 },
  { id: "PE-INNER", name: "国産PE内袋 (0.07×1850×3000 平シール)", defaultPrice: 550, safetyStock: 300 },
  { id: "SOYPASS-BAG", name: "ソイパス用紙袋 新印刷 (813×419×76mm)", defaultPrice: 71.5, safetyStock: 1000 }
];

const FLEXCON_SUPPLIERS = [
  "株式会社シオヤ",
  "佐藤産業株式会社",
  "その他仕入先"
];

const INITIAL_FLEXCON_DATA = {
  transactions: [
    { id: "TX-1001", date: "2026-06-22", type: "inbound", location: "上組 福岡支店", item: "SNS-1", qty: 150, price: 1000, supplier: "株式会社シオヤ", purpose: "", note: "発注書 2026.06.23" },
    { id: "TX-1002", date: "2026-07-10", type: "inbound", location: "八代サイロ（上組福岡支店八代出張所）", item: "BTNR-1000C", qty: 50, price: 1000, supplier: "株式会社シオヤ", purpose: "", note: "吊り下げポケット50枚同梱" },
    { id: "TX-1003", date: "2026-07-10", type: "inbound", location: "熊本南関工場", item: "SNS-1", qty: 500, price: 1150, supplier: "株式会社シオヤ", purpose: "", note: "発注書 2026.07.10" },
    { id: "TX-1004", date: "2026-07-10", type: "inbound", location: "熊本南関工場", item: "PE-INNER", qty: 500, price: 550, supplier: "株式会社シオヤ", purpose: "", note: "発注書 2026.07.10 別添PE内袋" },
    { id: "TX-1005", date: "2026-05-29", type: "inbound", location: "上組 福岡支店", item: "SOYPASS-BAG", qty: 3000, price: 71.5, supplier: "佐藤産業株式会社", purpose: "", note: "佐藤産業見積書単価 ￥71.5" },
    { id: "TX-1006", date: "2026-07-12", type: "outbound", location: "熊本南関工場", item: "SNS-1", qty: 80, price: 1150, supplier: "", purpose: "牧草サイレージ製品充填", note: "工場作業使用" },
    { id: "TX-1007", date: "2026-07-15", type: "outbound", location: "上組 福岡支店", item: "SOYPASS-BAG", qty: 1200, price: 71.5, supplier: "", purpose: "大豆粕パッキング出荷", note: "出荷使用" }
  ]
};

function loadFlexconData() {
  const saved = localStorage.getItem('cascadia_flexcon_inventory_v1');
  if (saved) {
    try { return JSON.parse(saved); } catch(e){}
  }
  localStorage.setItem('cascadia_flexcon_inventory_v1', JSON.stringify(INITIAL_FLEXCON_DATA));
  return JSON.parse(JSON.stringify(INITIAL_FLEXCON_DATA));
}

function saveFlexconData(data) {
  localStorage.setItem('cascadia_flexcon_inventory_v1', JSON.stringify(data));
}

let activeFlexconTab = 'dashboard';

function renderFlexconInventory() {
  const data = loadFlexconData();

  contentArea.innerHTML = `
    <div class="page-hero" style="padding: 24px; margin-bottom: 24px; background: linear-gradient(135deg, rgba(139,92,246,0.1), rgba(168,85,247,0.05)); border: 1px solid rgba(139,92,246,0.2);">
      <h1 class="page-title">📦 フレコンバッグ資材 在庫数・在庫金額確認ツール</h1>
      <p class="page-subtitle">消耗品として費用処理されるフレコンバッグ等のリアルタイム実在庫枚数・評価金額を一元管理し、安全在庫切れを防ぎます。</p>
    </div>

    <!-- サブタブナビゲーション -->
    <div class="flexcon-tabs" style="display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 2px solid var(--border-subtle); padding-bottom: 8px;">
      <button class="btn ${activeFlexconTab === 'dashboard' ? 'btn-primary' : 'btn-secondary'}" id="tabFlexconDash" style="padding: 8px 16px; font-size: 13px;">📊 在庫・金額ダッシュボード</button>
      <button class="btn ${activeFlexconTab === 'inbound' ? 'btn-primary' : 'btn-secondary'}" id="tabFlexconInbound" style="padding: 8px 16px; font-size: 13px;">📥 入庫（仕入）登録</button>
      <button class="btn ${activeFlexconTab === 'outbound' ? 'btn-primary' : 'btn-secondary'}" id="tabFlexconOutbound" style="padding: 8px 16px; font-size: 13px;">📤 出庫（使用）登録</button>
      <button class="btn ${activeFlexconTab === 'ledger' ? 'btn-primary' : 'btn-secondary'}" id="tabFlexconLedger" style="padding: 8px 16px; font-size: 13px;">📋 入出庫全履歴帳簿</button>
      <button class="btn ${activeFlexconTab === 'check' ? 'btn-primary' : 'btn-secondary'}" id="tabFlexconCheck" style="padding: 8px 16px; font-size: 13px;">📑 月末棚卸し・CSV出力</button>
    </div>

    <div id="flexconTabContent"></div>
  `;

  document.getElementById('tabFlexconDash').addEventListener('click', () => { activeFlexconTab = 'dashboard'; renderFlexconInventory(); });
  document.getElementById('tabFlexconInbound').addEventListener('click', () => { activeFlexconTab = 'inbound'; renderFlexconInventory(); });
  document.getElementById('tabFlexconOutbound').addEventListener('click', () => { activeFlexconTab = 'outbound'; renderFlexconInventory(); });
  document.getElementById('tabFlexconLedger').addEventListener('click', () => { activeFlexconTab = 'ledger'; renderFlexconInventory(); });
  document.getElementById('tabFlexconCheck').addEventListener('click', () => { activeFlexconTab = 'check'; renderFlexconInventory(); });

  const container = document.getElementById('flexconTabContent');

  if (activeFlexconTab === 'dashboard') renderFlexconDashboard(container, data);
  if (activeFlexconTab === 'inbound') renderFlexconInboundForm(container, data);
  if (activeFlexconTab === 'outbound') renderFlexconOutboundForm(container, data);
  if (activeFlexconTab === 'ledger') renderFlexconLedger(container, data);
  if (activeFlexconTab === 'check') renderFlexconCheck(container, data);
}

// 在庫計算ヘルパー
function calculateStockMatrix(transactions) {
  const matrix = {};
  FLEXCON_LOCATIONS.forEach(loc => {
    matrix[loc] = {};
    FLEXCON_ITEMS.forEach(item => {
      matrix[loc][item.id] = { qty: 0, totalValue: 0, lastPrice: item.defaultPrice };
    });
  });

  transactions.slice().sort((a, b) => new Date(a.date) - new Date(b.date)).forEach(tx => {
    if (!matrix[tx.location]) return;
    if (!matrix[tx.location][tx.item]) {
      matrix[tx.location][tx.item] = { qty: 0, totalValue: 0, lastPrice: tx.price || 1000 };
    }

    const cell = matrix[tx.location][tx.item];
    if (tx.price > 0) cell.lastPrice = tx.price;

    if (tx.type === 'inbound') {
      cell.qty += tx.qty;
      cell.totalValue += (tx.qty * (tx.price || cell.lastPrice));
    } else if (tx.type === 'outbound') {
      cell.qty -= tx.qty;
      cell.totalValue -= (tx.qty * (tx.price || cell.lastPrice));
      if (cell.qty < 0) cell.qty = 0;
      if (cell.totalValue < 0) cell.totalValue = 0;
    }
  });

  return matrix;
}

// 1. ダッシュボード描画
function renderFlexconDashboard(container, data) {
  const matrix = calculateStockMatrix(data.transactions);

  let grandTotalQty = 0;
  let grandTotalValue = 0;
  const alertItems = [];

  FLEXCON_LOCATIONS.forEach(loc => {
    FLEXCON_ITEMS.forEach(item => {
      const cell = matrix[loc][item.id];
      grandTotalQty += cell.qty;
      grandTotalValue += cell.totalValue;

      if (cell.qty < item.safetyStock) {
        alertItems.push({
          location: loc,
          item: item,
          currentQty: cell.qty,
          safetyStock: item.safetyStock
        });
      }
    });
  });

  container.innerHTML = `
    <!-- 集計カード -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 20px;">
      <div class="tool-card" style="padding: 16px;">
        <div style="font-size: 12px; color: var(--text-secondary); font-weight: 600;">全社合計 在庫枚数</div>
        <div style="font-size: 26px; font-weight: 800; color: var(--accent-blue); margin-top: 4px;">${grandTotalQty.toLocaleString()} <span style="font-size: 14px; font-weight: 600;">枚</span></div>
      </div>
      <div class="tool-card" style="padding: 16px;">
        <div style="font-size: 12px; color: var(--text-secondary); font-weight: 600;">全社総在庫金額（評価額）</div>
        <div style="font-size: 26px; font-weight: 800; color: var(--accent-violet); margin-top: 4px;">¥${Math.round(grandTotalValue).toLocaleString()}</div>
      </div>
      <div class="tool-card" style="padding: 16px; ${alertItems.length > 0 ? 'border: 1px solid rgba(239,68,68,0.3); background: rgba(239,68,68,0.03);' : ''}">
        <div style="font-size: 12px; color: var(--text-secondary); font-weight: 600;">安全在庫アラート発生数</div>
        <div style="font-size: 26px; font-weight: 800; color: ${alertItems.length > 0 ? '#ef4444' : 'var(--accent-green)'}; margin-top: 4px;">${alertItems.length} <span style="font-size: 14px; font-weight: 600;">件</span></div>
      </div>
      <div class="tool-card" style="padding: 16px;">
        <div style="font-size: 12px; color: var(--text-secondary); font-weight: 600;">アクティブ保管拠点数</div>
        <div style="font-size: 26px; font-weight: 800; color: var(--text-primary); margin-top: 4px;">${FLEXCON_LOCATIONS.length} <span style="font-size: 14px; font-weight: 600;">箇所</span></div>
      </div>
    </div>

    ${alertItems.length > 0 ? `
      <div class="alert alert-warning" style="margin-bottom: 20px; font-size: 12.5px; border-left: 4px solid #ef4444;">
        <strong>⚠️ 安全在庫アラート通知 (${alertItems.length}件):</strong><br>
        <ul style="margin: 6px 0 0; padding-left: 20px;">
          ${alertItems.map(a => `<li><strong>${a.location}</strong> - ${a.item.name}: 現在 <strong>${a.currentQty} 枚</strong> (安全基準: ${a.safetyStock}枚) ── 資材発注をご検討ください。</li>`).join('')}
        </ul>
      </div>
    ` : ''}

    <!-- 拠点別×型番別 在庫マトリックス -->
    <div class="tool-card">
      <h3 style="margin-top: 0; margin-bottom: 14px;">📊 拠点別・品名型番別 在庫数および在庫金額一覧</h3>
      <div style="overflow-x: auto;">
        <table class="assistant-table" style="font-size: 12px; width: 100%; border-collapse: collapse;">
          <thead>
            <tr style="background: var(--bg-primary); text-align: center;">
              <th style="padding: 10px; text-align: left; min-width: 180px;">保管場所（拠点）</th>
              ${FLEXCON_ITEMS.map(item => `
                <th style="padding: 10px; min-width: 150px;">
                  <div>${item.id}</div>
                  <div style="font-size: 10px; font-weight: normal; color: var(--text-muted);">${item.name.split(' ')[0]}</div>
                </th>
              `).join('')}
              <th style="padding: 10px; min-width: 140px; background: rgba(37,99,235,0.06);">拠点小計金額</th>
            </tr>
          </thead>
          <tbody>
            ${FLEXCON_LOCATIONS.map(loc => {
              let locTotalVal = 0;
              return `
                <tr>
                  <td style="padding: 10px; font-weight: 600;">${loc}</td>
                  ${FLEXCON_ITEMS.map(item => {
                    const cell = matrix[loc][item.id];
                    locTotalVal += cell.totalValue;
                    const isAlert = cell.qty < item.safetyStock;
                    return `
                      <td style="padding: 10px; text-align: right; ${isAlert ? 'background: rgba(239,68,68,0.08);' : ''}">
                        <div style="font-size: 14px; font-weight: 700; color: ${isAlert ? '#ef4444' : 'var(--text-primary)'};">${cell.qty.toLocaleString()} <span style="font-size: 11px;">枚</span></div>
                        <div style="font-size: 11px; color: var(--text-muted);">¥${Math.round(cell.totalValue).toLocaleString()}</div>
                      </td>
                    `;
                  }).join('')}
                  <td style="padding: 10px; text-align: right; font-weight: 800; color: var(--accent-violet); background: rgba(37,99,235,0.03);">
                    ¥${Math.round(locTotalVal).toLocaleString()}
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// 2. 入庫（仕入）登録フォーム
function renderFlexconInboundForm(container, data) {
  const today = new Date().toISOString().split('T')[0];

  container.innerHTML = `
    <div class="tool-card" style="max-width: 700px; margin: 0 auto;">
      <h3 style="margin-top: 0; margin-bottom: 16px;">📥 フレコン資材 入庫（仕入れ）登録</h3>
      <form id="flexconInboundForm" class="tool-form">
        <div class="tool-group">
          <label for="inDate">入庫日（仕入れ日） <span style="color:#ef4444;">*</span></label>
          <input type="date" id="inDate" value="${today}" required>
        </div>

        <div class="tool-group">
          <label for="inLocation">納品先（保管場所） <span style="color:#ef4444;">*</span></label>
          <select id="inLocation" required>
            ${FLEXCON_LOCATIONS.map(l => `<option value="${l}">${l}</option>`).join('')}
          </select>
        </div>

        <div class="tool-group">
          <label for="inItem">品名（型番） <span style="color:#ef4444;">*</span></label>
          <select id="inItem" required>
            ${FLEXCON_ITEMS.map(i => `<option value="${i.id}">${i.name} (基準単価: ¥${i.defaultPrice})</option>`).join('')}
          </select>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
          <div class="tool-group">
            <label for="inQty">入庫枚数 <span style="color:#ef4444;">*</span></label>
            <input type="number" id="inQty" min="1" max="99999" value="100" required>
          </div>
          <div class="tool-group">
            <label for="inPrice">仕入単価（税抜円） <span style="color:#ef4444;">*</span></label>
            <input type="number" id="inPrice" min="0" step="0.1" value="1000" required>
          </div>
        </div>

        <div class="tool-group">
          <label for="inSupplier">仕入れ先メーカー・商社</label>
          <select id="inSupplier">
            ${FLEXCON_SUPPLIERS.map(s => `<option value="${s}">${s}</option>`).join('')}
          </select>
        </div>

        <div class="tool-group">
          <label for="inNote">備考・発注書Noなど</label>
          <input type="text" id="inNote" placeholder="例: 発注書 2026.07.10">
        </div>

        <div style="background: var(--bg-primary); border: 1px solid var(--border-subtle); padding: 12px; border-radius: 8px; margin-top: 12px; font-size: 13px; display: flex; justify-content: space-between; align-items: center;">
          <span>入庫小計金額:</span>
          <strong id="inSubtotalText" style="font-size: 18px; color: var(--accent-blue);">¥100,000</strong>
        </div>

        <button type="submit" class="btn btn-primary" style="margin-top: 16px; width: 100%; padding: 10px; font-size: 14px;">📥 入庫データを登録する</button>
      </form>
    </div>
  `;

  const qtyIn = document.getElementById('inQty');
  const priceIn = document.getElementById('inPrice');
  const itemIn = document.getElementById('inItem');

  function updateInSubtotal() {
    const qty = parseInt(qtyIn.value) || 0;
    const price = parseFloat(priceIn.value) || 0;
    document.getElementById('inSubtotalText').textContent = `¥${Math.round(qty * price).toLocaleString()}`;
  }

  itemIn.addEventListener('change', () => {
    const selectedItem = FLEXCON_ITEMS.find(i => i.id === itemIn.value);
    if (selectedItem) priceIn.value = selectedItem.defaultPrice;
    updateInSubtotal();
  });

  qtyIn.addEventListener('input', updateInSubtotal);
  priceIn.addEventListener('input', updateInSubtotal);

  document.getElementById('flexconInboundForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const newTx = {
      id: "TX-" + Date.now().toString().slice(-6),
      date: document.getElementById('inDate').value,
      type: "inbound",
      location: document.getElementById('inLocation').value,
      item: document.getElementById('inItem').value,
      qty: parseInt(document.getElementById('inQty').value),
      price: parseFloat(document.getElementById('inPrice').value),
      supplier: document.getElementById('inSupplier').value,
      purpose: "",
      note: document.getElementById('inNote').value
    };

    data.transactions.push(newTx);
    saveFlexconData(data);
    showToast("✨ 入庫データを正常に登録しました");
    activeFlexconTab = 'dashboard';
    renderFlexconInventory();
  });
}

// 3. 出庫（使用）登録フォーム
function renderFlexconOutboundForm(container, data) {
  const today = new Date().toISOString().split('T')[0];

  container.innerHTML = `
    <div class="tool-card" style="max-width: 700px; margin: 0 auto;">
      <h3 style="margin-top: 0; margin-bottom: 16px;">📤 フレコン資材 出荷（使用）登録</h3>
      <form id="flexconOutboundForm" class="tool-form">
        <div class="tool-group">
          <label for="outDate">出荷日 / 使用日 <span style="color:#ef4444;">*</span></label>
          <input type="date" id="outDate" value="${today}" required>
        </div>

        <div class="tool-group">
          <label for="outLocation">使用拠点（保管場所） <span style="color:#ef4444;">*</span></label>
          <select id="outLocation" required>
            ${FLEXCON_LOCATIONS.map(l => `<option value="${l}">${l}</option>`).join('')}
          </select>
        </div>

        <div class="tool-group">
          <label for="outItem">品名（型番） <span style="color:#ef4444;">*</span></label>
          <select id="outItem" required>
            ${FLEXCON_ITEMS.map(i => `<option value="${i.id}">${i.name}</option>`).join('')}
          </select>
        </div>

        <div class="tool-group">
          <label for="outQty">使用枚数 <span style="color:#ef4444;">*</span></label>
          <input type="number" id="outQty" min="1" max="99999" value="50" required>
        </div>

        <div class="tool-group">
          <label for="outPurpose">使用用途・充填製品 <span style="color:#ef4444;">*</span></label>
          <input type="text" id="outPurpose" placeholder="例: 牧草サイレージ製品充填、大豆粕パッキング出荷など" required>
        </div>

        <div class="tool-group">
          <label for="outNote">備考</label>
          <input type="text" id="outNote" placeholder="例: 担当〇〇作業">
        </div>

        <button type="submit" class="btn btn-primary" style="margin-top: 16px; width: 100%; padding: 10px; font-size: 14px; background: linear-gradient(135deg, var(--accent-violet), #9333ea);">📤 出庫データを登録する</button>
      </form>
    </div>
  `;

  document.getElementById('flexconOutboundForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const loc = document.getElementById('outLocation').value;
    const itemId = document.getElementById('outItem').value;
    const qty = parseInt(document.getElementById('outQty').value);

    // 在庫チェック
    const matrix = calculateStockMatrix(data.transactions);
    const available = matrix[loc][itemId] ? matrix[loc][itemId].qty : 0;
    const itemObj = FLEXCON_ITEMS.find(i => i.id === itemId);

    if (qty > available) {
      alert(`⚠️ 出庫警告: ${loc} にある ${itemObj ? itemObj.name : itemId} の現在の在庫枚数は ${available} 枚です。要求枚数 (${qty} 枚) が現在庫を超過しています。`);
    }

    const newTx = {
      id: "TX-" + Date.now().toString().slice(-6),
      date: document.getElementById('outDate').value,
      type: "outbound",
      location: loc,
      item: itemId,
      qty: qty,
      price: matrix[loc][itemId] ? matrix[loc][itemId].lastPrice : 1000,
      supplier: "",
      purpose: document.getElementById('outPurpose').value,
      note: document.getElementById('outNote').value
    };

    data.transactions.push(newTx);
    saveFlexconData(data);
    showToast("📤 出庫データを正常に登録しました");
    activeFlexconTab = 'dashboard';
    renderFlexconInventory();
  });
}

// 4. 入出庫全履歴帳簿
function renderFlexconLedger(container, data) {
  container.innerHTML = `
    <div class="tool-card">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 16px;">
        <h3 style="margin: 0;">📋 入出庫全履歴トランザクション帳簿</h3>
        <button class="btn btn-secondary" id="btnResetFlexconData" style="font-size: 11px; color: #ef4444; border-color: rgba(239,68,68,0.3);">🔄 初期サンプルデータにリセット</button>
      </div>

      <div style="overflow-x: auto;">
        <table class="assistant-table" style="font-size: 12px; width: 100%; border-collapse: collapse;">
          <thead>
            <tr style="background: var(--bg-primary); text-align: left;">
              <th style="padding: 8px;">日付</th>
              <th style="padding: 8px;">区分</th>
              <th style="padding: 8px;">保管場所（拠点）</th>
              <th style="padding: 8px;">品名（型番）</th>
              <th style="padding: 8px; text-align: right;">枚数</th>
              <th style="padding: 8px; text-align: right;">単価</th>
              <th style="padding: 8px; text-align: right;">小計金額</th>
              <th style="padding: 8px;">仕入先 / 使用用途</th>
              <th style="padding: 8px;">備考</th>
              <th style="padding: 8px; text-align: center;">操作</th>
            </tr>
          </thead>
          <tbody>
            ${data.transactions.slice().reverse().map(tx => {
              const itemObj = FLEXCON_ITEMS.find(i => i.id === tx.item);
              const isInfo = tx.type === 'inbound';
              const amt = tx.qty * (tx.price || 0);
              return `
                <tr>
                  <td style="padding: 8px;">${tx.date}</td>
                  <td style="padding: 8px;">
                    <span style="padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; ${isInfo ? 'background: rgba(37,99,235,0.1); color: var(--accent-blue);' : 'background: rgba(139,92,246,0.1); color: var(--accent-violet);'}">
                      ${isInfo ? '📥 入庫' : '📤 出庫'}
                    </span>
                  </td>
                  <td style="padding: 8px;">${tx.location}</td>
                  <td style="padding: 8px; font-weight: 600;">${itemObj ? itemObj.name : tx.item}</td>
                  <td style="padding: 8px; text-align: right; font-weight: 700; color: ${isInfo ? 'var(--accent-blue)' : '#ef4444'};">
                    ${isInfo ? '+' : '-'}${tx.qty.toLocaleString()} 枚
                  </td>
                  <td style="padding: 8px; text-align: right;">¥${(tx.price || 0).toLocaleString()}</td>
                  <td style="padding: 8px; text-align: right; font-weight: 700;">¥${Math.round(amt).toLocaleString()}</td>
                  <td style="padding: 8px;">${tx.supplier || tx.purpose || '-'}</td>
                  <td style="padding: 8px; color: var(--text-muted);">${tx.note || '-'}</td>
                  <td style="padding: 8px; text-align: center;">
                    <button class="btn-delete-tx" data-id="${tx.id}" style="background: none; border: none; color: #ef4444; cursor: pointer;">✕</button>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;

  document.querySelectorAll('.btn-delete-tx').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = e.target.dataset.id;
      if (confirm("このトランザクションレコードを削除してもよろしいですか？")) {
        data.transactions = data.transactions.filter(t => t.id !== id);
        saveFlexconData(data);
        showToast("🗑️ レコードを削除しました");
        renderFlexconInventory();
      }
    });
  });

  document.getElementById('btnResetFlexconData').addEventListener('click', () => {
    if (confirm("初期サンプルデータにリセットしますか？入力されたデータは消去されます。")) {
      localStorage.removeItem('cascadia_flexcon_inventory_v1');
      renderFlexconInventory();
    }
  });
}

// 5. 月末棚卸し＆CSVエクスポート
function renderFlexconCheck(container, data) {
  const matrix = calculateStockMatrix(data.transactions);

  container.innerHTML = `
    <div class="tool-card" style="margin-bottom: 20px;">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 14px;">
        <h3 style="margin: 0;">📑 月末実在庫 棚卸し照合・差額調整</h3>
        <button class="btn btn-primary" id="btnExportFlexconCSV" style="background: linear-gradient(135deg, var(--accent-green), #107c41); color: #fff; padding: 8px 16px; font-size: 13px;">
          📥 全在庫・入出庫データをCSVエクスポート
        </button>
      </div>
      <p style="font-size: 12px; color: var(--text-muted); margin-top: 0; margin-bottom: 16px;">
        各拠点の月末棚卸カウント数を入力し、システム帳簿理論在庫との差額を照合します。
      </p>

      <div style="overflow-x: auto;">
        <table class="assistant-table" style="font-size: 12px; width: 100%; border-collapse: collapse;">
          <thead>
            <tr style="background: var(--bg-primary); text-align: left;">
              <th style="padding: 8px;">保管場所（拠点）</th>
              <th style="padding: 8px;">品名（型番）</th>
              <th style="padding: 8px; text-align: right;">システム理論在庫</th>
              <th style="padding: 8px; text-align: right;">評価単価</th>
              <th style="padding: 8px; text-align: right;">システム在庫金額</th>
            </tr>
          </thead>
          <tbody>
            ${FLEXCON_LOCATIONS.map(loc => {
              return FLEXCON_ITEMS.map(item => {
                const cell = matrix[loc][item.id];
                return `
                  <tr>
                    <td style="padding: 8px;">${loc}</td>
                    <td style="padding: 8px; font-weight: 600;">${item.name}</td>
                    <td style="padding: 8px; text-align: right; font-weight: 700;">${cell.qty.toLocaleString()} 枚</td>
                    <td style="padding: 8px; text-align: right;">¥${cell.lastPrice.toLocaleString()}</td>
                    <td style="padding: 8px; text-align: right; font-weight: 700; color: var(--accent-violet);">¥${Math.round(cell.totalValue).toLocaleString()}</td>
                  </tr>
                `;
              }).join('');
            }).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;

  document.getElementById('btnExportFlexconCSV').addEventListener('click', () => {
    let csv = "\uFEFF日付,区分,保管場所,品名ID,枚数,単価,金額,仕入先/用途,備考\n";
    data.transactions.forEach(tx => {
      csv += `"${tx.date}","${tx.type === 'inbound' ? '入庫' : '出庫'}","${tx.location}","${tx.item}",${tx.qty},${tx.price || 0},${tx.qty * (tx.price || 0)},"${tx.supplier || tx.purpose || ''}","${tx.note || ''}"\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `flexcon_inventory_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("📄 CSVファイルをダウンロードしました");
  });
}


// Trigger build


// --- LAT Equipment Inventory Management Interactive Tool ---
const LAT_MASTER_ITEMS = [{"cat": "部材", "orig_cat": "部材　金額", "name": "タグケース　第4ロット　穴有", "price": 27.5, "qty": 50, "note": "消耗品費除く"}, {"cat": "部材", "orig_cat": "部材　金額", "name": "タグケース　第4ロット　穴無", "price": 27.5, "qty": 13, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "タグケース　ピンク　穴有", "price": 38.0, "qty": 590, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "タグケース　ピンク　穴無", "price": 38.0, "qty": 590, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "タグケース　透明　穴有", "price": 500.0, "qty": 17, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "タグケース　透明　穴無", "price": 500.0, "qty": 21, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "タグケース　第5ロット　穴有", "price": 42.5, "qty": 3990, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "タグケース　第5ロット　穴無", "price": 42.5, "qty": 3990, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "防水パッキン", "price": 50.0, "qty": 1780, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "防水パッキン　TRピンクタグ用", "price": 70.0, "qty": 2000, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "防水パッキン　第5ロットタグ用", "price": 98.0, "qty": 3990, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "丸リンク", "price": 159.0, "qty": 1485, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "タッピングネジ(12mm)", "price": 3.3, "qty": 16000, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "タッピングネジ(12mm)", "price": 4.2, "qty": 2000, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "タッピングネジ(16mm)", "price": 3.7, "qty": 26000, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "タッピングネジ(16mm)", "price": 4.6, "qty": 10000, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "クッション材", "price": 5.0, "qty": 10000, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "ビーコンEB10-B", "price": 4050.0, "qty": 851, "note": "LAT(R5.3)"}, {"cat": "部材", "orig_cat": "部材　金額", "name": "ビーコンEB10-B01", "price": 4800.0, "qty": 809, "note": "LAT(R5.4)"}, {"cat": "部材", "orig_cat": "部材　金額", "name": "ビーコンEB10-B01", "price": 5800.0, "qty": 4020, "note": "LAT(R5.5~R5.8)"}, {"cat": "部材", "orig_cat": "部材　金額", "name": "ビーコンEB10-B", "price": 4406.55737704918, "qty": 3050, "note": "CTI直接購入分(R7.2)"}, {"cat": "部材", "orig_cat": "部材　金額", "name": "ビーコンEB10-B", "price": 4800.0, "qty": 1000, "note": "CTI追加LAT経由(R5.9)"}, {"cat": "部材", "orig_cat": "部材　金額", "name": "ビーコンEB10-B", "price": 4800.0, "qty": 3000, "note": "CTI追加LAT経由(R5.10)"}, {"cat": "部材", "orig_cat": "部材　金額", "name": "ビーコンEB10-B", "price": 5091.0, "qty": 4794, "note": "CTI追加LAT経由(R4.12~R5.4)"}, {"cat": "部材", "orig_cat": "部材　金額", "name": "ビーコンEB10-B", "price": 4800.0, "qty": 3000, "note": "CTI直接購入分(R6.8)"}, {"cat": "部材", "orig_cat": "部材　金額", "name": "ネオジム磁石", "price": 523.5, "qty": 12, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "フリーポイント金具", "price": 150.0, "qty": 10, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "荷締めベルト", "price": 420.0, "qty": 8, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "グロメット", "price": 99.0, "qty": 36, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "タッピングトラスネジ", "price": 6.0, "qty": 92, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "ビス(抑え上手)", "price": 4.0, "qty": 600, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "プラボックス：受信機用(旧バージョン)", "price": 2890.0, "qty": 5, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "プラボックス：受信機用(新バージョン)", "price": 2890.0, "qty": 3, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "ケーブルクランプMネジ", "price": 95.0, "qty": 41, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "サージタップ(雷ガード)", "price": 600.0, "qty": 12, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "コネクタボディ(メス)", "price": 200.0, "qty": 11, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "ビニル平型コード(3m/5m)", "price": 800.0, "qty": 9, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "丸型端子", "price": 10.0, "qty": 185, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "配線ダクト", "price": 999.0, "qty": 2, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "配線ダクト（切り出し）", "price": 76.84615384615384, "qty": 2, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "L字型電源コード", "price": 499.0, "qty": 12, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "OBSVX2(菱洋)", "price": 73500.0, "qty": 37, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "OBSEX1G(菱洋)", "price": 64000.0, "qty": 1, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "プラボックス：アンテナ用", "price": 4790.0, "qty": 0, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "小ねじ(3×15)", "price": 3.5, "qty": 92, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "X1000(マクニカ)", "price": 36000.0, "qty": 19, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "X2000(マクニカ)", "price": 84000.0, "qty": 2, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "PoEインジェクタ(2口)無印", "price": 2300.0, "qty": 4, "note": "1450"}, {"cat": "部材", "orig_cat": "部材　金額", "name": "PoEインジェクタ(2口)サンワ", "price": 7600.0, "qty": 8, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "PoEインジェクタ(2口)サンワ(大)", "price": 7600.0, "qty": 2, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "LANケーブル(30cm)", "price": 1000.0, "qty": 16, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "90ｃｍ首輪(新品)", "price": 452.0, "qty": 2, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "90ｃｍ首輪(中古）", "price": 452.0, "qty": 527, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "90ｃｍ首輪(130㎝をカット)", "price": 514.0, "qty": 0, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "130cm首輪(新品)", "price": 514.0, "qty": 3490, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "130cm首輪(中古)", "price": 648.0, "qty": 0, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "リングキャッチ（新品）※2025.11 購入", "price": 333.2, "qty": 33, "note": "333.2"}, {"cat": "部材", "orig_cat": "部材　金額", "name": "リングキャッチ（中古）", "price": 260.0, "qty": 255, "note": ""}, {"cat": "部材", "orig_cat": "部材　金額", "name": "PPベルト専用金具（新品）※2025.11 購入", "price": 209.0, "qty": 133, "note": "209"}, {"cat": "部材", "orig_cat": "部材　金額", "name": "PPベルト専用金具（中古）", "price": 170.0, "qty": 130, "note": ""}, {"cat": "トライアル", "orig_cat": "トライアル　金額", "name": "第1ロットタグ", "price": 3260.0, "qty": 0, "note": ""}, {"cat": "トライアル", "orig_cat": "トライアル　金額", "name": "第2ロットタグ", "price": 5150.0, "qty": 55, "note": ""}, {"cat": "トライアル", "orig_cat": "トライアル　金額", "name": "第3ロットタグ", "price": 3260.0, "qty": 50, "note": ""}, {"cat": "トライアル", "orig_cat": "トライアル　金額", "name": "第4ロットタグ", "price": 4856.0, "qty": 84, "note": ""}, {"cat": "トライアル", "orig_cat": "トライアル　金額", "name": "トライアルタグ", "price": 4903.0, "qty": 521, "note": ""}, {"cat": "トライアル", "orig_cat": "トライアル　金額", "name": "受信機", "price": 83288.0, "qty": 19, "note": ""}, {"cat": "トライアル", "orig_cat": "トライアル　金額", "name": "高感度アンテナ", "price": 46727.0, "qty": 0, "note": ""}, {"cat": "トライアル", "orig_cat": "トライアル　金額", "name": "首輪（90㎝)", "price": 882.0, "qty": 698, "note": ""}, {"cat": "トライアル", "orig_cat": "トライアル　金額", "name": "首輪（130㎝）", "price": 1051.0, "qty": 0, "note": ""}, {"cat": "新品製品", "orig_cat": "新品製品　金額", "name": "第1ロットタグ", "price": 3260.0, "qty": 0, "note": ""}, {"cat": "新品製品", "orig_cat": "新品製品　金額", "name": "第2ロットタグ", "price": 5150.0, "qty": 3, "note": ""}, {"cat": "新品製品", "orig_cat": "新品製品　金額", "name": "第3ロットタグ", "price": 3260.0, "qty": 35, "note": ""}, {"cat": "新品製品", "orig_cat": "新品製品　金額", "name": "第4ロットタグ", "price": 4856.0, "qty": 308, "note": ""}, {"cat": "新品製品", "orig_cat": "新品製品　金額", "name": "第5ロットタグA", "price": 4233.0, "qty": 660, "note": ""}, {"cat": "新品製品", "orig_cat": "新品製品　金額", "name": "トライアルタグ", "price": 4903.0, "qty": 823, "note": ""}, {"cat": "新品製品", "orig_cat": "新品製品　金額", "name": "受信機", "price": 83288.0, "qty": 0, "note": ""}, {"cat": "新品製品", "orig_cat": "新品製品　金額", "name": "アンテナ", "price": 46727.0, "qty": 2, "note": ""}, {"cat": "新品製品", "orig_cat": "新品製品　金額", "name": "首輪（90㎝）", "price": 882.0, "qty": 0, "note": ""}, {"cat": "新品製品", "orig_cat": "新品製品　金額", "name": "首輪（90㎝）※130cmをカット", "price": 1051.0, "qty": 3, "note": ""}, {"cat": "新品製品", "orig_cat": "新品製品　金額", "name": "首輪（130㎝）", "price": 1051.0, "qty": 0, "note": ""}, {"cat": "中古製品", "orig_cat": "中古製品　金額", "name": "第1ロットタグ　中古", "price": 3260.0, "qty": 28, "note": ""}, {"cat": "中古製品", "orig_cat": "中古製品　金額", "name": "第2ロットタグ　中古", "price": 5150.0, "qty": 7, "note": ""}, {"cat": "中古製品", "orig_cat": "中古製品　金額", "name": "第3ロットタグ　中古", "price": 3260.0, "qty": 192, "note": ""}, {"cat": "中古製品", "orig_cat": "中古製品　金額", "name": "第4ロットタグ　中古", "price": 4856.0, "qty": 180, "note": ""}, {"cat": "中古製品", "orig_cat": "中古製品　金額", "name": "第5ロットタグ　中古", "price": 4233.0, "qty": 0, "note": ""}, {"cat": "中古製品", "orig_cat": "中古製品　金額", "name": "受信機　中古", "price": 83288.0, "qty": 13, "note": ""}, {"cat": "中古製品", "orig_cat": "中古製品　金額", "name": "高感度アンテナ　中古", "price": 46727.0, "qty": 7, "note": ""}, {"cat": "中古製品", "orig_cat": "中古製品　金額", "name": "首輪（90㎝）", "price": 882.0, "qty": 13, "note": ""}, {"cat": "中古製品", "orig_cat": "中古製品　金額", "name": "首輪（90㎝）※130cmをカット", "price": 1051.0, "qty": 19, "note": ""}, {"cat": "中古製品", "orig_cat": "中古製品　金額", "name": "首輪（130㎝）", "price": 1051.0, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "故障除却タグ製品　金額　※振替伝票", "name": "第1ロット", "price": 3260.0, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "故障除却タグ製品　金額　※振替伝票", "name": "第2ロット", "price": 5150.0, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "故障除却タグ製品　金額　※振替伝票", "name": "第3ロット", "price": 3260.0, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "故障除却タグ製品　金額　※振替伝票", "name": "第4ロット", "price": 4856.0, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "故障除却タグ製品　金額　※振替伝票", "name": "第5ロット", "price": 4233.0, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "故障除却タグ製品　金額　※振替伝票", "name": "トライアルタグ", "price": 4903.0, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "トライアルタグ組み換え（除却）", "name": "タグケース　第4ロット　穴有", "price": 27.5, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "トライアルタグ組み換え（除却）", "name": "タグケース　第4ロット　穴無", "price": 27.5, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "トライアルタグ組み換え（除却）", "name": "防水パッキン", "price": 50.0, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "トライアルタグ組み換え（除却）", "name": "タッピングネジ(12mm)", "price": 3.3, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "トライアルタグ組み換え（除却）", "name": "タッピングネジ(16mm)", "price": 3.7, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "第5ロットタグ組み換え（除却）", "name": "タグケース　第5ロット　穴有", "price": 27.5, "qty": 100, "note": ""}, {"cat": "雑損・除却", "orig_cat": "第5ロットタグ組み換え（除却）", "name": "タグケース　第5ロット　穴無", "price": 27.5, "qty": 100, "note": ""}, {"cat": "雑損・除却", "orig_cat": "第5ロットタグ組み換え（除却）", "name": "防水パッキン", "price": 50.0, "qty": 100, "note": ""}, {"cat": "雑損・除却", "orig_cat": "第5ロットタグ組み換え（除却）", "name": "タッピングネジ(12mm)", "price": 3.3, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "第5ロットタグ組み換え（除却）", "name": "タッピングネジ(16mm)", "price": 3.7, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "顧客への故障補償提供分（除却）", "name": "第1ロット", "price": 3260.0, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "顧客への故障補償提供分（除却）", "name": "第2ロット", "price": 5150.0, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "顧客への故障補償提供分（除却）", "name": "第3ロット", "price": 3260.0, "qty": 0, "note": ""}, {"cat": "雑損・除却", "orig_cat": "顧客への故障補償提供分（除却）", "name": "第4ロット", "price": 4856.0, "qty": 19, "note": ""}, {"cat": "雑損・除却", "orig_cat": "顧客への故障補償提供分（除却）", "name": "第5ロット", "price": 4233.0, "qty": 0, "note": ""}];

function renderLatInventoryTool() {
  const content = contentArea;
  
  // Load saved state or default
  const savedData = JSON.parse(localStorage.getItem('cascadia_lat_inventory') || 'null');
  const items = LAT_MASTER_ITEMS.map((item, idx) => {
    const savedQty = savedData && savedData[idx] !== undefined ? savedData[idx] : item.qty;
    return { ...item, qty: savedQty };
  });

  content.innerHTML = `
    <div class="tool-container" style="max-width: 1200px; margin: 0 auto; padding: 20px;">
      <div class="section-hero" style="background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); border-radius: 16px; padding: 28px; color: #ffffff; margin-bottom: 24px; box-shadow: 0 10px 25px -5px rgba(15,23,42,0.3);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px;">
          <div>
            <span class="hero-emoji">⚡</span>
            <h1 style="margin: 8px 0; font-size: 1.8em;">LAT機材・在庫金額 集計＆推移データ作成ツール</h1>
            <p class="hero-sub" style="margin: 0; color: #94a3b8;">棚卸数の入力、リアルタイム資産評価、推移表（☆CTI10期）転記用データのワンクリック生成</p>
          </div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <button id="btnLatCopySummary" class="btn" style="background: #2563eb; color: #fff; border: none; padding: 10px 18px; border-radius: 8px; font-weight: bold; cursor: pointer; transition: all 0.2s;">📋 転記データをコピー</button>
            <button id="btnLatSave" class="btn" style="background: #059669; color: #fff; border: none; padding: 10px 18px; border-radius: 8px; font-weight: bold; cursor: pointer; transition: all 0.2s;">💾 入力値を保存</button>
            <button id="btnLatExportCsv" class="btn" style="background: #475569; color: #fff; border: none; padding: 10px 18px; border-radius: 8px; cursor: pointer;">📥 CSV出力</button>
            <button id="btnLatReset" class="btn" style="background: #ef4444; color: #fff; border: none; padding: 10px 14px; border-radius: 8px; cursor: pointer;">🔄 リセット</button>
          </div>
        </div>
      </div>

      <!-- KPI Summary Header -->
      <div class="kpi-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin-bottom: 24px;">
        <div class="kpi-card" style="background: #ffffff; padding: 16px; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
          <div style="font-size: 0.85em; color: #64748b; font-weight: bold;">📦 部材 在庫小計</div>
          <div id="kpiCatParts" style="font-size: 1.3em; font-weight: bold; color: #0f172a; margin-top: 4px;">¥0</div>
        </div>
        <div class="kpi-card" style="background: #ffffff; padding: 16px; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
          <div style="font-size: 0.85em; color: #64748b; font-weight: bold;">🧪 トライアル 小計</div>
          <div id="kpiCatTrial" style="font-size: 1.3em; font-weight: bold; color: #0f172a; margin-top: 4px;">¥0</div>
        </div>
        <div class="kpi-card" style="background: #ffffff; padding: 16px; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
          <div style="font-size: 0.85em; color: #64748b; font-weight: bold;">✨ 新品製品 小計</div>
          <div id="kpiCatNew" style="font-size: 1.3em; font-weight: bold; color: #0f172a; margin-top: 4px;">¥0</div>
        </div>
        <div class="kpi-card" style="background: #ffffff; padding: 16px; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
          <div style="font-size: 0.85em; color: #64748b; font-weight: bold;">♻️ 中古製品 小計 (正規評価)</div>
          <div id="kpiCatUsed" style="font-size: 1.3em; font-weight: bold; color: #2563eb; margin-top: 4px;">¥0</div>
        </div>
        <div class="kpi-card" style="background: #ffffff; padding: 16px; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">
          <div style="font-size: 0.85em; color: #64748b; font-weight: bold;">⚠️ 雑損・除却 小計</div>
          <div id="kpiCatLoss" style="font-size: 1.3em; font-weight: bold; color: #dc2626; margin-top: 4px;">¥0</div>
        </div>
        <div class="kpi-card" style="background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); padding: 16px; border-radius: 12px; color: #ffffff; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
          <div style="font-size: 0.85em; color: #cbd5e1; font-weight: bold;">💰 在庫金額 総合計</div>
          <div id="kpiTotalAmount" style="font-size: 1.4em; font-weight: bold; color: #38bdf8; margin-top: 4px;">¥0</div>
        </div>
      </div>

      <!-- Filter & Search Controls -->
      <div style="background: #ffffff; padding: 16px; border-radius: 12px; border: 1px solid #e2e8f0; margin-bottom: 20px; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px;">
        <div style="display: flex; gap: 8px; flex-wrap: wrap;" id="catFilterGroup">
          <button class="filter-btn active" data-cat="all" style="padding: 6px 14px; border-radius: 20px; border: 1px solid #cbd5e1; background: #1e293b; color: #fff; cursor: pointer;">すべて (111)</button>
          <button class="filter-btn" data-cat="部材" style="padding: 6px 14px; border-radius: 20px; border: 1px solid #cbd5e1; background: #f8fafc; color: #334155; cursor: pointer;">部材</button>
          <button class="filter-btn" data-cat="トライアル" style="padding: 6px 14px; border-radius: 20px; border: 1px solid #cbd5e1; background: #f8fafc; color: #334155; cursor: pointer;">トライアル</button>
          <button class="filter-btn" data-cat="新品製品" style="padding: 6px 14px; border-radius: 20px; border: 1px solid #cbd5e1; background: #f8fafc; color: #334155; cursor: pointer;">新品製品</button>
          <button class="filter-btn" data-cat="中古製品" style="padding: 6px 14px; border-radius: 20px; border: 1px solid #cbd5e1; background: #f8fafc; color: #334155; cursor: pointer;">中古製品</button>
          <button class="filter-btn" data-cat="雑損・除却" style="padding: 6px 14px; border-radius: 20px; border: 1px solid #cbd5e1; background: #f8fafc; color: #334155; cursor: pointer;">雑損・除却</button>
        </div>
        <input type="text" id="latSearchInput" placeholder="🔍 品名・キーワード検索..." style="padding: 8px 14px; border-radius: 8px; border: 1px solid #cbd5e1; width: 220px; font-size: 0.9em;">
      </div>

      <!-- Inventory Table -->
      <div style="background: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; overflow-x: auto; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
        <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9em;">
          <thead>
            <tr style="background: #f8fafc; border-bottom: 2px solid #e2e8f0; color: #475569;">
              <th style="padding: 12px 16px; width: 120px;">分類</th>
              <th style="padding: 12px 16px;">品目名</th>
              <th style="padding: 12px 16px; width: 110px; text-align: right;">単価（円）</th>
              <th style="padding: 12px 16px; width: 130px; text-align: center;">当月棚卸数</th>
              <th style="padding: 12px 16px; width: 140px; text-align: right;">小計金額</th>
              <th style="padding: 12px 16px; width: 150px;">備考</th>
            </tr>
          </thead>
          <tbody id="latTableBody">
            <!-- Dynamic rows -->
          </tbody>
        </table>
      </div>
    </div>
  `;

  function updateTable() {
    const filterCat = document.querySelector('#catFilterGroup .filter-btn.active')?.dataset.cat || 'all';
    const keyword = (document.getElementById('latSearchInput')?.value || '').trim().toLowerCase();

    const tbody = document.getElementById('latTableBody');
    if (!tbody) return;

    let html = '';
    let sumParts = 0, sumTrial = 0, sumNew = 0, sumUsed = 0, sumLoss = 0;

    items.forEach((item, idx) => {
      const subtotal = item.price * item.qty;

      if (item.cat === '部材') sumParts += subtotal;
      else if (item.cat === 'トライアル') sumTrial += subtotal;
      else if (item.cat === '新品製品') sumNew += subtotal;
      else if (item.cat === '中古製品') sumUsed += subtotal;
      else if (item.cat === '雑損・除却') sumLoss += subtotal;

      if (filterCat !== 'all' && item.cat !== filterCat) return;
      if (keyword && !item.name.toLowerCase().includes(keyword) && !item.cat.toLowerCase().includes(keyword)) return;

      const catBadgeColor = item.cat === '中古製品' ? '#dbeafe' : (item.cat === '雑損・除却' ? '#fee2e2' : '#f1f5f9');
      const catTextColor = item.cat === '中古製品' ? '#1e40af' : (item.cat === '雑損・除却' ? '#991b1b' : '#334155');

      html += `
        <tr style="border-bottom: 1px solid #f1f5f9;">
          <td style="padding: 10px 16px;">
            <span style="background: ${catBadgeColor}; color: ${catTextColor}; padding: 3px 8px; border-radius: 6px; font-weight: bold; font-size: 0.85em;">${item.cat}</span>
          </td>
          <td style="padding: 10px 16px; font-weight: 500; color: #0f172a;">${item.name}</td>
          <td style="padding: 10px 16px; text-align: right; color: #475569;">¥${item.price.toLocaleString()}</td>
          <td style="padding: 10px 16px; text-align: center;">
            <input type="number" class="lat-qty-input" data-idx="${idx}" value="${item.qty}" min="0" style="width: 90px; padding: 6px; border: 1px solid #cbd5e1; border-radius: 6px; text-align: right; font-weight: bold; background: #fff;">
          </td>
          <td style="padding: 10px 16px; text-align: right; font-weight: bold; color: #0f172a;">¥${subtotal.toLocaleString()}</td>
          <td style="padding: 10px 16px; color: #64748b; font-size: 0.85em;">${item.note || '-'}</td>
        </tr>
      `;
    });

    tbody.innerHTML = html;

    // Update KPI Display
    document.getElementById('kpiCatParts').textContent = '¥' + Math.round(sumParts).toLocaleString();
    document.getElementById('kpiCatTrial').textContent = '¥' + Math.round(sumTrial).toLocaleString();
    document.getElementById('kpiCatNew').textContent = '¥' + Math.round(sumNew).toLocaleString();
    document.getElementById('kpiCatUsed').textContent = '¥' + Math.round(sumUsed).toLocaleString();
    document.getElementById('kpiCatLoss').textContent = '¥' + Math.round(sumLoss).toLocaleString();
    const grandTotal = sumParts + sumTrial + sumNew + sumUsed;
    document.getElementById('kpiTotalAmount').textContent = '¥' + Math.round(grandTotal).toLocaleString();

    // Re-bind input events
    tbody.querySelectorAll('.lat-qty-input').forEach(input => {
      input.addEventListener('input', (e) => {
        const idx = parseInt(e.target.dataset.idx, 10);
        items[idx].qty = Math.max(0, parseInt(e.target.value, 10) || 0);
        updateTable();
      });
    });
  }

  updateTable();

  // Filter Buttons Event
  document.querySelectorAll('#catFilterGroup .filter-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('#catFilterGroup .filter-btn').forEach(b => {
        b.classList.remove('active');
        b.style.background = '#f8fafc';
        b.style.color = '#334155';
      });
      e.target.classList.add('active');
      e.target.style.background = '#1e293b';
      e.target.style.color = '#ffffff';
      updateTable();
    });
  });

  // Search Event
  document.getElementById('latSearchInput').addEventListener('input', updateTable);

  // Save Event
  document.getElementById('btnLatSave').addEventListener('click', () => {
    const qtyArray = items.map(i => i.qty);
    localStorage.setItem('cascadia_lat_inventory', JSON.stringify(qtyArray));
    alert('✅ 棚卸入力値をブラウザに保存しました！');
  });

  // Copy Summary Event
  document.getElementById('btnLatCopySummary').addEventListener('click', () => {
    let sumParts = 0, sumTrial = 0, sumNew = 0, sumUsed = 0, sumLoss = 0;
    items.forEach(i => {
      const sub = i.price * i.qty;
      if (i.cat === '部材') sumParts += sub;
      else if (i.cat === 'トライアル') sumTrial += sub;
      else if (i.cat === '新品製品') sumNew += sub;
      else if (i.cat === '中古製品') sumUsed += sub;
      else if (i.cat === '雑損・除却') sumLoss += sub;
    });
    const total = sumParts + sumTrial + sumNew + sumUsed;

    const tsvText = `区分	金額（円）
部材在庫金額	${Math.round(sumParts)}
トライアル在庫金額	${Math.round(sumTrial)}
新品製品在庫金額	${Math.round(sumNew)}
中古在庫金額	${Math.round(sumUsed)}
故障・雑損金額	${Math.round(sumLoss)}
在庫金額合計	${Math.round(total)}`;
    
    navigator.clipboard.writeText(tsvText).then(() => {
      alert('📋 【☆CTI10期在庫推移】転記用データをクリップボードにコピーしました！\nExcelの該当セルへそのまま貼り付け（Ctrl+V）できます。');
    });
  });

  // CSV Export Event
  document.getElementById('btnLatExportCsv').addEventListener('click', () => {
    let csv = '\uFEFF分類,品目名,単価,棚卸数,小計金額,備考\n';
    items.forEach(i => {
      csv += `"${i.cat}","${i.name}",${i.price},${i.qty},${Math.round(i.price * i.qty)},"${i.note || ''}"\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `LAT機材在庫金額表_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  });

  // Reset Event
  document.getElementById('btnLatReset').addEventListener('click', () => {
    if (confirm('すべての入力値を初期データにリセットしますか？')) {
      localStorage.removeItem('cascadia_lat_inventory');
      renderLatInventoryTool();
    }
  });
}
