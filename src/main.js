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
        <a class="nav-item" data-page="ch4-food"><span class="nav-dot"></span>├ 飼料（その他）</a>
        <a class="nav-item" data-page="ch4-svc"><span class="nav-dot"></span>├ サービス・コンサル</a>
        <a class="nav-item" data-page="ch4-fat"><span class="nav-dot"></span>└ 脂肪酸の機能使い分け</a>
        <a class="nav-item" data-page="appendix"><span class="nav-dot"></span>業界用語・辞書</a>
        <a class="nav-item" data-page="app-pack"><span class="nav-dot"></span>荷姿・物流・単位</a>
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
    'ch4-food': '飼料（その他）',
    'ch4-svc': 'サービス・コンサル',
    'ch4-fat': '脂肪酸の機能使い分け',
    'appendix': '業界用語・辞書',
    'app-pack': '荷姿・物流・単位'
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
  let total = SALES_QUIZ.length;
  let completed = 0;
  
  SALES_QUIZ.forEach(ch => {
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
  const verifyStats = getOverallVerificationStats();
  const checklistStats = getOverallChecklistStats();
  const quizStats = getQuizProgressStats();

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

    <div class="stats-row">
      <div class="stat-card" style="border-color: rgba(96, 165, 250, 0.25);">
        <div class="stat-value" style="color: var(--accent-blue);">${verifyStats.resolved} / ${verifyStats.total} <span style="font-size:12px; font-weight:400; color:var(--text-muted);">項目</span></div>
        <div class="stat-label">有識者確認済み (実務適用率 ${verifyStats.pct}%)</div>
      </div>
      <div class="stat-card" style="border-color: rgba(52, 211, 153, 0.25);">
        <div class="stat-value" style="color: var(--accent-green);">${checklistStats.checked} / ${checklistStats.total} <span style="font-size:12px; font-weight:400; color:var(--text-muted);">項目</span></div>
        <div class="stat-label">業務ダブルチェック実行中</div>
      </div>
      <div class="stat-card" style="border-color: rgba(167, 139, 250, 0.25);">
        <div class="stat-value" style="color: var(--accent-violet);">${quizStats.completed} / ${quizStats.total} <span style="font-size:12px; font-weight:400; color:var(--text-muted);">章</span></div>
        <div class="stat-label">理解度クイズ全問クリア</div>
      </div>
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

    <h3 class="portal-section-title">👑 営業部マニュアル — ダイレクトアクセス</h3>
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

    <h3 class="portal-section-title">⚙️ 業務部マニュアル — プロセスダイレクトアクセス</h3>
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
  SALES_QUIZ.forEach(ch => {
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
      <h1>🐄 カスケディア営業力チェック</h1>
      <p>マニュアルの理解度をゲーム感覚でテストして、エース営業を目指そう！</p>
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
      <h2 style="font-size:16px; font-weight:700; margin-bottom:4px;">📚 チャプターを選択</h2>
      <p style="font-size:12px; color:var(--text-muted); margin-bottom: 12px;">各章をクリアしてXPを獲得し、ランクを上げよう！</p>
      
      <div class="ch-grid" id="chGrid"></div>
      
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
  const g = document.getElementById('chGrid');
  if(!g) return;
  g.innerHTML = '';
  
  SALES_QUIZ.forEach((ch) => {
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
    g.appendChild(d);
  });
}

function openQuizModal(chId) {
  pendingChId = chId;
  const ch = SALES_QUIZ.find(c => c.id === chId);
  if (!ch) return;
  
  document.getElementById('modalQuizTitle').textContent = `${ch.emoji} ${ch.title}`;
  document.getElementById('modalQuizPurpose').textContent = ch.purpose;
  document.getElementById('modalQuizVision').textContent = ch.vision;
  
  // Configure preview manual button dynamically
  const previewBtn = document.getElementById('btnPreviewManual');
  previewBtn.onclick = () => {
    closeModal();
    navigateTo(chId); // Direct link to corresponding sales manual chapter
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
  const ch = SALES_QUIZ.find(c => c.id === chId);
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
  SALES_QUIZ.forEach(ch => {
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
    SALES_QUIZ.forEach(ch => {
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
  const chInfo = SALES_QUIZ.find(c => c.id === curQuiz.chId);
  
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

          <!-- 第二胃 (網胃)：y座標を調整して第一胃・第三胃と美しく調和 -->
          <g transform="translate(510, 50)" filter="url(#shadow-stomach)" class="stomach-node">
            <rect width="210" height="75" rx="12" fill="url(#grad-reticulum)" stroke="#1d4ed8" stroke-width="2" />
            <text x="15" y="28" fill="#fff" font-size="13.5" font-weight="800">🔵 第二胃 (網胃)</text>
            <text x="15" y="48" fill="#eff6ff" font-size="10.5" font-weight="700">異物除去フィルター</text>
            <text x="15" y="64" fill="#dbeafe" font-size="10" font-weight="700">・蜂の巣状の壁で金属等の異物を捕獲</text>
          </g>

          <!-- 第三胃 (葉胃)：高コントラストなテキスト色を採用 -->
          <g transform="translate(510, 165)" filter="url(#shadow-stomach)" class="stomach-node">
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

          <!-- 第一胃 → 第二胃 (登り傾斜約26.5度を保ったまま自然にタッチし、三角の向きと線の流れが綺麗に一体化) -->
          <path d="M 475,120 C 485,120 493,92.5 503,87.5" fill="none" stroke="#2563eb" stroke-width="2.5" marker-end="url(#arrow-blue)" />
          
          <!-- 第二胃 → 第三胃 (中心軸 615 上を綺麗に垂直下落。第三胃天面 165 から 6px 手前の 159 で綺麗に接する) -->
          <path d="M 615,125 L 615,159" fill="none" stroke="#d97706" stroke-width="2.5" marker-end="url(#arrow-orange)" />
          
          <!-- 第三胃 → 第四胃 (カクつきを排除し、滑らかな孤を描きながら斜め約120度方向のまま第四胃の右上 483,231 にアプローチ) -->
          <path d="M 510,202.5 C 495,202.5 488,222.5 483,231" fill="none" stroke="#dc2626" stroke-width="2.5" marker-end="url(#arrow-red)" />
          
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

            <!-- 右側縦軸数値 (BCS) -->
            <text x="755" y="115" fill="var(--text-muted, #64748b)" font-size="11" text-anchor="start">高 (BCS 3.5)</text>
            <text x="755" y="235" fill="var(--text-muted, #64748b)" font-size="11" text-anchor="start">中 (BCS 3.0)</text>
            <text x="755" y="355" fill="var(--text-muted, #64748b)" font-size="11" text-anchor="start">低 (BCS 2.5)</text>

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
          <text x="382" y="108" fill="#dc2626" font-size="10.5" font-weight="700">⚠️ 多すぎるとアンモニアが過剰に</text>

          <!-- 2. DIP -->
          <g transform="translate(170, 130)" filter="url(#shadow-soft)">
            <rect width="160" height="60" rx="8" fill="url(#grad-dip)" stroke="#1d4ed8" stroke-width="1.5" />
            <text x="12" y="24" fill="#fff" font-size="12" font-weight="800">分解性タンパク (DIP)</text>
            <text x="12" y="44" fill="#bfdbfe" font-size="10.5">・微生物がゆっくり分解・利用</text>
          </g>
          <path d="M 330,160 L 380,160 C 410,160 420,135 440,135 L 530,135" fill="none" stroke="#2563eb" stroke-width="2.5" marker-end="url(#arrow-blue-p)" />
          <text x="355" y="148" fill="#2563eb" font-size="11" font-weight="800">微生物のエサに 🦠</text>

          <!-- 3. UIP -->
          <g transform="translate(170, 200)" filter="url(#shadow-soft)">
            <rect width="160" height="60" rx="8" fill="url(#grad-uip)" stroke="#047857" stroke-width="1.5" />
            <text x="12" y="24" fill="#fff" font-size="12" font-weight="800">非分解性タンパク (UIP)</text>
            <text x="12" y="44" fill="#ecfdf5" font-size="10.5" font-weight="700">・ルーメンを完全にスルー！</text>
          </g>
          <path d="M 330,230 L 530,230" fill="none" stroke="#059669" stroke-width="4" marker-end="url(#arrow-green-p)" />
          <text x="360" y="252" fill="#047857" font-size="11.5" font-weight="900">✨ 最も重要：バイパスプロテイン</text>

          <!-- 4. BP -->
          <g transform="translate(170, 270)" filter="url(#shadow-soft)">
            <rect width="160" height="50" rx="8" fill="url(#grad-bp)" stroke="#52525b" stroke-width="1.5" />
            <text x="12" y="22" fill="#fff" font-size="12" font-weight="800">結合タンパク (BP)</text>
            <text x="12" y="38" fill="#e4e4e7" font-size="10">・繊維と結合して消化不可</text>
          </g>
          <path d="M 330,295 L 430,295 C 460,295 470,305 490,305 L 530,305" fill="none" stroke="#71717a" stroke-width="2" marker-end="url(#arrow-gray-p)" />
          <text x="440" y="316" fill="#71717a" font-size="10">そのまま糞として排出 💩</text>

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
      ` + proteinFractionSvg;
      
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
