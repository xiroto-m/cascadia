
// トースト通知UIコンポーネント
function showToast(message, duration = 3000) {
  let container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.style.cssText = 'position: fixed; bottom: 24px; right: 24px; z-index: 99999; display: flex; flex-direction: column; gap: 8px; pointer-events: none;';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.style.cssText = 'background: linear-gradient(135deg, #1e293b, #0f172a); color: #ffffff; padding: 12px 20px; border-radius: 10px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4); font-size: 13.5px; font-weight: 600; border: 1px solid rgba(255, 255, 255, 0.15); transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1); transform: translateY(20px); opacity: 0; pointer-events: auto;';
  toast.textContent = message;

  container.appendChild(toast);

  requestAnimationFrame(() => {
    toast.style.transform = 'translateY(0)';
    toast.style.opacity = '1';
  });

  setTimeout(() => {
    toast.style.transform = 'translateY(10px)';
    toast.style.opacity = '0';
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, duration);
}

const FLEXCON_LOCATION_DETAILS = {
  "上組 福岡支店": {
    company: "株式会社 上組 福岡支店",
    recipient: "",
    contacts: ["業務ご担当者様"],
    postalCode: "〒810-8512",
    address: "福岡県福岡市中央区那の津3丁目2番10号",
    tel: "092-752-5586",
    presets: [
      {
        name: "那の津 本社・倉庫（標準）",
        company: "株式会社 上組 福岡支店",
        recipient: "",
        postalCode: "〒810-8512",
        address: "福岡県福岡市中央区那の津3丁目2番10号",
        tel: "092-752-5586"
      },
      {
        name: "箱崎ふ頭物流センター",
        company: "株式会社 上組 福岡支店 箱崎物流センター",
        recipient: "ご担当者様",
        postalCode: "〒812-0051",
        address: "福岡県福岡市東区箱崎ふ頭",
        tel: "092-641-1111"
      },
      {
        name: "須崎埠頭営業所",
        company: "株式会社 上組 福岡支店 須崎営業所",
        recipient: "ご担当者様",
        postalCode: "〒812-0031",
        address: "福岡県福岡市博多区沖浜町",
        tel: "092-281-2222"
      }
    ]
  },
  "八代サイロ（上組福岡支店八代出張所）": {
    company: "上組 福岡支店 八代出張所（八代サイロ）",
    recipient: "業務担当様",
    contacts: ["業務担当様", "出張所長様"],
    postalCode: "〒866-0034",
    address: "熊本県八代市新港町1-1",
    tel: "0965-37-1234",
    presets: [
      {
        name: "八代出張所（八代サイロ）",
        company: "上組 福岡支店 八代出張所（八代サイロ）",
        recipient: "業務担当様",
        postalCode: "〒866-0034",
        address: "熊本県八代市新港町1-1",
        tel: "0965-37-1234"
      }
    ]
  },
  "熊本南関工場": {
    company: "カスケディア 熊本南関工場",
    recipient: "工場長様",
    contacts: ["工場長様", "受入担当様"],
    postalCode: "〒861-0814",
    address: "熊本県玉名郡南関町大字小原",
    tel: "0968-53-8800",
    presets: [
      {
        name: "熊本南関工場",
        company: "カスケディア 熊本南関工場",
        recipient: "工場長様",
        postalCode: "〒861-0814",
        address: "熊本県玉名郡南関町大字小原",
        tel: "0968-53-8800"
      }
    ]
  },
  "志布志倉庫": {
    company: "カスケディア 志布志保管倉庫",
    recipient: "業務担当様",
    contacts: ["業務担当様", "現場担当様"],
    postalCode: "〒899-7103",
    address: "鹿児島県志布志市志布志町志布志",
    tel: "099-472-1111",
    presets: [
      {
        name: "志布志保管倉庫",
        company: "カスケディア 志布志保管倉庫",
        recipient: "業務担当様",
        postalCode: "〒899-7103",
        address: "鹿児島県志布志市志布志町志布志",
        tel: "099-472-1111"
      }
    ]
  },
  "門司倉庫": {
    company: "カスケディア 門司港湾倉庫",
    recipient: "業務担当様",
    contacts: ["業務担当様", "港湾担当様"],
    postalCode: "〒801-0853",
    address: "福岡県北九州市門司区東港町",
    tel: "093-331-2222",
    presets: [
      {
        name: "門司港湾倉庫",
        company: "カスケディア 門司港湾倉庫",
        recipient: "業務担当様",
        postalCode: "〒801-0853",
        address: "福岡県北九州市門司区東港町",
        tel: "093-331-2222"
      }
    ]
  },
  "本社倉庫": {
    company: "CASCADIA TRADING, INC. 本社",
    recipient: "資材担当様",
    contacts: ["資材担当様", "業務部担当様"],
    postalCode: "〒330-0063",
    address: "埼玉県さいたま市浦和区高砂2-11-13",
    tel: "048-762-9340",
    presets: [
      {
        name: "本社（浦和）",
        company: "CASCADIA TRADING, INC. 本社",
        recipient: "資材担当様",
        postalCode: "〒330-0063",
        address: "埼玉県さいたま市浦和区高砂2-11-13",
        tel: "048-762-9340"
      }
    ]
  }
};

const FLEXCON_LOCATIONS = Object.keys(FLEXCON_LOCATION_DETAILS);

// 品名マスター（商品名読み替え表【仮】に基づく読み替え後名称・正式商品名マッピング）
const FLEXCON_ITEMS = [
  { 
    id: "SNS-1", 
    commonName: "フレコンSNS-1", 
    name: "フレコンワンウェイバッグSNS-1　上下全開タイプφ1100×1200", 
    spec: "上下全開タイプ φ1100×1200 / 耐荷重1t",
    defaultPrice: 1000, 
    safetyStock: 300 
  },
  { 
    id: "PE-INNER", 
    commonName: "PE内袋", 
    name: "国産PE内袋(0.07×1850×3000 平シール)", 
    spec: "厚み0.07mm × 幅1850mm × 長さ3000mm 平シール",
    defaultPrice: 550, 
    safetyStock: 300 
  },
  { 
    id: "SOYPASS-BAG", 
    commonName: "紙袋（ソイパス詰替用）", 
    name: "ソイパス用紙袋 新印刷(813×419×76mm)", 
    spec: "3層クラフト紙 813×419×76mm (25kg詰替用)",
    defaultPrice: 71.5, 
    safetyStock: 1000 
  },
  { 
    id: "BTNR-1000C", 
    commonName: "投入口全開フレコン (1t用)", 
    name: "フレコンワンウェイバッグ BTNR-1000C (投入口全開型 φ1100×1100H)", 
    spec: "投入口全開型 φ1100×1100H / 排出口付",
    defaultPrice: 1000, 
    safetyStock: 200 
  }
];

const FLEXCON_SUPPLIERS = [
  { 
    name: "株式会社シオヤ", 
    contactPerson: "太田 光一　様", 
    tel: "092-712-1234", 
    email: "order@shioya-pack.co.jp", 
    address: "福岡県福岡市博多区博多駅前2-10-5" 
  },
  { 
    name: "佐藤産業株式会社", 
    contactPerson: "資材営業担当　様", 
    tel: "03-3661-5432", 
    email: "info@sato-sangyo.co.jp", 
    address: "東京都中央区日本橋本町3-4-1" 
  },
  { 
    name: "その他仕入先", 
    contactPerson: "ご担当者　様", 
    tel: "", 
    email: "", 
    address: "" 
  }
];

// 1拠点仮運用（上組 福岡支店）初期データ：8月末在庫数 1,933枚 / 金額 138,210円（71.5円/枚）
const INITIAL_FLEXCON_DATA = {
  transactions: [
    { 
      id: "TX-INIT-0831", 
      date: "2026-08-31", 
      orderDate: "2026-08-31", 
      type: "inbound", 
      status: "delivered", // 実在庫として即時計上
      location: "上組 福岡支店", 
      item: "SOYPASS-BAG", 
      qty: 1933, 
      price: 71.5, 
      supplier: "佐藤産業株式会社", 
      supplierContact: "資材営業担当　様",
      ourContact: "畑山",
      quoteNo: "",
      orderNo: "INIT-20260831", 
      purpose: "8月末繰越残高（仮運用開始）", 
      note: "2026年8月末時点の繰越在庫: 1,933枚 / 138,210円（単価: 71.5円）にて登録" 
    }
  ]
};

function loadFlexconData() {
  const saved = localStorage.getItem('cascadia_flexcon_inventory_v4');
  if (saved) {
    try { 
      const parsed = JSON.parse(saved);
      if (parsed && Array.isArray(parsed.transactions)) {
        // status 補完
        parsed.transactions.forEach(tx => {
          if (!tx.status) tx.status = 'delivered';
        });
        return parsed;
      }
    } catch(e){}
  }
  // v4データが存在しない場合は初期データ（上組 福岡支店の8月末在庫のみ）で初期化
  localStorage.setItem('cascadia_flexcon_inventory_v4', JSON.stringify(INITIAL_FLEXCON_DATA));
  return JSON.parse(JSON.stringify(INITIAL_FLEXCON_DATA));
}

function saveFlexconData(data) {
  localStorage.setItem('cascadia_flexcon_inventory_v4', JSON.stringify(data));
}

// 状態管理
let activeFlexconTab = 'dashboard'; // 'dashboard' | 'ledger' | 'check'
let currentFlexconAsOf = 'latest'; // 'latest' or 'YYYY-MM-DD'
let ledgerFilterLoc = 'all';
let ledgerFilterType = 'all';
let ledgerFilterMonth = 'all'; // 'all' or 'YYYY-MM'
let ledgerSortAsc = false; // デフォルトは新しい順（降順）

function renderFlexconInventory(targetEl) {
  const rootEl = targetEl || document.getElementById('contentArea') || document.getElementById('flexconAppContent');
  if (!rootEl) return;

  const data = loadFlexconData();
  const today = new Date().toISOString().split('T')[0];

  // 未納品・遅延件数の集計（タブバッジ用）
  const pendingOrders = data.transactions.filter(t => t.status === 'ordered');
  const overdueCount = pendingOrders.filter(t => t.deliveryDueDate && t.deliveryDueDate < today).length;
  const pendingCount = pendingOrders.length;

  const isStandalone = window.location.pathname.endsWith('flexcon.html') || window.location.pathname.includes('flexcon');

  rootEl.innerHTML = `
    <div class="page-hero" style="padding: 24px; margin-bottom: 20px; background: linear-gradient(135deg, rgba(139,92,246,0.1), rgba(168,85,247,0.05)); border: 1px solid rgba(139,92,246,0.2); border-radius: 14px;">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 14px;">
        <div style="flex: 1; min-width: 280px;">
          <h1 class="page-title" style="margin-bottom: 6px;">📦 フレコンバッグ資材 在庫数・在庫金額確認ツール</h1>
          <p class="page-subtitle" style="margin: 0;">消耗品として費用処理されるフレコンバッグ等のリアルタイム実在庫枚数・評価金額を一元管理し、発注書自動出力および納期遅延アラートに対応します。</p>
        </div>
        ${!isStandalone ? `
        <div>
          <a href="flexcon.html" target="_blank" rel="noopener noreferrer" style="display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; background: #ffffff; border: 1px solid rgba(139,92,246,0.35); border-radius: 8px; color: #7c3aed; font-size: 13px; font-weight: 700; text-decoration: none; box-shadow: 0 2px 5px rgba(139,92,246,0.1); transition: all 0.2s ease;">
            <span>🚀 他部署共有用・専用ポータルを開く</span>
            <span style="font-size: 11px;">↗</span>
          </a>
        </div>
        ` : ''}
      </div>
    </div>

    <!-- UX改善：ビュー切替（左）とアクションボタングループ（右）の明確な分離 -->
    <div class="flexcon-nav-bar">
      <!-- 閲覧ビュー切替（3つのピルタブ） -->
      <div class="flexcon-view-tabs">
        <button class="flexcon-tab-pill ${activeFlexconTab === 'dashboard' ? 'active' : ''}" id="tabFlexconDash">
          <span>📊</span> 在庫ダッシュボード
        </button>
        <button class="flexcon-tab-pill ${activeFlexconTab === 'ledger' ? 'active' : ''}" id="tabFlexconLedger">
          <span>📋</span> 履歴・未納品
          ${pendingCount > 0 ? `
            <span class="tab-badge ${overdueCount > 0 ? 'badge-danger' : ''}" title="${overdueCount > 0 ? `${overdueCount}件の納期遅延あり` : `${pendingCount}件の発注中`}">
              ${overdueCount > 0 ? `⚠️ ${pendingCount}` : pendingCount}
            </span>
          ` : ''}
        </button>
        <button class="flexcon-tab-pill ${activeFlexconTab === 'check' ? 'active' : ''}" id="tabFlexconCheck">
          <span>📑</span> 月末棚卸し・CSV
        </button>
      </div>

      <!-- クイック登録アクション（モーダル起動） -->
      <div class="flexcon-action-group">
        <button class="btn-action-order" id="btnOpenOrderModal" title="フレコン資材の新規発注を登録し、A4発注書を作成・印刷します">
          <span>📝</span> 発注・発注書作成
        </button>
        <button class="btn-action-sub" id="btnOpenInboundModal" title="直接の納品受入を実在庫に即時加算します">
          <span>📥</span> 入庫
        </button>
        <button class="btn-action-sub" id="btnOpenOutboundModal" title="現場での使用・出荷を実在庫から減算します">
          <span>📤</span> 出庫
        </button>
      </div>
    </div>

    <div id="flexconTabContent"></div>
    <div id="flexconActionModalContainer"></div>
    <div id="purchaseOrderModalContainer"></div>
  `;

  // タブ切り替え
  document.getElementById('tabFlexconDash').addEventListener('click', () => { activeFlexconTab = 'dashboard'; renderFlexconInventory(); });
  document.getElementById('tabFlexconLedger').addEventListener('click', () => { activeFlexconTab = 'ledger'; renderFlexconInventory(); });
  document.getElementById('tabFlexconCheck').addEventListener('click', () => { activeFlexconTab = 'check'; renderFlexconInventory(); });

  // アクションモーダル起動
  document.getElementById('btnOpenOrderModal').addEventListener('click', () => { openFlexconOrderModal(data); });
  document.getElementById('btnOpenInboundModal').addEventListener('click', () => { openFlexconInboundModal(data); });
  document.getElementById('btnOpenOutboundModal').addEventListener('click', () => { openFlexconOutboundModal(data); });

  const container = document.getElementById('flexconTabContent');

  if (activeFlexconTab === 'dashboard') renderFlexconDashboard(container, data);
  else if (activeFlexconTab === 'ledger') renderFlexconLedger(container, data);
  else if (activeFlexconTab === 'check') renderFlexconCheck(container, data);
  else {
    activeFlexconTab = 'dashboard';
    renderFlexconDashboard(container, data);
  }
}

// 在庫計算ヘルパー（指定月末時点対応 ＆ 未納品発注残の分離）
function calculateStockMatrix(transactions, asOfDate = null) {
  const matrix = {};
  FLEXCON_LOCATIONS.forEach(loc => {
    matrix[loc] = {};
    FLEXCON_ITEMS.forEach(item => {
      matrix[loc][item.id] = { qty: 0, totalValue: 0, lastPrice: item.defaultPrice, orderedQty: 0 };
    });
  });

  const filtered = transactions.filter(tx => {
    if (asOfDate && tx.date > asOfDate) return false;
    return true;
  });

  filtered.slice().sort((a, b) => new Date(a.date) - new Date(b.date)).forEach(tx => {
    if (!matrix[tx.location]) return;

    // 複数品目対応（tx.items があればそれを使用、なければ従来の単一品目）
    const items = (tx.items && tx.items.length > 0) ? tx.items : [{
      item: tx.item,
      qty: tx.qty,
      price: tx.price
    }];

    items.forEach(it => {
      const itemKey = it.item;
      if (!itemKey) return;
      if (!matrix[tx.location][itemKey]) {
        matrix[tx.location][itemKey] = { qty: 0, totalValue: 0, lastPrice: it.price || 1000, orderedQty: 0 };
      }

      const cell = matrix[tx.location][itemKey];
      if (it.price > 0) cell.lastPrice = it.price;

      if (tx.type === 'inbound') {
        if (tx.status === 'ordered') {
          // 未納品（発注残）としてカウント（実在庫にはまだ加算しない）
          cell.orderedQty = (cell.orderedQty || 0) + it.qty;
        } else {
          // 納品完了（実在庫）に加算
          cell.qty += it.qty;
          cell.totalValue += (it.qty * (it.price || cell.lastPrice));
        }
      } else if (tx.type === 'outbound') {
        cell.qty -= it.qty;
        cell.totalValue -= (it.qty * (it.price || cell.lastPrice));
        if (cell.qty < 0) cell.qty = 0;
        if (cell.totalValue < 0) cell.totalValue = 0;
      }
    });
  });

  return matrix;
}

// 1. ダッシュボード描画（何月末時点対応 ＆ 納期遅延アラート表示）
function renderFlexconDashboard(container, data) {
  const today = new Date().toISOString().split('T')[0];
  const asOf = currentFlexconAsOf === 'latest' ? null : currentFlexconAsOf;
  const matrix = calculateStockMatrix(data.transactions, asOf);

  let grandTotalQty = 0;
  let grandTotalValue = 0;
  let grandTotalOrdered = 0;
  const shortageItems = []; // 未発注（発注残なし・至急手配が必要）
  const incomingItems = []; // 入荷待ち（発注残あり・手配済）

  FLEXCON_LOCATIONS.forEach(loc => {
    FLEXCON_ITEMS.forEach(item => {
      const cell = matrix[loc][item.id];
      grandTotalQty += cell.qty;
      grandTotalValue += cell.totalValue;
      const ordQty = cell.orderedQty || 0;
      grandTotalOrdered += ordQty;

      if (cell.qty < item.safetyStock) {
        const alertObj = {
          location: loc,
          item: item,
          currentQty: cell.qty,
          orderedQty: ordQty,
          safetyStock: item.safetyStock
        };
        if (ordQty > 0) {
          incomingItems.push(alertObj);
        } else {
          shortageItems.push(alertObj);
        }
      }
    });
  });

  // 拠点ごとにアイテムをまとめる
  const shortageByLoc = {};
  shortageItems.forEach(a => {
    if (!shortageByLoc[a.location]) shortageByLoc[a.location] = [];
    shortageByLoc[a.location].push(a);
  });

  const incomingByLoc = {};
  incomingItems.forEach(a => {
    if (!incomingByLoc[a.location]) incomingByLoc[a.location] = [];
    incomingByLoc[a.location].push(a);
  });

  // 納品予定日超過アラート（status: 'ordered' かつ deliveryDueDate < today）
  const overdueOrders = data.transactions.filter(t => 
    t.status === 'ordered' && t.deliveryDueDate && t.deliveryDueDate < today
  );

  container.innerHTML = `
    <!-- 集計基準年月セレクター（何月末時点の残高確認） -->
    <div style="background: var(--bg-card); border: 1px solid var(--border-medium); border-radius: 12px; padding: 14px 18px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
      <div style="display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 20px;">📅</span>
        <div>
          <div style="font-size: 13px; font-weight: 700; color: var(--text-primary);">在庫集計の基準時点（指定月末時点の枚数・金額確認）</div>
          <div style="font-size: 11px; color: var(--text-muted);">
            指定した月末日時点での各倉庫の在庫枚数と評価額（経理・経営向け／実務向け）を瞬時に再現・表示します。
          </div>
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 8px;">
        <select id="asOfSelect" style="padding: 6px 12px; font-size: 13px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-medium); background: var(--bg-primary); color: var(--text-primary);">
          <option value="latest" ${currentFlexconAsOf === 'latest' ? 'selected' : ''}>⚡ 最新リアルタイム（全期間）</option>
          <option value="2026-08-31" ${currentFlexconAsOf === '2026-08-31' ? 'selected' : ''}>2026年 8月末 時点 (2026/08/31)</option>
          <option value="2026-07-31" ${currentFlexconAsOf === '2026-07-31' ? 'selected' : ''}>2026年 7月末 時点 (2026/07/31)</option>
          <option value="2026-06-30" ${currentFlexconAsOf === '2026-06-30' ? 'selected' : ''}>2026年 6月末 時点 (2026/06/30)</option>
          <option value="2026-05-31" ${currentFlexconAsOf === '2026-05-31' ? 'selected' : ''}>2026年 5月末 時点 (2026/05/31)</option>
        </select>
        <span style="font-size: 12px; font-weight: 700; color: var(--accent-blue); background: rgba(37,99,235,0.1); padding: 4px 10px; border-radius: 6px;">
          ${currentFlexconAsOf === 'latest' ? '現在時点' : currentFlexconAsOf + ' 時点'}
        </span>
      </div>
    </div>

    <!-- 集計カード -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 20px;">
      <div class="tool-card" style="padding: 16px;">
        <div style="font-size: 12px; color: var(--text-secondary); font-weight: 600;">全社合計 実在庫枚数</div>
        <div style="font-size: 26px; font-weight: 800; color: var(--accent-blue); margin-top: 4px;">${grandTotalQty.toLocaleString()} <span style="font-size: 14px; font-weight: 600;">枚</span></div>
        ${grandTotalOrdered > 0 ? `<div style="font-size: 11px; color: var(--accent-green); margin-top: 4px;">+ 発注中（入荷待ち）: <strong>${grandTotalOrdered.toLocaleString()}</strong> 枚</div>` : ''}
      </div>
      <div class="tool-card" style="padding: 16px;">
        <div style="font-size: 12px; color: var(--text-secondary); font-weight: 600;">全社総在庫金額（評価額）</div>
        <div style="font-size: 26px; font-weight: 800; color: var(--accent-violet); margin-top: 4px;">¥${Math.round(grandTotalValue).toLocaleString()}</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">税抜・移動平均/最終仕入単価</div>
      </div>
      <div class="tool-card" style="padding: 16px; ${overdueOrders.length > 0 ? 'border: 1px solid rgba(239,68,68,0.3); background: rgba(239,68,68,0.04);' : ''}">
        <div style="font-size: 12px; color: var(--text-secondary); font-weight: 600;">納品予定日超過アラート</div>
        <div style="font-size: 26px; font-weight: 800; color: ${overdueOrders.length > 0 ? '#ef4444' : 'var(--accent-green)'}; margin-top: 4px;">${overdueOrders.length} <span style="font-size: 14px; font-weight: 600;">件</span></div>
        <div style="font-size: 11px; color: ${overdueOrders.length > 0 ? '#ef4444' : 'var(--text-muted)'}; margin-top: 4px;">${overdueOrders.length > 0 ? '未納品・要納期確認！' : '遅延なし'}</div>
      </div>
      <div class="tool-card" style="padding: 16px; ${shortageItems.length > 0 ? 'border: 1px solid rgba(239,68,68,0.3); background: rgba(239,68,68,0.03);' : ''}">
        <div style="font-size: 12px; color: var(--text-secondary); font-weight: 600;">安全在庫アラート（要発注）</div>
        <div style="font-size: 26px; font-weight: 800; color: ${shortageItems.length > 0 ? '#ef4444' : 'var(--accent-green)'}; margin-top: 4px;">${shortageItems.length} <span style="font-size: 14px; font-weight: 600;">件</span></div>
        <div style="font-size: 11px; color: ${shortageItems.length > 0 ? '#ef4444' : 'var(--text-muted)'}; margin-top: 4px;">${shortageItems.length > 0 ? '未発注・至急手配が必要' : '安全在庫維持OK'}</div>
        ${incomingItems.length > 0 ? `
          <div style="font-size: 11px; color: var(--accent-blue); margin-top: 5px; border-top: 1px dashed var(--border-subtle); padding-top: 4px; font-weight: 600;">
            🚚 入荷待ち(手配済): <strong>${incomingItems.length}</strong> 件
          </div>
        ` : ''}
      </div>
    </div>

    <!-- 🚨 納品予定日超過アラートボックス -->
    ${overdueOrders.length > 0 ? `
      <div class="alert" style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3); border-left: 5px solid #ef4444; border-radius: 10px; padding: 16px; margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
          <div style="font-size: 14px; font-weight: 700; color: #ef4444; display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 18px;">🚨</span> 納品予定日超過（未納品）アラート通知 (${overdueOrders.length}件)
          </div>
          <span style="font-size: 11px; color: var(--text-secondary);">納品予定日を過ぎていますが「納品完了」が登録されていません。至急状況をご確認ください。</span>
        </div>
        <div style="margin-top: 10px; display: flex; flex-direction: column; gap: 8px;">
          ${overdueOrders.map(o => {
            const itemObj = FLEXCON_ITEMS.find(i => i.id === o.item);
            const supObj = FLEXCON_SUPPLIERS.find(s => s.name === o.supplier) || {};
            const diffDays = Math.floor((new Date(today) - new Date(o.deliveryDueDate)) / (1000 * 60 * 60 * 24));
            const dueDisplayStr = o.isEarliestDelivery ? `最短希望 (目安: ${o.deliveryDueDate})` : o.deliveryDueDate;
            const mailSubject = encodeURIComponent(`【納期確認】発注書(${o.orderNo || o.id})の納品状況について (株式会社カスケディア・トレーディング)`);
            const mailBody = encodeURIComponent(`${o.supplier} 御中\n\nお世話になっております。株式会社カスケディア・トレーディングの業務部です。\n\n下記の発注につきまして、納品希望日(${dueDisplayStr})を過ぎておりますが、現在の到着・発送状況はいかがでしょうか。\nご確認のほどよろしくお願い申し上げます。\n\n■発注番号: ${o.orderNo || o.id}\n■納入場所: ${o.location}\n■品名: ${itemObj ? itemObj.name : o.item}\n■数量: ${o.qty} 枚\n■納品希望日: ${dueDisplayStr}\n`);
            return `
              <div style="background: var(--bg-primary); border: 1px solid rgba(239,68,68,0.2); border-radius: 8px; padding: 10px 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                <div>
                  <div style="font-size: 13px; font-weight: 700;">
                    <span style="color: #ef4444;">[納期超過 +${diffDays}日]</span> 
                    <strong>${o.location}</strong> 宛 ── ${itemObj ? `<span style="color: var(--accent-blue);">【${itemObj.commonName}】</span> ${itemObj.id}` : o.item} × <strong>${o.qty}枚</strong>
                  </div>
                  <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">
                    発注日: ${o.orderDate || o.date} ｜ 納品予定日: <strong style="color: #ef4444;">${o.isEarliestDelivery ? `⚡最短希望 (目安: ${o.deliveryDueDate})` : o.deliveryDueDate}</strong> ｜ 仕入先: ${o.supplier} ${supObj.tel ? `(TEL: ${supObj.tel})` : ''} ｜ 発注No: ${o.orderNo || o.id}
                  </div>
                </div>
                <div style="display: flex; gap: 6px;">
                  ${supObj.email ? `
                    <a href="mailto:${supObj.email}?subject=${mailSubject}&body=${mailBody}" class="btn btn-secondary" style="padding: 4px 10px; font-size: 11px; text-decoration: none; display: inline-flex; align-items: center; gap: 4px; border-color: var(--accent-blue); color: var(--accent-blue);">
                      ✉️ 納期確認メール作成
                    </a>
                  ` : ''}
                  <button class="btn btn-primary btn-quick-deliver" data-id="${o.id}" style="padding: 4px 12px; font-size: 11px; background: var(--accent-green); border-color: var(--accent-green);">
                    ✅ 納品完了にする
                  </button>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    ` : ''}

    <!-- 📊 アラート通知エリア（2カラム・拠点別にコンパクト整理） -->
    ${(shortageItems.length > 0 || incomingItems.length > 0) ? `
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 14px; margin-bottom: 20px;">
        <!-- 🚨 要発注（未手配） -->
        <div class="alert" style="background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.25); border-left: 4px solid #ef4444; border-radius: 8px; padding: 12px 14px; margin: 0;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <div style="color: #ef4444; font-size: 13px; font-weight: 700; display: flex; align-items: center; gap: 6px;">
              <span>🚨</span> 要発注・安全在庫不足 (${shortageItems.length}件)
            </div>
            <span style="font-size: 11px; color: #ef4444; font-weight: 600; background: rgba(239,68,68,0.1); padding: 2px 8px; border-radius: 10px;">発注残なし・至急手配</span>
          </div>
          ${shortageItems.length === 0 ? `
            <div style="font-size: 12px; color: var(--text-muted); padding: 6px 0;">現在、未発注の在庫不足品目はありません。</div>
          ` : `
            <div style="max-height: 240px; overflow-y: auto; padding-right: 4px; display: flex; flex-direction: column; gap: 6px;">
              ${Object.entries(shortageByLoc).map(([loc, list]) => `
                <div style="background: var(--bg-primary); border: 1px solid rgba(239,68,68,0.15); border-radius: 6px; padding: 6px 10px; font-size: 12px;">
                  <div style="font-weight: 700; color: var(--text-primary); margin-bottom: 4px; display: flex; justify-content: space-between;">
                    <span>📍 ${loc}</span>
                    <span style="font-size: 11px; color: #ef4444; font-weight: 600;">${list.length}品目 要手配</span>
                  </div>
                  <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                    ${list.map(a => `
                      <span title="${a.item.name}" style="display: inline-flex; align-items: center; gap: 4px; background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.25); border-radius: 4px; padding: 2px 6px; font-size: 11px;">
                        <strong>【${a.item.commonName}】</strong>
                        <span style="color: #ef4444; font-weight: 700;">残${a.currentQty}枚</span>
                        <span style="color: var(--text-muted); font-size: 10px;">(基準:${a.safetyStock})</span>
                      </span>
                    `).join('')}
                  </div>
                </div>
              `).join('')}
            </div>
          `}
        </div>

        <!-- 🚚 入荷待ち（発注済・手配中） -->
        <div class="alert" style="background: rgba(37, 99, 235, 0.04); border: 1px solid rgba(37, 99, 235, 0.22); border-left: 4px solid var(--accent-blue); border-radius: 8px; padding: 12px 14px; margin: 0;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <div style="color: var(--accent-blue); font-size: 13px; font-weight: 700; display: flex; align-items: center; gap: 6px;">
              <span>🚚</span> 入荷待ち（発注済・手配中） (${incomingItems.length}件)
            </div>
            <span style="font-size: 11px; color: var(--accent-blue); font-weight: 600; background: rgba(37,99,235,0.1); padding: 2px 8px; border-radius: 10px;">手配済・到着待ち</span>
          </div>
          ${incomingItems.length === 0 ? `
            <div style="font-size: 12px; color: var(--text-muted); padding: 6px 0;">現在、入荷待ちの品目はありません。</div>
          ` : `
            <div style="max-height: 240px; overflow-y: auto; padding-right: 4px; display: flex; flex-direction: column; gap: 6px;">
              ${Object.entries(incomingByLoc).map(([loc, list]) => `
                <div style="background: var(--bg-primary); border: 1px solid rgba(37,99,235,0.15); border-radius: 6px; padding: 6px 10px; font-size: 12px;">
                  <div style="font-weight: 700; color: var(--text-primary); margin-bottom: 4px; display: flex; justify-content: space-between;">
                    <span>📍 ${loc}</span>
                    <span style="font-size: 11px; color: var(--accent-blue); font-weight: 600;">${list.length}品目 手配中</span>
                  </div>
                  <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                    ${list.map(a => `
                      <span title="${a.item.name}" style="display: inline-flex; align-items: center; gap: 4px; background: rgba(37,99,235,0.06); border: 1px solid rgba(37,99,235,0.22); border-radius: 4px; padding: 2px 6px; font-size: 11px;">
                        <strong>【${a.item.commonName}】</strong>
                        <span style="color: var(--text-muted); font-size: 10px;">残${a.currentQty}枚</span>
                        <span style="color: #059669; font-weight: 700;">+発注残${a.orderedQty}枚</span>
                      </span>
                    `).join('')}
                  </div>
                </div>
              `).join('')}
            </div>
          `}
        </div>
      </div>
    ` : ''}

    <!-- 拠点別×型番別 在庫マトリックス -->
    <div class="tool-card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 10px;">
        <h3 style="margin: 0;">📊 拠点別・品名型番別 在庫数および在庫金額一覧 (${currentFlexconAsOf === 'latest' ? '現在時点' : currentFlexconAsOf + ' 時点'})</h3>
        <button class="btn btn-secondary" id="btnGoToOrderTab" style="font-size: 12px; padding: 5px 12px; border-color: var(--accent-green); color: var(--accent-green);">
          + 新規資材を発注する
        </button>
      </div>

      <div class="flexcon-matrix-scroll-wrapper" style="overflow-x: auto;">
        <table class="assistant-table flexcon-matrix-table" style="font-size: 12px; width: 100%; border-collapse: separate; border-spacing: 0;">
          <thead>
            <tr style="background: var(--bg-primary); text-align: center;">
              <th class="col-sticky-loc" style="padding: 10px 14px; text-align: left; min-width: 190px;">保管場所（拠点）</th>
              ${FLEXCON_ITEMS.map(item => `
                <th style="padding: 8px 10px; min-width: 160px;">
                  <div style="color: var(--accent-blue); font-weight: 700; font-size: 12px;">【${item.commonName}】</div>
                  <div style="font-size: 11px; font-weight: 600; color: var(--text-primary);">${item.id}</div>
                  <div style="font-size: 10px; font-weight: normal; color: var(--text-muted);">${item.name.split(' ')[0]}</div>
                </th>
              `).join('')}
              <th style="padding: 10px; min-width: 130px; background: rgba(37,99,235,0.06); text-align: right;">拠点小計金額</th>
            </tr>
          </thead>
          <tbody>
            ${FLEXCON_LOCATIONS.map(loc => {
              let locTotalVal = 0;
              return `
                <tr>
                  <td class="col-sticky-loc" style="padding: 10px 14px; font-weight: 600;">${loc}</td>
                  ${FLEXCON_ITEMS.map(item => {
                    const cell = matrix[loc][item.id];
                    locTotalVal += cell.totalValue;
                    const isAlert = cell.qty < item.safetyStock;
                    return `
                      <td style="padding: 8px 10px; text-align: right; ${isAlert ? 'background: rgba(239,68,68,0.06);' : ''}">
                        <div style="font-size: 14px; font-weight: 700; color: ${isAlert ? '#ef4444' : 'var(--text-primary)'};">
                          ${cell.qty.toLocaleString()} <span style="font-size: 11px; font-weight: normal;">枚</span>
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted);">¥${Math.round(cell.totalValue).toLocaleString()}</div>
                        ${cell.orderedQty > 0 ? `
                          <div style="font-size: 10px; color: var(--accent-green); font-weight: 600; margin-top: 2px;">
                            (入荷待 +${cell.orderedQty}枚)
                          </div>
                        ` : ''}
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
          <tfoot>
            <tr style="background: var(--bg-primary); font-weight: 800; border-top: 2px solid var(--border-medium);">
              <td class="col-sticky-loc" style="padding: 10px 14px; text-align: left;">全社品目別 合計</td>
              ${FLEXCON_ITEMS.map(item => {
                let itemTotalQty = 0;
                let itemTotalVal = 0;
                let itemTotalOrdered = 0;
                FLEXCON_LOCATIONS.forEach(loc => {
                  itemTotalQty += matrix[loc][item.id].qty;
                  itemTotalVal += matrix[loc][item.id].totalValue;
                  itemTotalOrdered += (matrix[loc][item.id].orderedQty || 0);
                });
                return `
                  <td style="padding: 10px; text-align: right;">
                    <div style="color: var(--accent-blue); font-size: 14px;">${itemTotalQty.toLocaleString()} 枚</div>
                    <div style="font-size: 11px; color: var(--text-muted); font-weight: normal;">¥${Math.round(itemTotalVal).toLocaleString()}</div>
                    ${itemTotalOrdered > 0 ? `<div style="font-size: 10px; color: var(--accent-green); font-weight: 600;">(待 +${itemTotalOrdered}枚)</div>` : ''}
                  </td>
                `;
              }).join('')}
              <td style="padding: 10px; text-align: right; font-size: 15px; color: var(--accent-violet);">
                ¥${Math.round(grandTotalValue).toLocaleString()}
              </td>
            </tr>
          </tfoot>
        </table>
      </div>
    </div>
  `;

  // イベントバインド
  document.getElementById('asOfSelect').addEventListener('change', (e) => {
    currentFlexconAsOf = e.target.value;
    renderFlexconDashboard(container, data);
  });

  const btnGoOrder = document.getElementById('btnGoToOrderTab');
  if (btnGoOrder) {
    btnGoOrder.addEventListener('click', () => {
      openFlexconOrderModal(data);
    });
  }

  // 納品完了クイックボタン
  container.querySelectorAll('.btn-quick-deliver').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = e.target.dataset.id;
      markOrderDelivered(id, data);
    });
  });
}

// 納品完了処理（複数品目対応）
function markOrderDelivered(txId, data) {
  const tx = data.transactions.find(t => t.id === txId);
  if (!tx) return;
  const today = new Date().toISOString().split('T')[0];

  const items = (tx.items && tx.items.length > 0) ? tx.items : [{
    item: tx.item,
    qty: tx.qty,
    price: tx.price
  }];

  const itemsSummary = items.map(it => {
    const itemObj = FLEXCON_ITEMS.find(i => i.id === it.item);
    const name = it.customName || (itemObj ? itemObj.commonName : it.item);
    return `${name} (${it.qty.toLocaleString()}枚)`;
  }).join('、');

  if (confirm(`発注番号 ${tx.orderNo || tx.id} (${tx.location}宛: ${itemsSummary}) の納品受入を完了しますか？\n（本日 ${today} 付で実在庫に計上されます）`)) {
    tx.status = 'delivered';
    tx.date = today;
    saveFlexconData(data);
    showToast("✨ 納品受入を完了しました（各品目が実在庫に計上されました）");
    renderFlexconInventory();
  }
}

// 2. 資材発注・発注書自動出力モーダル（複数品目対応・自由入力対応）
function openFlexconOrderModal(data) {
  const modalContainer = document.getElementById('flexconActionModalContainer');
  const today = new Date().toISOString().split('T')[0];
  const targetDate = new Date();
  targetDate.setDate(targetDate.getDate() + 14);
  const defaultDueDate = targetDate.toISOString().split('T')[0];
  const autoPoNo = "PO-" + today.replace(/-/g, '') + "-" + String(Math.floor(Math.random() * 90) + 10);

  const defaultSup = FLEXCON_SUPPLIERS[0];
  const defaultLoc = FLEXCON_LOCATIONS[0];

  modalContainer.innerHTML = `
    <div class="flexcon-modal-overlay" id="flexconOrderModalOverlay">
      <div class="flexcon-modal-box" style="max-width: 780px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 20px;">📝</span>
            <h3 style="margin: 0; font-size: 17px; font-weight: 800;">フレコン資材 新規発注・発注書作成</h3>
          </div>
          <button type="button" id="btnCloseOrderModal" style="background: none; border: none; font-size: 22px; cursor: pointer; color: var(--text-muted); line-height: 1;">✕</button>
        </div>

        <form id="modalOrderForm" class="tool-form" novalidate>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
            <div class="tool-group">
              <label for="mPoDate">発注日 <span style="color:#ef4444;">*</span></label>
              <input type="date" id="mPoDate" value="${today}" required>
            </div>
            <div class="tool-group">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
                <label for="mPoDueDate" style="margin: 0;">納品希望日 <span style="color:#ef4444;">*</span></label>
                <label style="display: inline-flex; align-items: center; gap: 4px; font-size: 11px; cursor: pointer; color: var(--accent-blue); font-weight: 600; margin: 0; user-select: none;" title="最短での納品を希望（社内アラート管理用に2週間後を目安期日に設定）">
                  <input type="checkbox" id="mPoIsEarliest" style="width: auto; margin: 0; cursor: pointer;">
                  <span>⚡ 最短納期希望</span>
                </label>
              </div>
              <input type="date" id="mPoDueDate" value="${defaultDueDate}" required>
              <div id="mPoEarliestNotice" style="font-size: 10.5px; color: var(--accent-blue); margin-top: 3px; display: none;">
                ※社内の遅延アラート管理用として2週間後を目安期日に設定しています
              </div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
            <div class="tool-group">
              <label for="mPoSupplier">発注先（仕入先） <span style="color:#ef4444;">*</span></label>
              <select id="mPoSupplier" required>
                ${FLEXCON_SUPPLIERS.map(s => `<option value="${s.name}">${s.name}</option>`).join('')}
              </select>
            </div>
            <div class="tool-group">
              <label for="mPoSupplierContact">先方ご担当者様名</label>
              <input type="text" id="mPoSupplierContact" value="${defaultSup.contactPerson || ''}" placeholder="例: 太田 光一　様">
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
            <div class="tool-group">
              <label for="mPoLocation">受入拠点（在庫管理場所） <span style="color:#ef4444;">*</span></label>
              <select id="mPoLocation" required>
                ${FLEXCON_LOCATIONS.map(l => `<option value="${l}">${l}</option>`).join('')}
              </select>
            </div>
            <div class="tool-group">
              <label for="mPoOurContact">当社担当者</label>
              <input type="text" id="mPoOurContact" value="畑山" required placeholder="例: 畑山">
            </div>
          </div>

          <!-- 納品先・配送先詳細ブロック（プリセット選択 ＋ 直接手入力・微調整） -->
          <div style="margin-bottom: 16px; background: var(--bg-primary); border: 1px solid var(--border-medium); border-radius: 10px; padding: 12px 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 6px;">
              <span style="font-size: 12px; font-weight: 800; color: var(--text-primary); display: flex; align-items: center; gap: 5px;">
                <span>🚚</span> 納品先／配送先詳細（発注書に印字）
              </span>
              <div style="display: flex; align-items: center; gap: 6px;">
                <label for="mPoAddressPreset" style="font-size: 11px; color: var(--text-secondary); margin: 0; font-weight: 600;">住所候補:</label>
                <select id="mPoAddressPreset" style="padding: 3px 8px; font-size: 11px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-card); color: var(--text-primary); max-width: 240px; text-overflow: ellipsis;">
                </select>
              </div>
            </div>

            <!-- 編集可能な宛先会社名・担当者名 -->
            <div style="display: grid; grid-template-columns: 1.3fr 1.1fr; gap: 8px; margin-bottom: 8px;">
              <div>
                <label style="font-size: 10.5px; color: var(--text-muted); display: block; margin-bottom: 2px;">宛先会社・事業所名 <span style="color:#ef4444;">*</span></label>
                <input type="text" id="mPoDeliveryCompany" required style="width: 100%; font-size: 12px; padding: 5px 8px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-card); color: var(--text-primary); box-sizing: border-box;">
              </div>
              <div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
                  <label style="font-size: 10.5px; color: var(--text-muted); margin: 0;">先方ご担当者様名（受取人）</label>
                  <div id="recipientQuickTags" style="display: flex; gap: 3px; flex-wrap: wrap;"></div>
                </div>
                <input type="text" id="mPoDeliveryRecipient" placeholder="例: ご担当者様（空欄で担当なし）" style="width: 100%; font-size: 12px; padding: 5px 8px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-card); color: var(--text-primary); box-sizing: border-box;">
              </div>
            </div>

            <!-- 編集可能な郵便番号・住所・電話番号 -->
            <div style="display: grid; grid-template-columns: 100px 1fr 130px; gap: 8px;">
              <div>
                <label style="font-size: 10.5px; color: var(--text-muted); display: block; margin-bottom: 2px;">郵便番号</label>
                <input type="text" id="mPoDeliveryPostal" placeholder="〒000-0000" style="width: 100%; font-size: 12px; padding: 5px 8px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-card); color: var(--text-primary); box-sizing: border-box;">
              </div>
              <div>
                <label style="font-size: 10.5px; color: var(--text-muted); display: block; margin-bottom: 2px;">納品先住所（番地・ヤード等） <span style="color:#ef4444;">*</span></label>
                <input type="text" id="mPoDeliveryAddress" required style="width: 100%; font-size: 12px; padding: 5px 8px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-card); color: var(--text-primary); box-sizing: border-box;">
              </div>
              <div>
                <label style="font-size: 10.5px; color: var(--text-muted); display: block; margin-bottom: 2px;">電話番号</label>
                <input type="text" id="mPoDeliveryTel" placeholder="000-000-0000" style="width: 100%; font-size: 12px; padding: 5px 8px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-card); color: var(--text-primary); box-sizing: border-box;">
              </div>
            </div>
            <div style="margin-top: 5px; font-size: 10.5px; color: var(--text-muted);">
              💡 住所候補で切り替えできるほか、この欄で番地や担当者名を直接タイピングして修正できます（発注書にそのまま印字されます）。
            </div>
          </div>

          <!-- 発注明細（複数品名対応） -->
          <div style="margin-bottom: 18px; background: rgba(37,99,235,0.02); border: 1px solid var(--border-medium); border-radius: 10px; padding: 14px 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
              <label style="font-weight: 800; font-size: 14px; display: flex; align-items: center; gap: 6px; margin: 0; color: var(--text-primary);">
                <span>📦</span> 発注明細（品名・数量・単価） <span style="color:#ef4444;">*</span>
              </label>
              <button type="button" id="btnAddPoItemRow" class="btn btn-secondary" style="padding: 5px 12px; font-size: 12px; display: inline-flex; align-items: center; gap: 4px; font-weight: 700; color: var(--accent-blue); border-color: var(--accent-blue); background: var(--bg-card); cursor: pointer;">
                ➕ 品目を追加
              </button>
            </div>

            <div id="poItemsRowsContainer" style="display: flex; flex-direction: column; gap: 12px;"></div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
            <div class="tool-group">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <label for="mPoNo" style="margin: 0;">発注書番号（管理No） <span style="font-size: 11px; color: var(--text-muted); font-weight: normal;">(空白・未記入可)</span></label>
                <div style="display: flex; gap: 4px;">
                  <button type="button" id="btnGenPoNo" style="background: none; border: 1px solid var(--border-medium); border-radius: 4px; font-size: 10.5px; padding: 1px 6px; cursor: pointer; color: var(--accent-blue);" title="自動採番コードを挿入">🎲 採番</button>
                  <button type="button" id="btnClearPoNo" style="background: none; border: 1px solid var(--border-subtle); border-radius: 4px; font-size: 10.5px; padding: 1px 6px; cursor: pointer; color: #ef4444;" title="空白にする">✕ 空白</button>
                </div>
              </div>
              <input type="text" id="mPoNo" value="" placeholder="例: PO-20260930-01（空白のまま印刷・登録可能）">
            </div>
            <div class="tool-group">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <label for="mPoDueMonthNote" style="margin: 0;">計上月等の特記事項 <span style="font-size: 11px; color: var(--text-muted); font-weight: normal;">(空白出力可)</span></label>
                <div style="display: flex; gap: 4px;">
                  <button type="button" id="btnResetDueMonthNote" style="background: none; border: 1px solid var(--border-medium); border-radius: 4px; font-size: 10.5px; padding: 1px 6px; cursor: pointer; color: var(--accent-blue);" title="標準の出荷月注記をセット">🔄 標準文</button>
                  <button type="button" id="btnClearDueMonthNote" style="background: none; border: 1px solid var(--border-subtle); border-radius: 4px; font-size: 10.5px; padding: 1px 6px; cursor: pointer; color: #ef4444;" title="空白にする">✕ 空白</button>
                </div>
              </div>
              <input type="text" id="mPoDueMonthNote" value="※出荷（計上）も当月でお願いいたします。" placeholder="※空白の場合は発注書にも印字されません">
            </div>
          </div>

          <div class="tool-group">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; flex-wrap: wrap; gap: 4px;">
              <label for="mPoNote" style="margin: 0;">備考欄（発注書に印字）</label>
              <div style="display: flex; gap: 4px; flex-wrap: wrap; align-items: center;">
                <span style="font-size: 10.5px; color: var(--text-muted); margin-right: 2px;">定型文:</span>
                <button type="button" id="btnNotePresetAll" style="border: 1px solid var(--border-medium); background: var(--bg-card); font-size: 10.5px; padding: 2px 7px; border-radius: 4px; cursor: pointer; color: var(--accent-blue); font-weight: 600;" title="標準の2行定型文をセット">🔄 標準定型文</button>
                <button type="button" id="btnNoteAddInvoice" style="border: 1px solid var(--border-medium); background: var(--bg-card); font-size: 10.5px; padding: 2px 7px; border-radius: 4px; cursor: pointer; color: var(--text-secondary);" title="送り状社名注記を追加">＋ 送り状社名</button>
                <button type="button" id="btnNoteAddDueDate" style="border: 1px solid var(--border-medium); background: var(--bg-card); font-size: 10.5px; padding: 2px 7px; border-radius: 4px; cursor: pointer; color: var(--text-secondary);" title="納品日連絡希望を追加">＋ 納品日連絡</button>
                <button type="button" id="btnNoteClear" style="border: 1px solid var(--border-subtle); background: var(--bg-card); font-size: 10.5px; padding: 2px 7px; border-radius: 4px; cursor: pointer; color: #ef4444;" title="備考欄を空にして自由に手入力">✕ 空白にする</button>
              </div>
            </div>
            <textarea id="mPoNote" rows="3" placeholder="備考を自由に入力できます（右上のボタンで定型文の挿入やクリアも可能）" style="width: 100%; padding: 8px 12px; font-size: 13px; border-radius: 8px; border: 1px solid var(--border-medium); background: var(--bg-card); color: var(--text-primary); box-sizing: border-box;">・送り状には弊社の名前が入るよう、ご準備の程よろしくお願いいたします。
・納品日がお決まりになりましたらご連絡お待ちしております。</textarea>
          </div>

          <div style="background: var(--bg-primary); border: 1px solid var(--border-subtle); padding: 14px 18px; border-radius: 10px; margin-top: 12px; font-size: 13px;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
              <span>発注小計（税抜）:</span>
              <strong id="mPoSubtotal">¥0</strong>
            </div>
            <div style="display: flex; justify-content: space-between; color: var(--text-secondary); font-size: 12px; margin-bottom: 4px;">
              <span>消費税（10%）:</span>
              <span id="mPoTax">¥0</span>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 16px; border-top: 1px dashed var(--border-medium); padding-top: 8px; margin-top: 8px;">
              <span style="font-weight: 700;">発注合計（税込）:</span>
              <strong id="mPoTotal" style="color: var(--accent-blue); font-size: 18px;">¥0</strong>
            </div>
          </div>

          <div style="display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap;">
            <button type="button" id="btnCancelOrderModal" class="btn btn-secondary" style="flex: 1; min-width: 90px; padding: 11px;">キャンセル</button>
            <button type="button" id="btnPreviewOrderModal" class="btn btn-secondary" style="flex: 1.5; min-width: 150px; padding: 11px; font-size: 13.5px; font-weight: 700; color: #1d4ed8; border-color: #93c5fd; background: #eff6ff; display: inline-flex; align-items: center; justify-content: center; gap: 6px; cursor: pointer;" title="発注登録を確定する前に、発注書プレビュー（A4横）を確認します">
              👁️ 発注書プレビュー
            </button>
            <button type="submit" id="btnSubmitOrderModal" class="btn btn-primary" style="flex: 1.5; min-width: 150px; padding: 11px; font-size: 13.5px; font-weight: 700; background: linear-gradient(135deg, #10b981, #059669); border-color: #059669; display: inline-flex; align-items: center; justify-content: center; gap: 6px; cursor: pointer;" title="この内容で発注登録を実行し、在庫・入出庫台帳に反映します">
              ✅ 発注登録する
            </button>
          </div>
        </form>
      </div>
    </div>
  `;

  const closeModal = () => { modalContainer.innerHTML = ''; };
  document.getElementById('btnCloseOrderModal').addEventListener('click', closeModal);
  document.getElementById('btnCancelOrderModal').addEventListener('click', closeModal);
  document.getElementById('flexconOrderModalOverlay').addEventListener('click', (e) => {
    if (e.target.id === 'flexconOrderModalOverlay') closeModal();
  });

  const supplierSelect = document.getElementById('mPoSupplier');
  const supplierContactInput = document.getElementById('mPoSupplierContact');
  const locationSelect = document.getElementById('mPoLocation');
  const addressPresetSelect = document.getElementById('mPoAddressPreset');
  const deliveryCompanyInput = document.getElementById('mPoDeliveryCompany');
  const deliveryRecipientInput = document.getElementById('mPoDeliveryRecipient');
  const deliveryPostalInput = document.getElementById('mPoDeliveryPostal');
  const deliveryAddressInput = document.getElementById('mPoDeliveryAddress');
  const deliveryTelInput = document.getElementById('mPoDeliveryTel');
  const dueDateInput = document.getElementById('mPoDueDate');
  const dueMonthNoteInput = document.getElementById('mPoDueMonthNote');
  const poNoInput = document.getElementById('mPoNo');
  const rowsContainer = document.getElementById('poItemsRowsContainer');

  document.getElementById('btnGenPoNo').addEventListener('click', () => {
    poNoInput.value = autoPoNo;
  });
  document.getElementById('btnClearPoNo').addEventListener('click', () => {
    poNoInput.value = '';
  });

  document.getElementById('btnClearDueMonthNote').addEventListener('click', () => {
    dueMonthNoteInput.value = '';
    dueMonthNoteInput.dataset.userCleared = 'true';
    dueMonthNoteInput.focus();
  });
  document.getElementById('btnResetDueMonthNote').addEventListener('click', () => {
    dueMonthNoteInput.dataset.userCleared = 'false';
    if (dueDateInput.value) {
      const parts = dueDateInput.value.split('-');
      if (parts.length === 3) {
        const m = parseInt(parts[1], 10);
        dueMonthNoteInput.value = `※出荷（計上）も${m}月でお願いいたします。`;
        return;
      }
    }
    dueMonthNoteInput.value = '※出荷（計上）も当月でお願いいたします。';
  });
  dueMonthNoteInput.addEventListener('input', () => {
    if (dueMonthNoteInput.value.trim() === '') {
      dueMonthNoteInput.dataset.userCleared = 'true';
    } else {
      dueMonthNoteInput.dataset.userCleared = 'false';
    }
  });

  const isEarliestCheckbox = document.getElementById('mPoIsEarliest');
  const earliestNotice = document.getElementById('mPoEarliestNotice');
  isEarliestCheckbox.addEventListener('change', (e) => {
    if (e.target.checked) {
      dueDateInput.value = defaultDueDate;
      earliestNotice.style.display = 'block';
    } else {
      earliestNotice.style.display = 'none';
    }
  });

  const noteTextarea = document.getElementById('mPoNote');
  const defaultNotesText = `・送り状には弊社の名前が入るよう、ご準備の程よろしくお願いいたします。\n・納品日がお決まりになりましたらご連絡お待ちしております。`;
  const noteInvoiceText = '・送り状には弊社の名前が入るよう、ご準備の程よろしくお願いいたします。';
  const noteDueDateText = '・納品日がお決まりになりましたらご連絡お待ちしております。';

  document.getElementById('btnNotePresetAll').addEventListener('click', () => {
    noteTextarea.value = defaultNotesText;
  });
  document.getElementById('btnNoteClear').addEventListener('click', () => {
    noteTextarea.value = '';
    noteTextarea.focus();
  });
  document.getElementById('btnNoteAddInvoice').addEventListener('click', () => {
    if (!noteTextarea.value.includes(noteInvoiceText)) {
      noteTextarea.value = (noteTextarea.value.trim() ? noteTextarea.value.trim() + '\n' : '') + noteInvoiceText;
    }
  });
  document.getElementById('btnNoteAddDueDate').addEventListener('click', () => {
    if (!noteTextarea.value.includes(noteDueDateText)) {
      noteTextarea.value = (noteTextarea.value.trim() ? noteTextarea.value.trim() + '\n' : '') + noteDueDateText;
    }
  });

  // 納品先住所プリセットの連動＆反映
  function applyAddressPreset(preset) {
    if (!preset) return;
    deliveryCompanyInput.value = preset.company || '';
    deliveryRecipientInput.value = preset.recipient || '';
    deliveryPostalInput.value = preset.postalCode || '';
    deliveryAddressInput.value = preset.address || '';
    deliveryTelInput.value = preset.tel || '';
  }

  function updateAddressPresetList() {
    const locKey = locationSelect.value;
    const detail = FLEXCON_LOCATION_DETAILS[locKey];
    if (!detail) return;

    const presets = detail.presets && detail.presets.length > 0
      ? detail.presets
      : [{
          name: "標準住所",
          company: detail.company,
          recipient: detail.recipient,
          postalCode: detail.postalCode,
          address: detail.address,
          tel: detail.tel
        }];

    addressPresetSelect.innerHTML = presets.map((p, idx) => `<option value="${idx}">${p.name}</option>`).join('')
      + `<option value="custom">✏️ 自由入力・直接編集</option>`;

    applyAddressPreset(presets[0]);
    renderRecipientQuickTags();
  }

  // 納品先担当者のクイックタグ描画（ワンクリックで担当者名をセット）
  function renderRecipientQuickTags() {
    const locKey = locationSelect.value;
    const detail = FLEXCON_LOCATION_DETAILS[locKey];
    const tagsContainer = document.getElementById('recipientQuickTags');
    if (!tagsContainer) return;

    const contacts = (detail && detail.contacts && detail.contacts.length > 0)
      ? detail.contacts
      : ['ご担当者様'];

    let html = '';
    contacts.forEach(c => {
      html += `<button type="button" class="btn-rec-tag" data-val="${c}" style="border: 1px solid var(--border-medium); background: var(--bg-primary); font-size: 10px; padding: 1px 6px; border-radius: 4px; cursor: pointer; color: var(--accent-blue); font-weight: 600;">${c}</button>`;
    });
    html += `<button type="button" class="btn-rec-tag" data-val="" style="border: 1px solid var(--border-subtle); background: var(--bg-primary); font-size: 10px; padding: 1px 5px; border-radius: 4px; cursor: pointer; color: #ef4444;" title="担当者をクリアして会社宛にする">✕なし</button>`;
    tagsContainer.innerHTML = html;

    tagsContainer.querySelectorAll('.btn-rec-tag').forEach(b => {
      b.addEventListener('click', (e) => {
        e.preventDefault();
        deliveryRecipientInput.value = b.dataset.val;
      });
    });
  }

  locationSelect.addEventListener('change', updateAddressPresetList);

  addressPresetSelect.addEventListener('change', () => {
    const val = addressPresetSelect.value;
    if (val === 'custom') {
      deliveryAddressInput.focus();
      return;
    }
    const locKey = locationSelect.value;
    const detail = FLEXCON_LOCATION_DETAILS[locKey];
    if (detail && detail.presets && detail.presets[val]) {
      applyAddressPreset(detail.presets[val]);
    }
  });

  // 初期住所セット＆クイックタグ初期化
  updateAddressPresetList();

  function updateOrderTotals() {
    let subtotal = 0;
    rowsContainer.querySelectorAll('.po-item-row-card').forEach(row => {
      const q = parseInt(row.querySelector('.row-item-qty').value) || 0;
      const p = parseFloat(row.querySelector('.row-item-price').value) || 0;
      const rowAmt = Math.round(q * p);
      row.querySelector('.row-item-subtotal').textContent = `¥${rowAmt.toLocaleString()}`;
      subtotal += rowAmt;
    });
    const tax = Math.round(subtotal * 0.10);
    const total = subtotal + tax;
    document.getElementById('mPoSubtotal').textContent = `¥${subtotal.toLocaleString()}`;
    document.getElementById('mPoTax').textContent = `¥${tax.toLocaleString()}`;
    document.getElementById('mPoTotal').textContent = `¥${total.toLocaleString()}`;
  }

  function updateRowBadgesAndButtons() {
    const rows = rowsContainer.querySelectorAll('.po-item-row-card');
    rows.forEach((row, idx) => {
      const badge = row.querySelector('.row-num-badge');
      if (badge) badge.textContent = `品目 #${idx + 1}`;
      const delBtn = row.querySelector('.btn-remove-po-item');
      if (delBtn) delBtn.style.display = rows.length > 1 ? 'inline-flex' : 'none';
    });
  }

  function addPoItemRow(defaultData = {}) {
    const row = document.createElement('div');
    row.className = 'po-item-row-card';
    row.style.cssText = 'background: var(--bg-card); border: 1px solid var(--border-medium); border-radius: 8px; padding: 12px 14px; position: relative;';

    const selectedItemId = defaultData.item || (FLEXCON_ITEMS[0] ? FLEXCON_ITEMS[0].id : 'SNS-1');
    const defItem = FLEXCON_ITEMS.find(i => i.id === selectedItemId);
    const itemName = defaultData.name || defaultData.customName || (defItem ? defItem.name : (defaultData.item || 'フレコンワンウェイバッグSNS-1 上下全開タイプφ1100×1200'));
    const itemSpec = defaultData.spec || defaultData.customSpec || (defItem ? (defItem.spec || '') : '');
    const price = defaultData.price !== undefined ? defaultData.price : (defItem ? defItem.defaultPrice : 1000);
    const qty = defaultData.qty !== undefined ? defaultData.qty : 150;
    const quoteNo = defaultData.quoteNo || '';

    row.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <span class="row-num-badge" style="font-size: 11.5px; font-weight: 800; color: var(--accent-blue); background: rgba(37,99,235,0.08); padding: 2px 8px; border-radius: 4px;">
          品目
        </span>
        <button type="button" class="btn-remove-po-item" style="background: none; border: none; color: #ef4444; font-size: 12px; font-weight: 700; cursor: pointer; display: none; align-items: center; gap: 2px;">
          ✕ 削除
        </button>
      </div>

      <div style="margin-bottom: 8px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; flex-wrap: wrap; gap: 4px;">
          <label style="font-size: 11.5px; font-weight: 700; color: var(--text-secondary); margin: 0;">
            品名・商品名（直接自由入力・編集可能） <span style="color:#ef4444;">*</span>
          </label>
          <div style="display: flex; gap: 4px; align-items: center;">
            <span style="font-size: 10.5px; color: var(--text-muted);">マスタから引用:</span>
            <select class="row-item-select" style="font-size: 11px; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border-medium); background: var(--bg-card); color: var(--text-primary); max-width: 250px;">
              <option value="">-- 定型マスタから選ぶ --</option>
              ${FLEXCON_ITEMS.map(i => `
                <option value="${i.id}" ${i.id === selectedItemId ? 'selected' : ''}>【${i.commonName}】 ${i.name} (¥${i.defaultPrice})</option>
              `).join('')}
            </select>
            <button type="button" class="btn-clear-item-name" style="border: 1px solid var(--border-subtle); background: var(--bg-card); font-size: 10.5px; padding: 2px 6px; border-radius: 4px; cursor: pointer; color: #ef4444;" title="品名欄を空にして手入力">✕ 空白</button>
          </div>
        </div>
        <input type="text" class="row-item-name-input" value="${itemName}" placeholder="例: フレコンワンウェイバッグSNS-1 上下全開タイプ（自由に入力・編集できます）" required style="width: 100%; font-size: 13px; font-weight: 600; padding: 7px 10px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-primary); color: var(--text-primary); box-sizing: border-box;">
        <div style="margin-top: 4px;">
          <input type="text" class="row-item-spec-input" value="${itemSpec}" placeholder="仕様・規格・サイズ（例: φ1100×1200 / 反転ベルト付）（任意）" style="width: 100%; font-size: 11.5px; padding: 5px 8px; border-radius: 4px; border: 1px solid var(--border-subtle); background: var(--bg-card); color: var(--text-secondary); box-sizing: border-box;">
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 1.2fr 1.2fr 1.6fr auto; gap: 10px; align-items: flex-end;">
        <div>
          <label style="font-size: 11px; color: var(--text-secondary); display: block; margin-bottom: 2px;">発注枚数 <span style="color:#ef4444;">*</span></label>
          <input type="number" class="row-item-qty" min="1" max="99999" value="${qty}" required style="width: 100%; font-size: 13.5px; font-weight: 700; padding: 6px 8px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-primary); color: var(--text-primary); box-sizing: border-box;">
        </div>
        <div>
          <label style="font-size: 11px; color: var(--text-secondary); display: block; margin-bottom: 2px;">発注単価 (税別円) <span style="color:#ef4444;">*</span></label>
          <input type="number" class="row-item-price" min="0" step="0.1" value="${price}" required style="width: 100%; font-size: 13.5px; font-weight: 700; padding: 6px 8px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-primary); color: var(--text-primary); box-sizing: border-box;">
        </div>
        <div>
          <label style="font-size: 11px; color: var(--text-secondary); display: block; margin-bottom: 2px;">見積書No (任意)</label>
          <input type="text" class="row-item-quote" placeholder="例: 見積書No.23922" value="${quoteNo}" style="width: 100%; font-size: 12px; padding: 6px 8px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-primary); color: var(--text-primary); box-sizing: border-box;">
        </div>
        <div style="text-align: right; min-width: 85px; padding-bottom: 6px;">
          <span style="font-size: 10.5px; color: var(--text-muted); display: block;">小計(税別)</span>
          <strong class="row-item-subtotal" style="font-size: 13.5px; color: var(--accent-blue);">¥${Math.round(qty * price).toLocaleString()}</strong>
        </div>
      </div>
    `;

    const itemSelect = row.querySelector('.row-item-select');
    const nameInput = row.querySelector('.row-item-name-input');
    const specInput = row.querySelector('.row-item-spec-input');
    const clearBtn = row.querySelector('.btn-clear-item-name');
    const priceInput = row.querySelector('.row-item-price');
    const qtyInput = row.querySelector('.row-item-qty');
    const delBtn = row.querySelector('.btn-remove-po-item');

    itemSelect.addEventListener('change', () => {
      if (!itemSelect.value) return;
      const found = FLEXCON_ITEMS.find(i => i.id === itemSelect.value);
      if (found) {
        nameInput.value = found.name;
        specInput.value = found.spec || '';
        priceInput.value = found.defaultPrice;
        updateOrderTotals();
      }
    });

    clearBtn.addEventListener('click', () => {
      nameInput.value = '';
      specInput.value = '';
      itemSelect.value = '';
      nameInput.focus();
    });

    qtyInput.addEventListener('input', updateOrderTotals);
    priceInput.addEventListener('input', updateOrderTotals);

    delBtn.addEventListener('click', () => {
      row.remove();
      updateRowBadgesAndButtons();
      updateOrderTotals();
    });

    rowsContainer.appendChild(row);
    updateRowBadgesAndButtons();
    updateOrderTotals();
  }

  // 初期行として1件追加
  addPoItemRow({
    item: FLEXCON_ITEMS[0].id,
    qty: 150,
    price: FLEXCON_ITEMS[0].defaultPrice,
    quoteNo: ''
  });

  // 「品目を追加」ボタン
  document.getElementById('btnAddPoItemRow').addEventListener('click', () => {
    addPoItemRow({
      item: FLEXCON_ITEMS[1] ? FLEXCON_ITEMS[1].id : FLEXCON_ITEMS[0].id,
      qty: 100,
      price: FLEXCON_ITEMS[1] ? FLEXCON_ITEMS[1].defaultPrice : 1000,
      quoteNo: ''
    });
  });

  // 仕入先切替時の担当者連動
  supplierSelect.addEventListener('change', () => {
    const sup = FLEXCON_SUPPLIERS.find(s => s.name === supplierSelect.value);
    if (sup && sup.contactPerson) {
      supplierContactInput.value = sup.contactPerson;
    }
  });

  // 納品希望日変更時に出荷月注記を自動更新（ユーザーが意図して空白にした場合は上書きしない）
  dueDateInput.addEventListener('change', () => {
    if (dueDateInput.value && dueMonthNoteInput.dataset.userCleared !== 'true') {
      const parts = dueDateInput.value.split('-');
      if (parts.length === 3) {
        const m = parseInt(parts[1], 10);
        dueMonthNoteInput.value = `※出荷（計上）も${m}月でお願いいたします。`;
      }
    }
  });

  // フォームデータから発注オブジェクトを生成する共通ヘルパー
  const getFormDataTx = (forPreview = false) => {
    const items = [];
    rowsContainer.querySelectorAll('.po-item-row-card').forEach(row => {
      const nameVal = row.querySelector('.row-item-name-input').value.trim();
      const specVal = row.querySelector('.row-item-spec-input').value.trim();
      const selVal = row.querySelector('.row-item-select').value;
      const q = parseInt(row.querySelector('.row-item-qty').value) || 0;
      const p = parseFloat(row.querySelector('.row-item-price').value) || 0;
      const quote = row.querySelector('.row-item-quote').value || '';

      const matched = FLEXCON_ITEMS.find(i => (selVal && i.id === selVal) || i.name === nameVal);
      const itemId = matched ? matched.id : 'CUSTOM';
      const finalName = nameVal || (matched ? matched.name : '資材・商品');

      items.push({
        item: itemId,
        name: finalName,
        spec: specVal,
        customName: finalName,
        customSpec: specVal,
        qty: q,
        price: p,
        quoteNo: quote
      });
    });

    if (items.length === 0) {
      alert("発注明細を1品目以上指定してください。");
      return null;
    }

    const totalQty = items.reduce((sum, it) => sum + it.qty, 0);
    const primaryItem = items[0].item;
    const primaryPrice = items[0].price;

    const deliveryInfo = {
      company: deliveryCompanyInput.value.trim(),
      recipient: deliveryRecipientInput.value.trim(),
      postalCode: deliveryPostalInput.value.trim(),
      address: deliveryAddressInput.value.trim(),
      tel: deliveryTelInput.value.trim()
    };

    return {
      id: forPreview ? ("PO-PREVIEW-" + Date.now().toString().slice(-4)) : ("TX-" + Date.now().toString().slice(-6)),
      date: document.getElementById('mPoDate').value,
      orderDate: document.getElementById('mPoDate').value,
      deliveryDueDate: document.getElementById('mPoDueDate').value,
      isEarliestDelivery: isEarliestCheckbox.checked,
      dueMonthNote: dueMonthNoteInput.value,
      type: "inbound",
      status: "ordered", // 未納品フラグ
      location: document.getElementById('mPoLocation').value,
      // 納品先詳細情報（手入力・プリセット変更に対応）
      deliveryInfo: deliveryInfo,
      // 複数品目データ
      items: items,
      // 既存コードとの後方互換性
      item: primaryItem,
      qty: totalQty,
      price: primaryPrice,
      supplier: document.getElementById('mPoSupplier').value,
      supplierContact: supplierContactInput.value,
      ourContact: document.getElementById('mPoOurContact').value,
      quoteNo: items[0].quoteNo || '',
      orderNo: document.getElementById('mPoNo').value.trim(),
      purpose: "",
      note: document.getElementById('mPoNote').value
    };
  };

  // 発注登録実行処理
  const registerOrder = (txToSave) => {
    data.transactions.push(txToSave);
    saveFlexconData(data);
    closeModal();
    // プレビューモーダルが開いていれば閉じる
    const poContainer = document.getElementById('purchaseOrderModalContainer');
    if (poContainer) poContainer.innerHTML = '';

    showToast("✨ 発注データを登録しました（発注台帳に反映されました）");
    renderFlexconInventory();
    // 登録後の確定発注書モーダルを表示
    openPurchaseOrderModal(txToSave, { isPreview: false });
  };

  // 「👁️ 発注書プレビュー」ボタン押下時（発注登録は行わずプレビュー表示のみ）
  document.getElementById('btnPreviewOrderModal').addEventListener('click', () => {
    const form = document.getElementById('modalOrderForm');
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }
    const previewTx = getFormDataTx(true);
    if (!previewTx) return;

    openPurchaseOrderModal(previewTx, {
      isPreview: true,
      onConfirmRegister: () => {
        // プレビュー画面からそのまま確定登録を実行
        const finalTx = getFormDataTx(false);
        if (finalTx) {
          registerOrder(finalTx);
        }
      }
    });
  });

  // 「✅ 発注登録する」送信時（プレビューなしで直接登録）
  document.getElementById('modalOrderForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const newTx = getFormDataTx(false);
    if (!newTx) return;
    registerOrder(newTx);
  });
}

// 発注書HTML生成ヘルパー（印刷用独立ドキュメントおよびモーダル内で共有）
function generatePurchaseOrderHtml(tx, forStandalone = false) {
  const rawItems = (tx.items && Array.isArray(tx.items) && tx.items.length > 0)
    ? tx.items
    : [{ item: tx.item, qty: tx.qty, price: tx.price, quoteNo: tx.quoteNo || '' }];

  const locDetail = tx.deliveryInfo || FLEXCON_LOCATION_DETAILS[tx.location] || {
    company: tx.location,
    recipient: "ご担当者様",
    postalCode: "",
    address: "",
    tel: ""
  };

  let subtotal = 0;
  const itemRowsHtml = rawItems.map(it => {
    let title = '';
    let spec = '';
    if (it.name || it.customName) {
      title = it.name || it.customName;
      spec = it.spec || it.customSpec || '';
    } else {
      const found = FLEXCON_ITEMS.find(i => i.id === it.item);
      title = found ? found.name.split('　')[0].split(' (')[0] : (it.item || 'フレコン');
      spec = found ? (found.spec || found.name) : '';
    }
    const q = it.qty || 0;
    const p = it.price || 0;
    const lineTotal = Math.round(q * p);
    subtotal += lineTotal;

    const quoteLine = it.quoteNo
      ? `<div class="po-item-quote">${it.quoteNo}</div>`
      : (tx.orderNo ? `<div class="po-item-quote">管理No: ${tx.orderNo}</div>` : '');

    return `
      <tr>
        <td class="cell-item-detail">
          <div class="po-item-title">${title}</div>
          ${spec ? `<div class="po-item-spec">${spec}</div>` : ''}
          ${quoteLine}
        </td>
        <td class="cell-qty">${q.toLocaleString()} <span class="po-unit">枚</span></td>
        <td class="cell-price">¥${p.toLocaleString()}</td>
        <td class="cell-amount">¥${lineTotal.toLocaleString()}</td>
      </tr>
    `;
  }).join('');

  const blankRowsCount = Math.max(0, 2 - rawItems.length);
  const blankRowsHtml = blankRowsCount > 0 ? `
    <tr class="blank-row">
      <td></td>
      <td></td>
      <td></td>
      <td></td>
    </tr>
  `.repeat(blankRowsCount) : '';

  const tax = Math.round(subtotal * 0.10);
  const total = subtotal + tax;

  const formatDateJa = (dateStr) => {
    if (!dateStr) return '';
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    return `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日`;
  };

  const formattedOrderDate = formatDateJa(tx.orderDate || tx.date);
  let formattedDueDate = '要相談';
  if (tx.isEarliestDelivery) {
    formattedDueDate = tx.deliveryDueDate
      ? `最短納期希望（目安: ～${formatDateJa(tx.deliveryDueDate)}頃）`
      : '最短納期希望';
  } else if (tx.deliveryDueDate) {
    formattedDueDate = `～${formatDateJa(tx.deliveryDueDate)}`;
  }
  const locRecipientStr = locDetail.recipient ? `（${locDetail.recipient}）` : '';
  const dueMonthNoteText = (tx.dueMonthNote !== undefined && tx.dueMonthNote !== null)
    ? tx.dueMonthNote.trim()
    : '※出荷（計上）も当月でお願いいたします。';

  const notes = [];
  if (tx.note && tx.note.trim()) {
    tx.note.split('\n').forEach(n => {
      const trimmed = n.trim();
      if (trimmed) {
        notes.push(trimmed.startsWith('・') ? trimmed : `・${trimmed}`);
      }
    });
  }

  const innerContent = `
    <div class="po-sheet-landscape" id="purchaseOrderPrintArea">
      <!-- 上部タイトル・日付 -->
      <div class="po-top-bar">
        <div class="po-title-frame">
          <h1 class="po-main-title">発　注　書</h1>
        </div>
        <div class="po-date-line">
          日付： <span class="po-date-val">${formattedOrderDate}</span>
        </div>
      </div>

      <!-- 宛先 ＆ 発注元企業情報 -->
      <div class="po-header-section">
        <div class="po-vendor-block">
          <div class="po-vendor-name">${tx.supplier}</div>
          <div class="po-vendor-attn">${tx.supplierContact || '太田 光一　様'}</div>
          <div class="po-greeting">いつもお世話になっております。<br>下記の通り、発注致します。</div>
        </div>

        <div class="po-issuer-block">
          <div class="po-issuer-logo-group">
            <span class="po-issuer-logo-mark">🌿</span>
            <span class="po-issuer-company">CASCADIA TRADING, INC.</span>
          </div>
          <div class="po-issuer-office">【本社】</div>
          <div class="po-issuer-postal">〒330-0063</div>
          <div class="po-issuer-address">埼玉県さいたま市浦和区高砂2-11-13</div>
          <div class="po-issuer-tel">TEL:048-762-9340 FAX:048-762-9360</div>
          <div class="po-issuer-staff">担当： ${tx.ourContact || '畑山'}</div>
        </div>
      </div>

      <!-- 明細テーブル（現行様式再現） -->
      <table class="po-actual-table">
        <thead>
          <tr>
            <th class="col-item-name">商品名</th>
            <th class="col-qty">数量</th>
            <th class="col-price">単価（税別）</th>
            <th class="col-amount">小計</th>
          </tr>
        </thead>
        <tbody>
          ${itemRowsHtml}
          ${blankRowsHtml}
        </tbody>
        <tfoot>
          <tr>
            <td colspan="2" class="total-empty"></td>
            <td class="total-label">合　計</td>
            <td class="total-val">¥${subtotal.toLocaleString()}</td>
          </tr>
          <tr>
            <td colspan="2" class="total-empty"></td>
            <td class="total-label">消費税（１０％）</td>
            <td class="total-val">¥${tax.toLocaleString()}</td>
          </tr>
          <tr class="grand-total-row">
            <td colspan="2" class="total-empty"></td>
            <td class="total-label grand-label">合計（税込）</td>
            <td class="total-val grand-val">¥${total.toLocaleString()}</td>
          </tr>
        </tfoot>
      </table>

      <!-- 下部情報：納品先/配送先 ＆ 納品希望日 ＆ 備考 -->
      <div class="po-bottom-grid">
        <div class="po-bottom-col delivery-col">
          <div class="po-block-title">【納品先/配送先】</div>
          <div class="po-dest-company">${locDetail.company}</div>
          ${locDetail.recipient ? `<div class="po-dest-recipient" style="font-size: 12px; font-weight: 800; color: #1e3a8a; margin: 2px 0 3px 0;">受取担当： ${locDetail.recipient}</div>` : ''}
          ${locDetail.postalCode ? `<div class="po-dest-postal">${locDetail.postalCode}</div>` : ''}
          ${locDetail.address ? `<div class="po-dest-address">${locDetail.address}</div>` : ''}
          ${locDetail.tel ? `<div class="po-dest-tel">TEL : ${locDetail.tel}</div>` : ''}
        </div>

        <div class="po-bottom-col duedate-col">
          <div class="po-block-title">【納品希望日】</div>
          <div class="po-duedate-box">
            <div class="po-duedate-val">${formattedDueDate}</div>
            ${dueMonthNoteText ? `<div class="po-duedate-note">${dueMonthNoteText}</div>` : ''}
          </div>
        </div>
      </div>

      <!-- 備考欄 -->
      <div class="po-notes-section">
        <div class="po-block-title">【備考欄】</div>
        <div class="po-notes-content">
          ${notes.map(n => `<div>${n}</div>`).join('')}
        </div>
      </div>

      <!-- 印鑑欄 -->
      <div class="po-stamp-row">
        <div class="po-stamp-box">
          <div class="po-stamp-label">承認</div>
          <div class="po-stamp-circle"></div>
        </div>
        <div class="po-stamp-box">
          <div class="po-stamp-label">担当</div>
          <div class="po-stamp-circle">
            <span style="font-size: 11px; color: #dc2626; font-weight: bold;">${tx.ourContact ? tx.ourContact.charAt(0) : '畑'}</span>
          </div>
        </div>
      </div>
    </div>
  `;

  if (!forStandalone) return innerContent;

  // 印刷専用のスタンドアロン完全HTML（親画面のスタイル干渉を完全排除）
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>発注書_${tx.orderNo || tx.id}_${tx.supplier}</title>
  <style>
    @page {
      size: A4 landscape;
      margin: 12mm 12mm 8mm 12mm;
    }
    * {
      box-sizing: border-box;
      -webkit-print-color-adjust: exact !important;
      print-color-adjust: exact !important;
    }
    body {
      margin: 0;
      padding: 16px;
      background: #f8fafc;
      font-family: "Hiragino Kaku Gothic ProN", "Yu Gothic", Meiryo, sans-serif;
      color: #111827;
      line-height: 1.4;
    }
    .po-standalone-bar {
      max-width: 1000px;
      margin: 0 auto 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #ffffff;
      padding: 10px 18px;
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .po-sheet-landscape {
      max-width: 1000px;
      margin: 0 auto;
      background: #ffffff;
      padding: 20px 28px;
      border-radius: 4px;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.08);
      page-break-inside: avoid;
      break-inside: avoid;
    }
    .po-top-bar {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      position: relative;
      min-height: 44px;
      margin-bottom: 14px;
    }
    .po-title-frame {
      position: absolute;
      left: 50%;
      top: 50%;
      transform: translate(-50%, -50%);
      border: 1.5px solid #111827;
      border-radius: 4px;
      padding: 4px 32px;
      background: #ffffff;
      box-sizing: border-box;
    }
    .po-main-title {
      font-size: 20px;
      font-weight: 800;
      letter-spacing: 5px;
      margin: 0;
      color: #111827;
      text-align: center;
      line-height: 1.2;
    }
    .po-date-line { margin-left: auto; font-size: 12.5px; font-weight: 600; border-bottom: 1px solid #111827; padding-bottom: 2px; min-width: 170px; text-align: right; }
    .po-header-section { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; gap: 20px; }
    .po-vendor-name { font-size: 16px; font-weight: 800; margin-bottom: 3px; }
    .po-vendor-attn { font-size: 15px; font-weight: 800; border-bottom: 1.5px solid #111827; display: inline-block; padding-bottom: 2px; min-width: 220px; margin-bottom: 6px; }
    .po-greeting { font-size: 11.5px; color: #374151; line-height: 1.5; }
    .po-issuer-block { text-align: right; font-size: 11.5px; line-height: 1.45; }
    .po-issuer-logo-group { display: flex; align-items: center; justify-content: flex-end; gap: 6px; margin-bottom: 2px; }
    .po-issuer-company { font-size: 14.5px; font-weight: 900; letter-spacing: 0.5px; color: #0f172a; }
    .po-issuer-office { font-weight: 700; font-size: 11.5px; }
    .po-issuer-address { font-size: 11px; }
    .po-issuer-tel { font-size: 11px; font-weight: 600; }
    .po-issuer-staff { font-size: 12px; font-weight: 700; margin-top: 2px; }
    .po-actual-table { width: 100%; border-collapse: collapse; border: 1.5px solid #111827; margin-bottom: 10px; font-size: 12px; }
    .po-actual-table th { border: 1px solid #111827; padding: 5px 8px; background: #f8fafc; font-weight: 800; text-align: center; }
    .po-actual-table td { border: 1px solid #111827; padding: 6px 10px; vertical-align: middle; }
    .po-actual-table .col-item-name { width: 52%; }
    .po-actual-table .col-qty { width: 14%; }
    .po-actual-table .col-price { width: 17%; }
    .po-actual-table .col-amount { width: 17%; }
    .cell-item-detail { line-height: 1.4; }
    .po-item-title { font-weight: 800; font-size: 13px; color: #0f172a; }
    .po-item-spec { font-size: 11.5px; color: #334155; }
    .po-item-quote { font-size: 11px; color: #475569; margin-top: 2px; }
    .cell-qty { text-align: center; font-size: 13.5px; font-weight: 800; }
    .po-unit { font-size: 11.5px; font-weight: normal; margin-left: 2px; }
    .cell-price { text-align: right; font-size: 13px; }
    .cell-amount { text-align: right; font-size: 13.5px; font-weight: 800; }
    .blank-row td { height: 16px; padding: 0; border-top: none; border-bottom: 1px solid #111827; }
    .po-actual-table tfoot td { padding: 4px 10px; }
    .total-empty { border: none !important; border-right: 1px solid #111827 !important; background: transparent !important; }
    .total-label { text-align: center; font-weight: 700; background: #f8fafc; border: 1px solid #111827; }
    .total-val { text-align: right; font-weight: 700; border: 1px solid #111827; }
    .grand-total-row td { background: #f1f5f9; }
    .grand-label { font-weight: 800; font-size: 13px; }
    .grand-val { font-weight: 900; font-size: 14.5px; }
    .po-bottom-grid { display: grid; grid-template-columns: 1.2fr 0.8fr; border: 1.5px solid #111827; border-bottom: none; }
    .po-bottom-col { padding: 6px 10px; }
    .delivery-col { border-right: 1px solid #111827; }
    .po-block-title { font-weight: 800; font-size: 11.5px; margin-bottom: 4px; }
    .po-dest-company { font-size: 12.5px; font-weight: 800; margin-bottom: 2px; }
    .po-dest-postal, .po-dest-address, .po-dest-tel { font-size: 11px; line-height: 1.4; color: #1f2937; }
    .po-duedate-box { padding-top: 2px; }
    .po-duedate-val { font-size: 13.5px; font-weight: 800; margin-bottom: 3px; }
    .po-duedate-note { font-size: 11px; color: #4b5563; }
    .po-notes-section { border: 1.5px solid #111827; padding: 6px 10px; }
    .po-notes-content { font-size: 11px; line-height: 1.5; color: #1f2937; }
    .po-stamp-row { display: flex; justify-content: flex-end; gap: 8px; margin-top: 8px; }
    .po-stamp-box { border: 1px solid #6b7280; width: 48px; text-align: center; border-radius: 3px; }
    .po-stamp-label { font-size: 9.5px; color: #4b5563; border-bottom: 1px solid #6b7280; padding: 1px 0; background: #f9fafb; }
    .po-stamp-circle { height: 34px; display: flex; align-items: center; justify-content: center; }

    @media print {
      body { background: #ffffff !important; padding: 0 !important; margin: 0 !important; }
      .po-standalone-bar { display: none !important; }
      .po-sheet-landscape { box-shadow: none !important; border: none !important; padding: 4mm 0 0 0 !important; margin: 0 auto !important; max-width: 100% !important; width: 100% !important; }
    }
  </style>
</head>
<body>
  <div class="po-standalone-bar">
    <div style="font-weight: 700; font-size: 14px; color: #0f172a;">
      📄 発注書 印刷プレビュー (${tx.orderNo || tx.id})
    </div>
    <div style="display: flex; gap: 10px;">
      <button onclick="window.print();" style="background: #2563eb; color: #fff; border: none; padding: 8px 18px; border-radius: 6px; font-weight: 700; font-size: 13px; cursor: pointer;">
        🖨️ この発注書を印刷 / PDF保存
      </button>
      <button onclick="window.close();" style="background: #e2e8f0; color: #334155; border: none; padding: 8px 14px; border-radius: 6px; font-size: 13px; cursor: pointer;">
        ✕ 閉じる
      </button>
    </div>
  </div>
  ${innerContent}
</body>
</html>`;
}

// 印刷実行関数（非表示iframeを用いて親画面UIやモーダル背景の干渉を完全排除）
function printPurchaseOrder(tx) {
  const printHtml = generatePurchaseOrderHtml(tx, true);

  // 非表示の印刷用 iframe を作成または取得
  let printFrame = document.getElementById('poHiddenPrintIframe');
  if (!printFrame) {
    printFrame = document.createElement('iframe');
    printFrame.id = 'poHiddenPrintIframe';
    printFrame.style.position = 'fixed';
    printFrame.style.right = '0';
    printFrame.style.bottom = '0';
    printFrame.style.width = '0';
    printFrame.style.height = '0';
    printFrame.style.border = '0';
    printFrame.style.visibility = 'hidden';
    document.body.appendChild(printFrame);
  }

  const frameDoc = printFrame.contentWindow.document;
  frameDoc.open();
  frameDoc.write(printHtml);
  frameDoc.close();

  // iframe の読み込み完了後に印刷ダイアログを起動
  setTimeout(() => {
    try {
      printFrame.contentWindow.focus();
      printFrame.contentWindow.print();
    } catch (e) {
      console.warn("Direct iframe print failed, falling back to window.print():", e);
      window.print();
    }
  }, 250);
}

// 別タブで発注書を開く関数
function openPurchaseOrderInNewTab(tx, autoPrint = false) {
  const printHtml = generatePurchaseOrderHtml(tx, true);
  const newWin = window.open('', '_blank');
  if (newWin) {
    newWin.document.open();
    newWin.document.write(printHtml);
    newWin.document.close();
    if (autoPrint) {
      setTimeout(() => {
        try {
          newWin.focus();
          newWin.print();
        } catch(e) {}
      }, 300);
    }
  } else {
    alert("ポップアップがブロックされました。ブラウザの設定でポップアップを許可するか、直接「発注書を印刷 / PDF保存」ボタンをご利用ください。");
  }
}

// 3. 発注書モーダル表示関数（現行使用フォーマット・A4横印刷対応）
function openPurchaseOrderModal(tx, options = {}) {
  const isPreview = !!options.isPreview;
  const contentHtml = generatePurchaseOrderHtml(tx, false);

  const modalHtml = `
    <div class="flexcon-modal-overlay" id="purchaseOrderModal" style="z-index: 9999;">
      <div class="po-modal-wrapper" style="max-width: 1060px; width: 96%; max-height: 94vh; overflow-y: auto; padding: 22px 28px; background: #ffffff; border-radius: 14px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); border: 1px solid var(--border-medium);">
        
        <!-- 操作ボタンバー（印刷時は非表示） -->
        <div class="no-print" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid #e2e8f0; flex-wrap: wrap; gap: 10px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 18px;">📄</span>
            <strong style="font-size: 15px; color: #0f172a;">${isPreview ? '発注書 プレビュー確認（未登録）' : '発注書プレビュー（現行フォーマット・A4横印刷対応）'}</strong>
            <span style="font-size: 12px; background: ${isPreview ? '#fef3c7' : '#e0f2fe'}; color: ${isPreview ? '#92400e' : '#0369a1'}; padding: 2px 8px; border-radius: 4px; font-weight: 600;">
              ${isPreview ? '⚠️ プレビューモード (未確定)' : 'A4 Landscape'}
            </span>
          </div>
          <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
            ${isPreview ? `
              <button type="button" class="btn btn-secondary" id="btnBackToEditPoBtn" style="padding: 8px 14px; font-size: 13px; display: inline-flex; align-items: center; gap: 4px; cursor: pointer; border-color: #64748b; font-weight: 700; color: #334155; background: #f8fafc;" title="プレビューを閉じて入力・編集画面に戻ります">
                ✏️ 修正に戻る
              </button>
            ` : ''}
            <button type="button" class="btn btn-primary" id="btnPrintPoBtn" style="background: #2563eb; color: #fff; padding: 8px 18px; font-size: 13px; font-weight: 700; display: inline-flex; align-items: center; gap: 6px; cursor: pointer; box-shadow: 0 2px 4px rgba(37,99,235,0.2);">
              🖨️ 発注書を印刷 / PDF保存
            </button>
            <button type="button" class="btn btn-secondary" id="btnOpenNewTabPoBtn" style="padding: 8px 14px; font-size: 13px; display: inline-flex; align-items: center; gap: 4px; cursor: pointer;" title="新しいタブで発注書を開き、単独で印刷・保存します">
              ↗ 別タブで開く
            </button>
            ${isPreview ? `
              <button type="button" class="btn btn-primary" id="btnConfirmRegisterPoBtn" style="background: linear-gradient(135deg, #10b981, #059669); border-color: #059669; color: #fff; padding: 8px 18px; font-size: 13px; font-weight: 700; display: inline-flex; align-items: center; gap: 6px; cursor: pointer; box-shadow: 0 2px 4px rgba(16,185,129,0.25);" title="このプレビュー内容で発注を確定し、在庫システムに登録します">
                ✅ この内容で発注登録する
              </button>
            ` : ''}
            <button type="button" class="btn btn-secondary" id="btnClosePoModalBtn" style="padding: 8px 14px; font-size: 13px; cursor: pointer;">
              ✕ 閉じる
            </button>
          </div>
        </div>

        <!-- 印刷・PDF保存のガイドヒント -->
        <div class="no-print" style="background: ${isPreview ? '#fffbeb' : '#eff6ff'}; border: 1px solid ${isPreview ? '#fde68a' : '#bfdbfe'}; border-radius: 6px; padding: 8px 14px; margin-bottom: 16px; font-size: 12px; color: ${isPreview ? '#92400e' : '#1e40af'}; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
          <span>💡 <strong>${isPreview ? 'プレビュー中:' : '印刷・PDF保存のヒント:'}</strong> ${isPreview ? 'まだ発注データは確定・登録されていません。修正したい項目がある場合は「✏️ 修正に戻る」を押してください。内容に問題がなければ「✅ この内容で発注登録する」を押すと発注台帳および在庫システムに反映されます。' : '「🖨️ 発注書を印刷 / PDF保存」をクリックすると印刷ダイアログが開きます。送信先（プリンター）を「<strong>PDFに保存</strong>」に切り替えることで、メール送信用PDFとして保存できます。うまく動作しない場合は「<strong>別タブで開く</strong>」もお試しください。'}</span>
        </div>

        <!-- 発注書本体エリア -->
        ${contentHtml}

      </div>
    </div>
  `;

  const container = document.getElementById('purchaseOrderModalContainer');
  container.innerHTML = modalHtml;

  const closePoModal = () => {
    container.innerHTML = '';
    if (options.onClose) options.onClose();
  };

  document.getElementById('btnClosePoModalBtn').addEventListener('click', closePoModal);

  if (document.getElementById('btnBackToEditPoBtn')) {
    document.getElementById('btnBackToEditPoBtn').addEventListener('click', () => {
      container.innerHTML = '';
      if (options.onBackToEdit) options.onBackToEdit();
    });
  }

  if (document.getElementById('btnConfirmRegisterPoBtn')) {
    document.getElementById('btnConfirmRegisterPoBtn').addEventListener('click', () => {
      if (options.onConfirmRegister) {
        options.onConfirmRegister();
      }
    });
  }

  document.getElementById('purchaseOrderModal').addEventListener('click', (e) => {
    if (e.target.id === 'purchaseOrderModal') closePoModal();
  });

  document.getElementById('btnPrintPoBtn').addEventListener('click', () => {
    printPurchaseOrder(tx);
  });

  document.getElementById('btnOpenNewTabPoBtn').addEventListener('click', () => {
    openPurchaseOrderInNewTab(tx);
  });
}

// 4. 入庫（受入）登録モーダル
function openFlexconInboundModal(data) {
  const modalContainer = document.getElementById('flexconActionModalContainer');
  const today = new Date().toISOString().split('T')[0];

  modalContainer.innerHTML = `
    <div class="flexcon-modal-overlay" id="flexconInboundModalOverlay">
      <div class="flexcon-modal-box" style="max-width: 580px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 20px;">📥</span>
            <h3 style="margin: 0; font-size: 17px; font-weight: 800;">フレコン資材 直接入庫・受入登録</h3>
          </div>
          <button type="button" id="btnCloseInboundModal" style="background: none; border: none; font-size: 22px; cursor: pointer; color: var(--text-muted); line-height: 1;">✕</button>
        </div>

        <form id="modalInboundForm" class="tool-form">
          <div class="tool-group">
            <label for="mInDate">入庫受入日 <span style="color:#ef4444;">*</span></label>
            <input type="date" id="mInDate" value="${today}" required>
          </div>

          <div class="tool-group">
            <label for="mInLocation">納品先（保管場所） <span style="color:#ef4444;">*</span></label>
            <select id="mInLocation" required>
              ${FLEXCON_LOCATIONS.map(l => `<option value="${l}">${l}</option>`).join('')}
            </select>
          </div>

          <div class="tool-group">
            <label for="mInItem">品名（社内通称・型番） <span style="color:#ef4444;">*</span></label>
            <select id="mInItem" required style="width: 100%; text-overflow: ellipsis;">
              ${FLEXCON_ITEMS.map(i => `<option value="${i.id}">【${i.commonName}】 ${i.name} (基準単価: ¥${i.defaultPrice})</option>`).join('')}
            </select>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
            <div class="tool-group">
              <label for="mInQty">入庫枚数 <span style="color:#ef4444;">*</span></label>
              <input type="number" id="mInQty" min="1" max="99999" value="100" required>
            </div>
            <div class="tool-group">
              <label for="mInPrice">仕入単価（税抜円） <span style="color:#ef4444;">*</span></label>
              <input type="number" id="mInPrice" min="0" step="0.1" value="1150" required>
            </div>
          </div>

          <div class="tool-group">
            <label for="mInSupplier">仕入れ先メーカー・商社</label>
            <select id="mInSupplier">
              ${FLEXCON_SUPPLIERS.map(s => `<option value="${s.name}">${s.name}</option>`).join('')}
            </select>
          </div>

          <div class="tool-group">
            <label for="mInNote">備考・伝票Noなど</label>
            <input type="text" id="mInNote" placeholder="例: 納品伝票受領済">
          </div>

          <div style="background: var(--bg-primary); border: 1px solid var(--border-subtle); padding: 12px 16px; border-radius: 8px; margin-top: 12px; font-size: 13px; display: flex; justify-content: space-between; align-items: center;">
            <span>入庫小計金額:</span>
            <strong id="mInSubtotal" style="font-size: 18px; color: var(--accent-blue);">¥115,000</strong>
          </div>

          <div style="display: flex; gap: 10px; margin-top: 20px;">
            <button type="button" id="btnCancelInboundModal" class="btn btn-secondary" style="flex: 1; padding: 11px;">キャンセル</button>
            <button type="submit" class="btn btn-primary" style="flex: 2; padding: 11px; font-size: 14px;">📥 納品受入を登録（実在庫加算）</button>
          </div>
        </form>
      </div>
    </div>
  `;

  const closeModal = () => { modalContainer.innerHTML = ''; };
  document.getElementById('btnCloseInboundModal').addEventListener('click', closeModal);
  document.getElementById('btnCancelInboundModal').addEventListener('click', closeModal);
  document.getElementById('flexconInboundModalOverlay').addEventListener('click', (e) => {
    if (e.target.id === 'flexconInboundModalOverlay') closeModal();
  });

  const qtyIn = document.getElementById('mInQty');
  const priceIn = document.getElementById('mInPrice');
  const itemIn = document.getElementById('mInItem');

  function updateInSubtotal() {
    const qty = parseInt(qtyIn.value) || 0;
    const price = parseFloat(priceIn.value) || 0;
    document.getElementById('mInSubtotal').textContent = `¥${Math.round(qty * price).toLocaleString()}`;
  }

  itemIn.addEventListener('change', () => {
    const selectedItem = FLEXCON_ITEMS.find(i => i.id === itemIn.value);
    if (selectedItem) priceIn.value = selectedItem.defaultPrice;
    updateInSubtotal();
  });

  qtyIn.addEventListener('input', updateInSubtotal);
  priceIn.addEventListener('input', updateInSubtotal);

  document.getElementById('modalInboundForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const newTx = {
      id: "TX-" + Date.now().toString().slice(-6),
      date: document.getElementById('mInDate').value,
      type: "inbound",
      status: "delivered", // 即時実在庫
      location: document.getElementById('mInLocation').value,
      item: document.getElementById('mInItem').value,
      qty: parseInt(qtyIn.value),
      price: parseFloat(priceIn.value),
      supplier: document.getElementById('mInSupplier').value,
      purpose: "",
      note: document.getElementById('mInNote').value
    };

    data.transactions.push(newTx);
    saveFlexconData(data);
    closeModal();
    showToast("✨ 入庫データを正常に登録しました（実在庫加算）");
    renderFlexconInventory();
  });
}

// 5. 出庫（使用）登録モーダル
function openFlexconOutboundModal(data) {
  const modalContainer = document.getElementById('flexconActionModalContainer');
  const today = new Date().toISOString().split('T')[0];

  modalContainer.innerHTML = `
    <div class="flexcon-modal-overlay" id="flexconOutboundModalOverlay">
      <div class="flexcon-modal-box" style="max-width: 580px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 20px;">📤</span>
            <h3 style="margin: 0; font-size: 17px; font-weight: 800;">フレコン資材 出荷・使用登録</h3>
          </div>
          <button type="button" id="btnCloseOutboundModal" style="background: none; border: none; font-size: 22px; cursor: pointer; color: var(--text-muted); line-height: 1;">✕</button>
        </div>

        <form id="modalOutboundForm" class="tool-form">
          <div class="tool-group">
            <label for="mOutDate">出荷日 / 使用日 <span style="color:#ef4444;">*</span></label>
            <input type="date" id="mOutDate" value="${today}" required>
          </div>

          <div class="tool-group">
            <label for="mOutLocation">使用拠点（保管場所） <span style="color:#ef4444;">*</span></label>
            <select id="mOutLocation" required>
              ${FLEXCON_LOCATIONS.map(l => `<option value="${l}">${l}</option>`).join('')}
            </select>
          </div>

          <div class="tool-group">
            <label for="mOutItem">品名（社内通称・型番） <span style="color:#ef4444;">*</span></label>
            <select id="mOutItem" required style="width: 100%; text-overflow: ellipsis;">
              ${FLEXCON_ITEMS.map(i => `<option value="${i.id}">【${i.commonName}】 ${i.name}</option>`).join('')}
            </select>
          </div>

          <div class="tool-group">
            <label for="mOutQty">使用枚数 <span style="color:#ef4444;">*</span></label>
            <input type="number" id="mOutQty" min="1" max="99999" value="50" required>
          </div>

          <div class="tool-group">
            <label for="mOutPurpose">使用用途・充填製品 <span style="color:#ef4444;">*</span></label>
            <input type="text" id="mOutPurpose" placeholder="例: 牧草サイレージ製品充填、大豆粕パッキング出荷など" required>
          </div>

          <div class="tool-group">
            <label for="mOutNote">備考</label>
            <input type="text" id="mOutNote" placeholder="例: 担当〇〇作業">
          </div>

          <div style="display: flex; gap: 10px; margin-top: 20px;">
            <button type="button" id="btnCancelOutboundModal" class="btn btn-secondary" style="flex: 1; padding: 11px;">キャンセル</button>
            <button type="submit" class="btn btn-primary" style="flex: 2; padding: 11px; font-size: 14px; background: linear-gradient(135deg, var(--accent-violet), #9333ea);">📤 出庫データを登録する</button>
          </div>
        </form>
      </div>
    </div>
  `;

  const closeModal = () => { modalContainer.innerHTML = ''; };
  document.getElementById('btnCloseOutboundModal').addEventListener('click', closeModal);
  document.getElementById('btnCancelOutboundModal').addEventListener('click', closeModal);
  document.getElementById('flexconOutboundModalOverlay').addEventListener('click', (e) => {
    if (e.target.id === 'flexconOutboundModalOverlay') closeModal();
  });

  document.getElementById('modalOutboundForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const loc = document.getElementById('mOutLocation').value;
    const itemId = document.getElementById('mOutItem').value;
    const qty = parseInt(document.getElementById('mOutQty').value);

    // 在庫チェック
    const matrix = calculateStockMatrix(data.transactions);
    const available = matrix[loc][itemId] ? matrix[loc][itemId].qty : 0;
    const itemObj = FLEXCON_ITEMS.find(i => i.id === itemId);

    if (qty > available) {
      if (!confirm(`⚠️ 出庫警告: ${loc} にある ${itemObj ? itemObj.commonName : itemId} の現在の実在庫枚数は ${available} 枚です。\n要求枚数 (${qty} 枚) が現在庫を超過していますが、登録を続行しますか？`)) {
        return;
      }
    }

    const newTx = {
      id: "TX-" + Date.now().toString().slice(-6),
      date: document.getElementById('mOutDate').value,
      type: "outbound",
      status: "delivered",
      location: loc,
      item: itemId,
      qty: qty,
      price: matrix[loc][itemId] ? matrix[loc][itemId].lastPrice : 1000,
      supplier: "",
      purpose: document.getElementById('mOutPurpose').value,
      note: document.getElementById('mOutNote').value
    };

    data.transactions.push(newTx);
    saveFlexconData(data);
    closeModal();
    showToast("📤 出庫データを正常に登録しました");
    renderFlexconInventory();
  });
}

// 6. 入出庫全履歴帳簿（ソート＆保管場所フィルター対応）
function renderFlexconLedger(container, data) {
  const today = new Date().toISOString().split('T')[0];

  // 納品日ベースの年月リストを抽出（発注中は納品予定日、それ以外は取引日）
  const monthSet = new Set();
  data.transactions.forEach(t => {
    const dStr = (t.status === 'ordered' && t.deliveryDueDate) ? t.deliveryDueDate : t.date;
    if (dStr && dStr.length >= 7) {
      monthSet.add(dStr.slice(0, 7)); // 'YYYY-MM'
    }
  });
  const availableMonths = Array.from(monthSet).sort().reverse();

  // フィルタリング処理
  let filteredList = data.transactions.filter(tx => {
    if (ledgerFilterLoc !== 'all' && tx.location !== ledgerFilterLoc) return false;
    if (ledgerFilterType === 'ordered' && tx.status !== 'ordered') return false;
    if (ledgerFilterType === 'inbound' && (tx.type !== 'inbound' || tx.status === 'ordered')) return false;
    if (ledgerFilterType === 'outbound' && tx.type !== 'outbound') return false;
    if (ledgerFilterMonth !== 'all') {
      const targetDate = (tx.status === 'ordered' && tx.deliveryDueDate) ? tx.deliveryDueDate : tx.date;
      if (!targetDate || !targetDate.startsWith(ledgerFilterMonth)) return false;
    }
    return true;
  });

  // ソート処理（納品日/取引日 昇順 / 降順）
  filteredList.sort((a, b) => {
    const daStr = (a.status === 'ordered' && a.deliveryDueDate) ? a.deliveryDueDate : a.date;
    const dbStr = (b.status === 'ordered' && b.deliveryDueDate) ? b.deliveryDueDate : b.date;
    const da = new Date(daStr);
    const db = new Date(dbStr);
    return ledgerSortAsc ? (da - db) : (db - da);
  });

  container.innerHTML = `
    <div class="tool-card">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 16px;">
        <h3 style="margin: 0;">📋 入出庫全履歴トランザクション帳簿</h3>
        <button class="btn btn-secondary" id="btnResetFlexconData" style="font-size: 11px; color: #ef4444; border-color: rgba(239,68,68,0.3);">🔄 8月末初期データにリセット</button>
      </div>

      <!-- フィルター＆ソート コントロールバー -->
      <div style="background: var(--bg-primary); border: 1px solid var(--border-subtle); border-radius: 10px; padding: 12px 16px; margin-bottom: 16px; display: flex; gap: 14px; flex-wrap: wrap; align-items: center;">
        <div style="display: flex; align-items: center; gap: 6px;">
          <label for="ledgerFilterMonthSelect" style="font-size: 12px; font-weight: 700; color: var(--accent-blue);">📅 納品月:</label>
          <select id="ledgerFilterMonthSelect" style="padding: 4px 10px; font-size: 12px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-card); color: var(--text-primary); font-weight: 600;">
            <option value="all" ${ledgerFilterMonth === 'all' ? 'selected' : ''}>すべての年月（全期間）</option>
            ${availableMonths.map(m => {
              const [y, mo] = m.split('-');
              return `<option value="${m}" ${ledgerFilterMonth === m ? 'selected' : ''}>${y}年${parseInt(mo, 10)}月 納品分</option>`;
            }).join('')}
          </select>
        </div>

        <div style="display: flex; align-items: center; gap: 6px;">
          <label for="ledgerFilterLocSelect" style="font-size: 12px; font-weight: 700; color: var(--text-secondary);">🏢 保管場所:</label>
          <select id="ledgerFilterLocSelect" style="padding: 4px 10px; font-size: 12px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-card); color: var(--text-primary);">
            <option value="all" ${ledgerFilterLoc === 'all' ? 'selected' : ''}>すべての保管場所（全拠点）</option>
            ${FLEXCON_LOCATIONS.map(l => `<option value="${l}" ${ledgerFilterLoc === l ? 'selected' : ''}>${l}</option>`).join('')}
          </select>
        </div>

        <div style="display: flex; align-items: center; gap: 6px;">
          <label for="ledgerFilterTypeSelect" style="font-size: 12px; font-weight: 700; color: var(--text-secondary);">🏷️ 区分:</label>
          <select id="ledgerFilterTypeSelect" style="padding: 4px 10px; font-size: 12px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-card); color: var(--text-primary);">
            <option value="all" ${ledgerFilterType === 'all' ? 'selected' : ''}>すべての区分</option>
            <option value="ordered" ${ledgerFilterType === 'ordered' ? 'selected' : ''}>📝 未納品（発注中）のみ</option>
            <option value="inbound" ${ledgerFilterType === 'inbound' ? 'selected' : ''}>📥 入庫（納品済）のみ</option>
            <option value="outbound" ${ledgerFilterType === 'outbound' ? 'selected' : ''}>📤 出庫（使用）のみ</option>
          </select>
        </div>

        ${(ledgerFilterMonth !== 'all' || ledgerFilterLoc !== 'all' || ledgerFilterType !== 'all') ? `
          <button type="button" id="btnClearLedgerFilters" style="background: none; border: 1px solid var(--border-subtle); color: #ef4444; border-radius: 6px; padding: 4px 8px; font-size: 11px; cursor: pointer;" title="フィルターをすべて解除">
            ✕ 絞り込み解除
          </button>
        ` : ''}

        <div style="display: flex; align-items: center; gap: 6px; margin-left: auto;">
          <span style="font-size: 11.5px; color: var(--text-muted);">表示: <strong>${filteredList.length}</strong> 件</span>
          <button class="btn btn-secondary" id="btnToggleSort" style="padding: 5px 12px; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 4px;">
            <span>${ledgerSortAsc ? '⬆️ 日付: 古い順 (昇順)' : '⬇️ 日付: 新しい順 (降順)'}</span>
          </button>
        </div>
      </div>

      <div style="overflow-x: auto;">
        <table class="assistant-table" style="font-size: 12px; width: 100%; border-collapse: collapse;">
          <thead>
            <tr style="background: var(--bg-primary); text-align: left;">
              <th style="padding: 8px; cursor: pointer; user-select: none;" id="thDateSort" title="クリックで昇順・降順切替">
                日付（納品日） ${ledgerSortAsc ? '▲' : '▼'}
              </th>
              <th style="padding: 8px;">区分・状態</th>
              <th style="padding: 8px;">保管場所（拠点）</th>
              <th style="padding: 8px;">品名（社内通称 / 型番）</th>
              <th style="padding: 8px; text-align: right;">枚数</th>
              <th style="padding: 8px; text-align: right;">単価</th>
              <th style="padding: 8px; text-align: right;">小計金額</th>
              <th style="padding: 8px;">仕入先 / 発注日 / 用途</th>
              <th style="padding: 8px;">備考 / 発注No</th>
              <th style="padding: 8px; text-align: center; min-width: 110px;">操作</th>
            </tr>
          </thead>
          <tbody>
            ${filteredList.length === 0 ? `
              <tr>
                <td colspan="10" style="text-align: center; padding: 24px; color: var(--text-muted);">
                  条件に一致するトランザクションレコードはありません。
                </td>
              </tr>
            ` : filteredList.map(tx => {
              const itemObj = FLEXCON_ITEMS.find(i => i.id === tx.item);
              const isOrdered = tx.status === 'ordered';
              const isInbound = tx.type === 'inbound';
              const hasMultipleItems = tx.items && Array.isArray(tx.items) && tx.items.length > 1;
              const totalAmt = (tx.items && Array.isArray(tx.items) && tx.items.length > 0)
                ? tx.items.reduce((s, it) => s + (it.qty * (it.price || 0)), 0)
                : (tx.qty * (tx.price || 0));
              const totalQty = (tx.items && Array.isArray(tx.items) && tx.items.length > 0)
                ? tx.items.reduce((s, it) => s + (it.qty || 0), 0)
                : tx.qty;
              const isOverdue = isOrdered && tx.deliveryDueDate && tx.deliveryDueDate < today;
              const displayDate = isOrdered ? (tx.deliveryDueDate || tx.date) : tx.date;

              return `
                <tr style="${isOverdue ? 'background: rgba(239,68,68,0.04);' : (isOrdered ? 'background: rgba(245,158,11,0.03);' : '')}">
                  <td style="padding: 8px; font-weight: 600;">
                    <div>${displayDate}</div>
                    ${isOrdered && tx.isEarliestDelivery ? `
                      <span style="font-size: 10px; color: ${isOverdue ? '#ef4444' : 'var(--accent-blue)'}; font-weight: 700; display: block; line-height: 1.2;">
                        ⚡ 最短希望
                      </span>
                    ` : ''}
                  </td>
                  <td style="padding: 8px;">
                    ${isOrdered ? `
                      <span style="padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 700; ${isOverdue ? 'background: rgba(239,68,68,0.15); color: #ef4444;' : 'background: rgba(245,158,11,0.15); color: #f59e0b;'}">
                        ${isOverdue ? '⚠️ 納期超過' : '📝 未納品'}
                      </span>
                    ` : `
                      <span style="padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 700; ${isInbound ? 'background: rgba(37,99,235,0.1); color: var(--accent-blue);' : 'background: rgba(139,92,246,0.1); color: var(--accent-violet);'}">
                        ${isInbound ? '📥 入庫' : '📤 出庫'}
                      </span>
                    `}
                  </td>
                  <td style="padding: 8px;">
                    <div style="font-weight: 600;">${tx.location}</div>
                    ${tx.deliveryInfo && (tx.deliveryInfo.company || tx.deliveryInfo.address) ? `
                      <div style="font-size: 10.5px; color: var(--text-secondary); line-height: 1.25; margin-top: 2px;" title="${tx.deliveryInfo.postalCode || ''} ${tx.deliveryInfo.address || ''}">
                        🚚 ${tx.deliveryInfo.company || ''}${tx.deliveryInfo.recipient ? ` (${tx.deliveryInfo.recipient})` : ''}
                      </div>
                    ` : ''}
                  </td>
                  <td style="padding: 8px;">
                    ${hasMultipleItems ? `
                      <div style="display: flex; flex-direction: column; gap: 3px;">
                        <span style="font-size: 10px; background: rgba(37,99,235,0.12); color: var(--accent-blue); padding: 1px 6px; border-radius: 4px; display: inline-block; font-weight: 700; width: fit-content;">複数品目 (${tx.items.length}件)</span>
                        ${tx.items.map(it => {
                          const itObj = FLEXCON_ITEMS.find(i => i.id === it.item);
                          const name = it.name || it.customName || (itObj ? itObj.commonName : it.item);
                          return `<div style="font-size: 11.5px; font-weight: 600; line-height: 1.3;"><span style="color: var(--accent-blue);">・</span>${name} <span style="font-size: 10.5px; color: var(--text-muted); font-weight: normal;">(${it.qty}枚 @¥${(it.price || 0).toLocaleString()})</span></div>`;
                        }).join('')}
                      </div>
                    ` : `
                      <div style="font-weight: 700; color: var(--accent-blue);">【${(tx.items && tx.items[0] && (tx.items[0].name || tx.items[0].customName)) || (itemObj ? itemObj.commonName : tx.item)}】</div>
                      <div style="font-size: 10.5px; color: var(--text-muted);">${itemObj ? itemObj.id : ''}</div>
                    `}
                  </td>
                  <td style="padding: 8px; text-align: right; font-weight: 700; color: ${isOrdered ? '#f59e0b' : (isInbound ? 'var(--accent-blue)' : '#ef4444')};">
                    ${isInbound ? '+' : '-'}${totalQty.toLocaleString()} 枚
                  </td>
                  <td style="padding: 8px; text-align: right;">
                    ${hasMultipleItems ? '<span style="font-size: 11px; color: var(--text-muted);">（内訳参照）</span>' : `¥${(tx.price || 0).toLocaleString()}`}
                  </td>
                  <td style="padding: 8px; text-align: right; font-weight: 700;">¥${Math.round(totalAmt).toLocaleString()}</td>
                  <td style="padding: 8px;">
                    ${isOrdered ? `
                      <div style="font-weight: 600;">${tx.supplier || '-'}</div>
                      <div style="font-size: 11px; color: var(--text-muted); margin-top: 1px;">
                        発注日: ${tx.orderDate || tx.date}
                      </div>
                    ` : (tx.supplier || tx.purpose || '-')}
                  </td>
                  <td style="padding: 8px; color: var(--text-muted);">
                    <div>${tx.note || '-'}</div>
                    ${tx.orderNo ? `<div style="font-size: 10.5px; color: var(--text-secondary);">No: ${tx.orderNo}</div>` : ''}
                  </td>
                  <td style="padding: 6px 8px; text-align: center; white-space: nowrap;">
                    <div style="display: inline-flex; gap: 4px; justify-content: center; align-items: center;">
                      ${isOrdered ? `
                        <button class="btn btn-primary btn-ledger-deliver" data-id="${tx.id}" style="padding: 3px 8px; font-size: 11px; background: var(--accent-green); border-color: var(--accent-green); cursor: pointer;" title="納品完了にし実在庫に反映">
                          ✅ 受入
                        </button>
                      ` : ''}
                      ${isInbound ? `
                        <button class="btn btn-secondary btn-ledger-po" data-id="${tx.id}" style="padding: 4px 10px; font-size: 11.5px; display: inline-flex; align-items: center; gap: 3px; font-weight: 700; color: #1e3a8a; border-color: #93c5fd; background: #eff6ff; cursor: pointer;" title="現行様式 A4横 発注書プレビュー・印刷">
                          📄 発注書
                        </button>
                      ` : ''}
                      <button class="btn-delete-tx" data-id="${tx.id}" style="background: none; border: none; color: #ef4444; cursor: pointer; font-size: 14px; padding: 2px 4px;" title="削除">✕</button>
                    </div>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;

  // フィルター・ソートイベント
  document.getElementById('ledgerFilterMonthSelect').addEventListener('change', (e) => {
    ledgerFilterMonth = e.target.value;
    renderFlexconLedger(container, data);
  });

  document.getElementById('ledgerFilterLocSelect').addEventListener('change', (e) => {
    ledgerFilterLoc = e.target.value;
    renderFlexconLedger(container, data);
  });

  document.getElementById('ledgerFilterTypeSelect').addEventListener('change', (e) => {
    ledgerFilterType = e.target.value;
    renderFlexconLedger(container, data);
  });

  const clearBtn = document.getElementById('btnClearLedgerFilters');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      ledgerFilterMonth = 'all';
      ledgerFilterLoc = 'all';
      ledgerFilterType = 'all';
      renderFlexconLedger(container, data);
    });
  }

  const toggleSort = () => {
    ledgerSortAsc = !ledgerSortAsc;
    renderFlexconLedger(container, data);
  };

  document.getElementById('btnToggleSort').addEventListener('click', toggleSort);
  document.getElementById('thDateSort').addEventListener('click', toggleSort);

  // 納品受入ボタン
  container.querySelectorAll('.btn-ledger-deliver').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const button = e.currentTarget || e.target.closest('.btn-ledger-deliver');
      const id = button ? button.dataset.id : null;
      if (id) markOrderDelivered(id, data);
    });
  });

  // 発注書ボタン
  container.querySelectorAll('.btn-ledger-po').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const button = e.currentTarget || e.target.closest('.btn-ledger-po');
      const id = button ? button.dataset.id : null;
      const targetTx = data.transactions.find(t => t.id === id);
      if (targetTx) openPurchaseOrderModal(targetTx);
    });
  });

  // レコード削除
  container.querySelectorAll('.btn-delete-tx').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const button = e.currentTarget || e.target.closest('.btn-delete-tx');
      const id = button ? button.dataset.id : null;
      if (!id) return;
      if (confirm("このレコードを削除してもよろしいですか？")) {
        data.transactions = data.transactions.filter(t => t.id !== id);
        saveFlexconData(data);
        showToast("🗑️ レコードを削除しました");
        renderFlexconInventory();
      }
    });
  });

  // リセットボタン
  document.getElementById('btnResetFlexconData').addEventListener('click', () => {
    if (confirm("8月末の初期データ（上組 福岡支店: 1,933枚 / 138,210円）にリセットしますか？\n追加・変更されたトランザクションは消去されます。")) {
      localStorage.removeItem('cascadia_flexcon_inventory_v4');
      localStorage.removeItem('cascadia_flexcon_inventory_v3');
      localStorage.removeItem('cascadia_flexcon_inventory_v2');
      showToast("🔄 8月末仮運用データにリセットしました");
      renderFlexconInventory();
    }
  });
}

// 7. 月末棚卸し＆CSVエクスポート
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
              <th style="padding: 8px;">品名（社内通称 / 型番）</th>
              <th style="padding: 8px; text-align: right;">システム理論実在庫</th>
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
                    <td style="padding: 8px; font-weight: 600;">
                      <span style="color: var(--accent-blue);">【${item.commonName}】</span> ${item.name}
                    </td>
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
    let csv = "\uFEFF日付(納品日),区分,ステータス,保管場所,品名ID,品名通称,枚数,単価,金額,仕入先/用途,発注日,発注No,備考\n";
    data.transactions.forEach(tx => {
      const isOrdered = tx.status === 'ordered';
      const statusText = isOrdered ? '発注中(未納品)' : '納品完了';
      const typeText = tx.type === 'inbound' ? '入庫' : '出庫';
      const recordDate = (isOrdered && tx.deliveryDueDate) ? tx.deliveryDueDate : tx.date;
      const orderDateStr = isOrdered ? (tx.orderDate || tx.date) : '';

      if (tx.items && Array.isArray(tx.items) && tx.items.length > 0) {
        tx.items.forEach(it => {
          const itemObj = FLEXCON_ITEMS.find(i => i.id === it.item);
          const itemId = it.item;
          const common = it.item === 'CUSTOM' ? (it.customName || '特注品') : (itemObj ? itemObj.commonName : it.item);
          const q = it.qty || 0;
          const p = it.price || 0;
          const quote = it.quoteNo ? `[${it.quoteNo}] ` : '';
          const noteText = `${quote}${tx.note || ''}`.trim();
          csv += `"${recordDate}","${typeText}","${statusText}","${tx.location}","${itemId}","${common}",${q},${p},${Math.round(q * p)},"${tx.supplier || tx.purpose || ''}","${orderDateStr}","${tx.orderNo || ''}","${noteText}"\n`;
        });
      } else {
        const itemObj = FLEXCON_ITEMS.find(i => i.id === tx.item);
        const common = itemObj ? itemObj.commonName : '';
        csv += `"${recordDate}","${typeText}","${statusText}","${tx.location}","${tx.item}","${common}",${tx.qty},${tx.price || 0},${tx.qty * (tx.price || 0)},"${tx.supplier || tx.purpose || ''}","${orderDateStr}","${tx.orderNo || ''}","${tx.note || ''}"\n`;
      }
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
