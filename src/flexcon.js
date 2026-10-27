
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

// ===== マスター初期定義（2026年10月13日 畑山様提出マスター精査版） =====
const DEFAULT_FLEXCON_LOCATION_DETAILS = {
  "上組福岡支店 須崎倉庫": {
    company: "上組福岡支店 須崎倉庫",
    recipient: "営業１課　　祐谷様",
    contacts: ["営業１課　　祐谷様"],
    postalCode: "〒810-0071",
    address: "福岡県福岡市中央区那の津５丁目９−２３",
    tel: "092-752-5586",
    deliveryNote: "",
    itemStocks: {
      "フレコンSNS-1": 330
    },
    presets: [
      {
        name: "須崎倉庫（標準）",
        company: "上組福岡支店 須崎倉庫",
        recipient: "営業１課　　祐谷様",
        postalCode: "〒810-0071",
        address: "福岡県福岡市中央区那の津５丁目９−２３",
        tel: "092-752-5586"
      }
    ]
  },
  "上組福岡支店 須崎ふ頭東二号": {
    company: "上組福岡支店 須崎ふ頭東二号",
    recipient: "営業１課　　祐谷様",
    contacts: ["営業１課　　祐谷様"],
    postalCode: "〒810-0071",
    address: "福岡県福岡市中央区那の津５丁目１−１５",
    tel: "092-752-5586",
    deliveryNote: "",
    itemStocks: {
      "紙袋（ソイパス詰替用）": 1000
    },
    presets: [
      {
        name: "須崎ふ頭東二号（標準）",
        company: "上組福岡支店 須崎ふ頭東二号",
        recipient: "営業１課　　祐谷様",
        postalCode: "〒810-0071",
        address: "福岡県福岡市中央区那の津５丁目１−１５",
        tel: "092-752-5586"
      }
    ]
  },
  "シャイニー": {
    company: "シャイニー",
    recipient: "五十嵐様",
    contacts: ["五十嵐様", "受入ご担当者様"],
    postalCode: "",
    address: "五十嵐さんに要確認",
    tel: "",
    deliveryNote: "",
    itemStocks: {
      "フレコンSNS-1-PE（コンテナ直送）": 0,
      "フレコンSNS-1-PE（コンテナ分納）": 0
    },
    presets: [
      {
        name: "シャイニー工場（標準）",
        company: "シャイニー",
        recipient: "五十嵐様",
        postalCode: "",
        address: "五十嵐さんに要確認",
        tel: ""
      }
    ]
  },
  "青森黒石工場": {
    company: "青森黒石工場",
    recipient: "五十嵐工場長",
    contacts: ["五十嵐工場長"],
    postalCode: "〒036-0343",
    address: "青森県黒石市浅瀬石川合160-14",
    tel: "080-4009-7959",
    deliveryNote: "受入れは平日のみ",
    itemStocks: {
      "フレコンSNS-1": 0,
      "PE内袋": 0,
      "フレコンSNS-1-PE（コンテナ直送）": 0,
      "フレコンSNS-1-PE（コンテナ分納）": 0,
      "BTNR-1000C": 0,
      "BTNRL-1000C": 0
    },
    presets: [
      {
        name: "青森黒石工場（標準）",
        company: "青森黒石工場",
        recipient: "五十嵐工場長",
        postalCode: "〒036-0343",
        address: "青森県黒石市浅瀬石川合160-14",
        tel: "080-4009-7959"
      }
    ]
  },
  "熊本南関工場": {
    company: "熊本南関工場",
    recipient: "兼行工場長",
    contacts: ["兼行工場長"],
    postalCode: "〒861-0822",
    address: "熊本県玉名郡南関町上坂下723番地",
    tel: "0968-82-7288",
    deliveryNote: "受入れは平日のみ",
    itemStocks: {
      "フレコンSNS-1": 0,
      "PE内袋": 0,
      "フレコンSNS-1-PE（コンテナ直送）": 0,
      "フレコンSNS-1-PE（コンテナ分納）": 0,
      "BTNR-1000C": 0
    },
    presets: [
      {
        name: "熊本南関工場（標準）",
        company: "熊本南関工場",
        recipient: "兼行工場長",
        postalCode: "〒861-0822",
        address: "熊本県玉名郡南関町上坂下723番地",
        tel: "0968-82-7288"
      }
    ]
  },
  "中村商店（釘宮牧場）": {
    company: "中村商店（釘宮牧場）",
    recipient: "毛利様",
    contacts: ["毛利様", "受入ご担当者様"],
    postalCode: "",
    address: "毛利さんに要確認",
    tel: "",
    deliveryNote: "",
    itemStocks: {
      "フレコンSNS-1-PE（コンテナ直送）": 0,
      "フレコンSNS-1-PE（コンテナ分納）": 0
    },
    presets: [
      {
        name: "釘宮牧場 納品場所",
        company: "中村商店（釘宮牧場）",
        recipient: "毛利様",
        postalCode: "",
        address: "毛利さんに要確認",
        tel: ""
      }
    ]
  },
  "上組福岡　八代出張所　八代サイロ": {
    company: "上組福岡　八代出張所　八代サイロ",
    recipient: "小堀様",
    contacts: ["小堀様", "業務担当様"],
    postalCode: "〒866-0034",
    address: "熊本県八代市新港3-2-12",
    tel: "0965-37-3565",
    deliveryNote: "受入れは平日のみ",
    itemStocks: {
      "BTNR-1000C": 0
    },
    presets: [
      {
        name: "八代サイロ（標準）",
        company: "上組福岡　八代出張所　八代サイロ",
        recipient: "小堀様",
        postalCode: "〒866-0034",
        address: "熊本県八代市新港3-2-12",
        tel: "0965-37-3565"
      }
    ]
  },
  "シオヤ倉庫": {
    company: "シオヤ倉庫",
    recipient: "大原様",
    contacts: ["大原様（製造部）", "太田様（シオヤ）"],
    postalCode: "",
    address: "シオヤ　太田さんに確認必要",
    tel: "",
    deliveryNote: "",
    itemStocks: {
      "フレコンSNS-1-PE（コンテナ分納）": 0
    },
    presets: [
      {
        name: "シオヤ倉庫（標準）",
        company: "シオヤ倉庫",
        recipient: "大原様",
        postalCode: "",
        address: "シオヤ　太田さんに確認必要",
        tel: ""
      }
    ]
  },
  "井手運送有限会社　桜町営業所": {
    company: "井手運送有限会社　桜町営業所",
    recipient: "柳様",
    contacts: ["柳様"],
    postalCode: "〒841-0014",
    address: "佐賀県鳥栖市桜町1240-6",
    tel: "080-8381-6938",
    deliveryNote: "",
    itemStocks: {
      "フレコンSNS-1": 330,
      "PP袋（綿実詰替用）": 3000
    },
    presets: [
      {
        name: "桜町営業所（標準）",
        company: "井手運送有限会社　桜町営業所",
        recipient: "柳様",
        postalCode: "〒841-0014",
        address: "佐賀県鳥栖市桜町1240-6",
        tel: "080-8381-6938"
      }
    ]
  }
};

const DEFAULT_FLEXCON_ITEMS = [
  {
    id: "SOYPASS-BAG",
    commonName: "紙袋（ソイパス詰替用）",
    name: "ソイパス用紙袋 新印刷",
    spec: "813×419×76×3P",
    defaultPrice: 71.5,
    defaultSupplier: "佐藤産業株式会社",
    note: ""
  },
  {
    id: "SNS-1",
    commonName: "フレコンSNS-1",
    name: "フレコンワンウェイバッグSNS-1　上下全開タイプ",
    spec: "φ1100×1200",
    defaultPrice: 1150,
    defaultSupplier: "株式会社シオヤ",
    note: ""
  },
  {
    id: "SNS-1-PE-DIRECT",
    commonName: "フレコンSNS-1-PE（コンテナ直送）",
    name: "フレコンワンウェイバッグSNS-1-PE　上下全開タイプ",
    spec: "φ1100×1200　内袋入り",
    defaultPrice: 1380,
    defaultSupplier: "株式会社シオヤ",
    note: "直送分　9/8見積書"
  },
  {
    id: "SNS-1-PE-SPLIT",
    commonName: "フレコンSNS-1-PE（コンテナ分納）",
    name: "フレコンワンウェイバッグSNS-1-PE　上下全開タイプ",
    spec: "φ1100×1200　内袋入り",
    defaultPrice: 1460,
    defaultSupplier: "株式会社シオヤ",
    note: "分納分　9/8見積書"
  },
  {
    id: "BTNR-1000C",
    commonName: "BTNR-1000C",
    name: "フレコンワンウェイバッグBTNR-1000C",
    spec: "φ1100×1100",
    defaultPrice: 1000,
    defaultSupplier: "株式会社シオヤ",
    note: ""
  },
  {
    id: "BTNRL-1000C",
    commonName: "BTNRL-1000C",
    name: "フレコンワンウェイバッグBTNRL-1000C",
    spec: "φ1100×1100",
    defaultPrice: 950,
    defaultSupplier: "株式会社シオヤ",
    note: "2024年見積書"
  },
  {
    id: "PE-INNER",
    commonName: "PE内袋",
    name: "国産PE内袋",
    spec: "0.07×1850×3000",
    defaultPrice: 550,
    defaultSupplier: "株式会社シオヤ",
    note: ""
  },
    {
    id: "PP-BAG",
    commonName: "PP袋（綿実詰替用）",
    name: "PP袋（綿実詰替用・通常）",
    spec: "3000枚/束",
    defaultPrice: 34.8,
    defaultSupplier: "輸入分",
    note: "通常分（基準単価: 34.8円）"
  },
  {
    id: "PP-BAG-IMPORT",
    commonName: "PP袋（綿実詰替用・輸入分）",
    name: "PP袋（綿実詰替用・輸入分）",
    spec: "1000枚/束",
    defaultPrice: 28.7,
    defaultSupplier: "輸入分",
    note: "輸入分（基準単価: 28.7円）"
  },
  {
    id: "SNS-1-REPAIRED",
    commonName: "フレコンSNS-1(補修済)",
    name: "フレコンワンウェイバッグSNS-1　上下全開タイプ",
    spec: "φ1100×1200",
    defaultPrice: 0,
    defaultSupplier: "補修作業実施",
    note: ""
  }
];

const DEFAULT_FLEXCON_OPERATORS = [
  "畑山",
  "荒井",
  "祐谷",
  "五十嵐",
  "兼行",
  "小堀",
  "柳",
  "水谷"
];

const DEFAULT_FLEXCON_NOTE_PRESETS = [
  "定期便",
  "拠点間振替",
  "実棚調整（9月末確定）",
  "初期在庫",
  "破損・廃棄",
  "至急手配",
  "予備品確保",
  "その他特記"
];

const DEFAULT_FLEXCON_SUPPLIERS = [
  {
    name: "株式会社シオヤ",
    postalCode: "〒454-0027",
    address: "愛知県名古屋市中川区広川町５－１",
    tel: "052-351-0531",
    contactPerson: "太田様"
  },
  {
    name: "佐藤産業株式会社",
    postalCode: "〒891-0122",
    address: "鹿児島県鹿児島市南栄4丁目15-1",
    tel: "092-235-5990",
    contactPerson: "松元様"
  },
  {
    name: "輸入分",
    postalCode: "",
    address: "",
    tel: "",
    contactPerson: ""
  }
];

// マスター管理機能：ローカルストレージからカスタムマスターをロード（未保存時は初期定義）
function loadFlexconMaster() {
  const saved = localStorage.getItem('cascadia_flexcon_master_v6');
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      if (parsed && parsed.locations && parsed.items && parsed.suppliers) {
        if (!parsed.operators) parsed.operators = JSON.parse(JSON.stringify(DEFAULT_FLEXCON_OPERATORS));
        if (!parsed.notePresets) parsed.notePresets = JSON.parse(JSON.stringify(DEFAULT_FLEXCON_NOTE_PRESETS));
        return parsed;
      }
    } catch(e) {}
  }
  // v5からの移行
  const v5 = localStorage.getItem('cascadia_flexcon_master_v5');
  if (v5) {
    try {
      const parsed = JSON.parse(v5);
      if (parsed && parsed.locations && parsed.items && parsed.suppliers) {
        parsed.operators = parsed.operators || JSON.parse(JSON.stringify(DEFAULT_FLEXCON_OPERATORS));
        parsed.notePresets = parsed.notePresets || JSON.parse(JSON.stringify(DEFAULT_FLEXCON_NOTE_PRESETS));
        // PP-BAG-IMPORT が未登録なら追加
        if (!parsed.items.find(i => i.id === 'PP-BAG-IMPORT')) {
          parsed.items.push(DEFAULT_FLEXCON_ITEMS.find(i => i.id === 'PP-BAG-IMPORT'));
        }
        localStorage.setItem('cascadia_flexcon_master_v6', JSON.stringify(parsed));
        return parsed;
      }
    } catch(e) {}
  }
  const initMaster = {
    locations: JSON.parse(JSON.stringify(DEFAULT_FLEXCON_LOCATION_DETAILS)),
    items: JSON.parse(JSON.stringify(DEFAULT_FLEXCON_ITEMS)),
    suppliers: JSON.parse(JSON.stringify(DEFAULT_FLEXCON_SUPPLIERS)),
    operators: JSON.parse(JSON.stringify(DEFAULT_FLEXCON_OPERATORS)),
    notePresets: JSON.parse(JSON.stringify(DEFAULT_FLEXCON_NOTE_PRESETS))
  };
  localStorage.setItem('cascadia_flexcon_master_v6', JSON.stringify(initMaster));
  return initMaster;
}

function saveFlexconMaster(master, options = {}) {
  localStorage.setItem('cascadia_flexcon_master_v6', JSON.stringify(master));
  refreshActiveMaster();
  // マスター（拠点・商品・仕入先・担当者・備考）もクラウド共有し、全端末に反映
  if (!options.skipCloud && typeof pushFlexconMasterToCloud === 'function') {
    pushFlexconMasterToCloud(master);
  }
}

// 実行時マスター変数
let activeFlexconMaster = loadFlexconMaster();
let FLEXCON_LOCATION_DETAILS = activeFlexconMaster.locations;
let FLEXCON_LOCATIONS = Object.keys(FLEXCON_LOCATION_DETAILS);
let FLEXCON_ITEMS = activeFlexconMaster.items;
let FLEXCON_SUPPLIERS = activeFlexconMaster.suppliers;
let FLEXCON_OPERATORS = activeFlexconMaster.operators || JSON.parse(JSON.stringify(DEFAULT_FLEXCON_OPERATORS));
let FLEXCON_NOTE_PRESETS = activeFlexconMaster.notePresets || JSON.parse(JSON.stringify(DEFAULT_FLEXCON_NOTE_PRESETS));


// ===== 担当者・備考 共通セレクタ補助関数 =====
function renderOperatorSelectHtml(selectId, label = "入力担当者 / 業務担当", selectedVal = "畑山") {
  return `
    <div class="tool-group">
      <label for="${selectId}">${label} <span style="color:#ef4444;">*</span></label>
      <div style="display: flex; gap: 8px;">
        <select id="${selectId}" required style="flex: 1; font-weight: 600;">
          ${FLEXCON_OPERATORS.map(op => `<option value="${op}" ${op === selectedVal ? 'selected' : ''}>👤 ${op}</option>`).join('')}
          <option value="__custom__">➕ 新規担当者を入力...</option>
        </select>
        <input type="text" id="${selectId}_custom" placeholder="担当者名を入力" style="display: none; flex: 1; border: 1px solid var(--accent-blue); padding: 6px 10px; border-radius: 6px;">
      </div>
    </div>
  `;
}

function renderNoteSelectHtml(selectId, textId, defaultText = "") {
  return `
    <div class="tool-group">
      <label for="${selectId}">備考 <span style="font-size: 11px; color: var(--text-muted); font-weight: normal;">（定型マスター選択 または 自由入力）</span></label>
      <div style="display: flex; flex-direction: column; gap: 6px;">
        <select id="${selectId}" style="width: 100%;">
          <option value="">-- 定型備考マスターから選択（任意） --</option>
          ${FLEXCON_NOTE_PRESETS.map(n => `<option value="${n}">${n}</option>`).join('')}
        </select>
        <input type="text" id="${textId}" value="${defaultText}" placeholder="例: 定期便、9月末実棚確定、特記事項など">
      </div>
    </div>
  `;
}

function setupModalOperatorAndNote(selectOpId, selectNoteId, textNoteId) {
  const opSel = document.getElementById(selectOpId);
  const opCustom = document.getElementById(`${selectOpId}_custom`);
  if (opSel && opCustom) {
    opSel.addEventListener('change', () => {
      if (opSel.value === '__custom__') {
        opCustom.style.display = 'block';
        opCustom.focus();
      } else {
        opCustom.style.display = 'none';
      }
    });
  }

  const noteSel = document.getElementById(selectNoteId);
  const noteTxt = document.getElementById(textNoteId);
  if (noteSel && noteTxt) {
    noteSel.addEventListener('change', () => {
      if (noteSel.value) {
        if (!noteTxt.value) {
          noteTxt.value = noteSel.value;
        } else if (!noteTxt.value.includes(noteSel.value)) {
          noteTxt.value = `${noteSel.value} / ${noteTxt.value}`;
        }
      }
    });
  }
}

function getSelectedOperator(selectId) {
  const sel = document.getElementById(selectId);
  const custom = document.getElementById(`${selectId}_custom`);
  if (sel && sel.value === '__custom__' && custom && custom.value.trim()) {
    const newName = custom.value.trim();
    if (!FLEXCON_OPERATORS.includes(newName)) {
      FLEXCON_OPERATORS.push(newName);
      activeFlexconMaster.operators = FLEXCON_OPERATORS;
      saveFlexconMaster(activeFlexconMaster);
    }
    return newName;
  }
  return (sel && sel.value) ? sel.value : '畑山';
}

function refreshActiveMaster() {
  activeFlexconMaster = loadFlexconMaster();
  FLEXCON_LOCATION_DETAILS = activeFlexconMaster.locations;
  FLEXCON_LOCATIONS = Object.keys(FLEXCON_LOCATION_DETAILS);
  FLEXCON_ITEMS = activeFlexconMaster.items;
  FLEXCON_SUPPLIERS = activeFlexconMaster.suppliers;
  FLEXCON_OPERATORS = activeFlexconMaster.operators || JSON.parse(JSON.stringify(DEFAULT_FLEXCON_OPERATORS));
  FLEXCON_NOTE_PRESETS = activeFlexconMaster.notePresets || JSON.parse(JSON.stringify(DEFAULT_FLEXCON_NOTE_PRESETS));
}

// 安全在庫判定ヘルパー（提出資料仕様：拠点 × 取扱商品ごとの個別設定）
function getSafetyStock(location, item) {
  const locDetail = FLEXCON_LOCATION_DETAILS[location];
  if (!locDetail || !locDetail.itemStocks) return 0;

  let itemObj = typeof item === 'object' ? item : null;
  if (!itemObj && typeof item === 'string') {
    itemObj = FLEXCON_ITEMS.find(i => i.id === item || i.commonName === item);
  }

  const itemCommon = itemObj ? itemObj.commonName : (typeof item === 'string' ? item : '');
  const itemId = itemObj ? itemObj.id : (typeof item === 'string' ? item : '');

  if (locDetail.itemStocks[itemCommon] !== undefined) return Number(locDetail.itemStocks[itemCommon]) || 0;
  if (locDetail.itemStocks[itemId] !== undefined) return Number(locDetail.itemStocks[itemId]) || 0;
  for (const [k, v] of Object.entries(locDetail.itemStocks)) {
    if (k === itemCommon || k === itemId) return Number(v) || 0;
    if (itemCommon && itemCommon.includes('フレコンSNS-1-PE') && k.includes('フレコンSNS-1-PE')) {
      return Number(v) || 0;
    }
  }
  return 0;
}

// 2026年9月末確定在庫データ（畑山様ご提出『水谷様ご提出用_9月末在庫.xlsx』に基づく全21拠点/商品実棚確定反映）
const INITIAL_FLEXCON_DATA = {
  transactions: [
    {
        "id": "TX-INIT-0930-01",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "上組福岡支店 須崎倉庫",
        "item": "SNS-1",
        "qty": 34,
        "price": 1150.0,
        "supplier": "株式会社シオヤ",
        "supplierContact": "太田様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-01",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 34枚（単価: 1,150.0円）"
    },
    {
        "id": "TX-INIT-0930-02",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "上組福岡支店 須崎ふ頭東二号",
        "item": "SOYPASS-BAG",
        "qty": 1001,
        "price": 71.5,
        "supplier": "佐藤産業株式会社",
        "supplierContact": "松元様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-02",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 1,001枚（単価: 71.5円）"
    },
    {
        "id": "TX-INIT-0930-03",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "シャイニー",
        "item": "SNS-1-PE-SPLIT",
        "qty": 102,
        "price": 1460.0,
        "supplier": "株式会社シオヤ",
        "supplierContact": "太田様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-03",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 102枚（単価: 1,460.0円）"
    },
    {
        "id": "TX-INIT-0930-04",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "青森黒石工場",
        "item": "SNS-1",
        "qty": 60,
        "price": 1150.0,
        "supplier": "株式会社シオヤ",
        "supplierContact": "太田様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-04",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 60枚（単価: 1,150.0円）"
    },
    {
        "id": "TX-INIT-0930-05",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "青森黒石工場",
        "item": "SNS-1-PE-SPLIT",
        "qty": 180,
        "price": 1460.0,
        "supplier": "株式会社シオヤ",
        "supplierContact": "太田様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-05",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 180枚（単価: 1,460.0円）"
    },
    {
        "id": "TX-INIT-0930-06",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "青森黒石工場",
        "item": "BTNR-1000C",
        "qty": 60,
        "price": 1000.0,
        "supplier": "株式会社シオヤ",
        "supplierContact": "太田様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-06",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 60枚（単価: 1,000.0円）"
    },
    {
        "id": "TX-INIT-0930-07",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "青森黒石工場",
        "item": "BTNRL-1000C",
        "qty": 69,
        "price": 950.0,
        "supplier": "株式会社シオヤ",
        "supplierContact": "太田様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-07",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 69枚（単価: 950.0円）"
    },
    {
        "id": "TX-INIT-0930-08",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "熊本南関工場",
        "item": "SNS-1",
        "qty": 10,
        "price": 1150.0,
        "supplier": "株式会社シオヤ",
        "supplierContact": "太田様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-08",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 10枚（単価: 1,150.0円）"
    },
    {
        "id": "TX-INIT-0930-09",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "熊本南関工場",
        "item": "PE-INNER",
        "qty": 60,
        "price": 550.0,
        "supplier": "株式会社シオヤ",
        "supplierContact": "太田様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-09",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 60枚（単価: 550.0円）"
    },
    {
        "id": "TX-INIT-0930-10",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "熊本南関工場",
        "item": "SNS-1-PE-DIRECT",
        "qty": 1753,
        "price": 1380.0,
        "supplier": "株式会社シオヤ",
        "supplierContact": "太田様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-10",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 1,753枚（単価: 1,380.0円）"
    },
    {
        "id": "TX-INIT-0930-11",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "熊本南関工場",
        "item": "BTNR-1000C",
        "qty": 131,
        "price": 1000.0,
        "supplier": "株式会社シオヤ",
        "supplierContact": "太田様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-11",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 131枚（単価: 1,000.0円）"
    },
    {
        "id": "TX-INIT-0930-12",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "上組福岡　八代出張所　八代サイロ",
        "item": "BTNR-1000C",
        "qty": 10,
        "price": 1000.0,
        "supplier": "株式会社シオヤ",
        "supplierContact": "太田様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-12",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 10枚（単価: 1,000.0円）"
    },
    {
        "id": "TX-INIT-0930-13",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "井手運送有限会社　桜町営業所",
        "item": "SNS-1",
        "qty": 154,
        "price": 1150.0,
        "supplier": "株式会社シオヤ",
        "supplierContact": "太田様",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-13",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 154枚（単価: 1,150.0円）"
    },
    {
        "id": "TX-INIT-0930-14",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "井手運送有限会社　桜町営業所",
        "item": "SNS-1-REPAIRED",
        "qty": 45,
        "price": 0.0,
        "supplier": "補修作業実施",
        "supplierContact": "",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-14",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 45枚（単価: 0.0円）"
    },
    {
        "id": "TX-INIT-0930-15",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "井手運送有限会社　桜町営業所",
        "item": "PP-BAG",
        "qty": 50000,
        "price": 34.8,
        "supplier": "輸入分",
        "supplierContact": "",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-15",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 50,000枚（単価: 34.8円）"
    },
    {
        "id": "TX-INIT-0930-16",
        "date": "2026-09-30",
        "orderDate": "2026-09-30",
        "type": "inbound",
        "status": "delivered",
        "location": "井手運送有限会社　桜町営業所",
        "item": "PP-BAG-IMPORT",
        "qty": 1000,
        "price": 28.7,
        "supplier": "輸入分",
        "supplierContact": "",
        "ourContact": "畑山",
        "operator": "畑山",
        "quoteNo": "",
        "orderNo": "INIT-20260930-16",
        "purpose": "2026年9月末繰越残高（実棚確定）",
        "note": "2026年9月末時点の確定繰越在庫: 1,000枚（単価: 28.7円）"
    }
]
};

// --- FIREBASE CLOUD FIRESTORE REAL-TIME SYNC ---
const CASCADIA_FIREBASE_CONFIG = {
  apiKey: "AIzaSyDuRK-JlfLdnSW8RAUyptNk_BIx39U3Lns",
  authDomain: "cascadia-trading-flexcon.firebaseapp.com",
  projectId: "cascadia-trading-flexcon",
  storageBucket: "cascadia-trading-flexcon.firebasestorage.app",
  messagingSenderId: "913475294878",
  appId: "1:913475294878:web:d20f0d40154ab44e6d0d8f"
};

let cascadiaFirestore = null;
let cloudSyncStatus = 'connecting'; // 'synced' | 'connecting' | 'saving' | 'offline' | 'error'
let lastRemoteUpdatedAt = null;
let hasInitiatedSync = false;

function initFirestoreSync() {
  if (hasInitiatedSync) return;
  hasInitiatedSync = true;

  if (typeof firebase === 'undefined') {
    console.warn('[Firestore] Firebase SDK is not loaded. Operating in offline/localStorage mode.');
    cloudSyncStatus = 'offline';
    updateSyncBadgeUI();
    return;
  }

  try {
    if (!firebase.apps || firebase.apps.length === 0) {
      firebase.initializeApp(CASCADIA_FIREBASE_CONFIG);
    }
    cascadiaFirestore = firebase.firestore();
    const docRef = cascadiaFirestore.collection('cascadia_flexcon').doc('shared_inventory');
    initFirestoreMasterSync();

    docRef.onSnapshot((docSnap) => {
      if (!docSnap.exists) {
        // クラウドにデータがまだ存在しない場合、既存ローカルデータを初回アップロードして共有DBを構築
        console.log('[Firestore] No remote data found. Initializing cloud database from local store...');
        const initialData = loadFlexconData();
        initialData.updatedAt = new Date().toISOString();
        initialData.updatedBy = '初期セットアップ';
        docRef.set(initialData).then(() => {
          cloudSyncStatus = 'synced';
          lastRemoteUpdatedAt = initialData.updatedAt;
          updateSyncBadgeUI();
          console.log('[Firestore] Cloud database initialized successfully.');
        }).catch(err => {
          console.error('[Firestore] Initialization error:', err);
          cloudSyncStatus = 'error';
          updateSyncBadgeUI();
        });
        return;
      }

      const remoteData = docSnap.data();
      // クラウド上の共有データに9月末確定在庫を1回だけ反映し、全端末へ同期
      // （トランザクション内で最新版を再判定し、複数端末の同時移行や他端末の登録との競合を防止）
      if (remoteData && Array.isArray(remoteData.transactions) &&
          !(remoteData.migrations && remoteData.migrations.sep2026Opening)) {
        console.log('[Firestore] Applying 2026-09 closing inventory to shared data.');
        cascadiaFirestore.runTransaction((t) => t.get(docRef).then((snap) => {
          const fresh = snap.exists ? snap.data() : null;
          if (!fresh || !applySep2026Opening(fresh)) return null; // 既に他端末で移行済み
          fresh.updatedAt = new Date().toISOString();
          t.set(docRef, fresh);
          return fresh;
        })).catch(err => console.error('[Firestore] Sep2026 migration error:', err));
        return; // 移行後のスナップショット受信時に画面へ反映
      }
      if (remoteData && Array.isArray(remoteData.transactions)) {
        const remoteUpdated = remoteData.updatedAt || 'initial';
        if (remoteUpdated !== lastRemoteUpdatedAt) {
          console.log('[Firestore] Received real-time update from cloud at:', remoteUpdated);
          lastRemoteUpdatedAt = remoteUpdated;
          localStorage.setItem('cascadia_flexcon_inventory_v6', JSON.stringify(remoteData));
          cloudSyncStatus = 'synced';
          updateSyncBadgeUI();

          // ユーザーがモーダルで作業中（入力中）でなければ画面をリアルタイム自動再描画
          const isModalActive = document.querySelector('.modal-overlay') || 
                                document.getElementById('flexconEditModalOverlay') ||
                                (document.getElementById('flexconActionModalContainer') && document.getElementById('flexconActionModalContainer').children.length > 0) ||
                                (document.getElementById('purchaseOrderModalContainer') && document.getElementById('purchaseOrderModalContainer').children.length > 0);
          
          if (!isModalActive) {
            renderFlexconInventory();
          }
        }
      }
    }, (error) => {
      console.warn('[Firestore] Real-time listener disconnected:', error);
      cloudSyncStatus = 'offline';
      updateSyncBadgeUI();
    });
  } catch (e) {
    console.error('[Firestore Init Exception]', e);
    cloudSyncStatus = 'error';
    updateSyncBadgeUI();
  }
}

// --- マスター（担当者・備考マスター等）のクラウド共有 ---
let lastRemoteMasterUpdatedAt = null;

function pushFlexconMasterToCloud(master) {
  if (!cascadiaFirestore || !master) return;
  const payload = JSON.parse(JSON.stringify(master));
  payload.updatedAt = new Date().toISOString();
  lastRemoteMasterUpdatedAt = payload.updatedAt;
  cascadiaFirestore.collection('cascadia_flexcon').doc('shared_master')
    .set(payload)
    .then(() => console.log('[Firestore] Master saved to cloud:', payload.updatedAt))
    .catch(err => console.error('[Firestore Master Save Error]', err));
}

function initFirestoreMasterSync() {
  if (!cascadiaFirestore) return;
  const masterRef = cascadiaFirestore.collection('cascadia_flexcon').doc('shared_master');
  masterRef.onSnapshot((snap) => {
    if (!snap.exists) {
      // クラウドに未登録なら、この端末のマスターを初回アップロード
      pushFlexconMasterToCloud(loadFlexconMaster());
      return;
    }
    const remote = snap.data();
    if (!remote || !remote.locations || !remote.items || !remote.suppliers) return;
    const remoteUpdated = remote.updatedAt || 'initial';
    if (remoteUpdated === lastRemoteMasterUpdatedAt) return;
    lastRemoteMasterUpdatedAt = remoteUpdated;

    const master = JSON.parse(JSON.stringify(remote));
    delete master.updatedAt;
    if (!master.operators) master.operators = JSON.parse(JSON.stringify(DEFAULT_FLEXCON_OPERATORS));
    if (!master.notePresets) master.notePresets = JSON.parse(JSON.stringify(DEFAULT_FLEXCON_NOTE_PRESETS));
    saveFlexconMaster(master, { skipCloud: true });
    console.log('[Firestore] Received master update from cloud at:', remoteUpdated);

    const isModalActive = document.querySelector('.modal-overlay') ||
                          document.getElementById('flexconEditModalOverlay') ||
                          (document.getElementById('flexconActionModalContainer') && document.getElementById('flexconActionModalContainer').children.length > 0) ||
                          (document.getElementById('purchaseOrderModalContainer') && document.getElementById('purchaseOrderModalContainer').children.length > 0);
    if (!isModalActive && typeof renderFlexconInventory === 'function') {
      renderFlexconInventory();
    }
  }, (error) => {
    console.warn('[Firestore] Master listener disconnected:', error);
  });
}

function updateSyncBadgeUI() {
  const badges = document.querySelectorAll('.cloud-sync-badge-target');
  badges.forEach(badge => {
    if (cloudSyncStatus === 'synced') {
      badge.style.background = '#ecfdf5';
      badge.style.color = '#065f46';
      badge.style.borderColor = '#a7f3d0';
      badge.innerHTML = '🟢 <span style="font-weight:700;">クラウド自動同期中</span> <span style="font-size:10.5px; opacity:0.85;">(リアルタイム)</span>';
      badge.title = 'Google Cloud (Firestore) とリアルタイム接続中。他端末の変更も即時反映されます。';
    } else if (cloudSyncStatus === 'saving') {
      badge.style.background = '#eff6ff';
      badge.style.color = '#1e40af';
      badge.style.borderColor = '#bfdbfe';
      badge.innerHTML = '⏳ <span style="font-weight:700;">クラウド保存中...</span>';
    } else if (cloudSyncStatus === 'connecting') {
      badge.style.background = '#fefce8';
      badge.style.color = '#854d0e';
      badge.style.borderColor = '#fef08a';
      badge.innerHTML = '🟡 <span style="font-weight:700;">クラウド接続中...</span>';
    } else {
      badge.style.background = '#f8fafc';
      badge.style.color = '#64748b';
      badge.style.borderColor = '#cbd5e1';
      badge.innerHTML = '⚪ <span style="font-weight:700;">ローカル保存</span>';
      badge.title = 'オフラインまたはクラウド未接続。端末内ローカルストレージに安全に保管されています。';
    }
  });
}

// 2026年9月末確定在庫の繰越処理（1回限り）
// ・9/30以前の納品済み伝票は archivedTransactions へ退避（削除はしない）
// ・9/30付の確定繰越伝票（INITIAL_FLEXCON_DATA）を投入
// ・未納品（発注中）伝票と 10/1以降の伝票はそのまま保持
const SEP2026_CUTOFF = '2026-09-30';
function applySep2026Opening(data) {
  if (!data || !Array.isArray(data.transactions)) return false;
  data.migrations = data.migrations || {};
  if (data.migrations.sep2026Opening) return false;

  const isOpeningTx = (t) => typeof t.id === 'string' && t.id.startsWith('TX-INIT-0930');
  const toArchive = data.transactions.filter(t =>
    !isOpeningTx(t) && t.status !== 'ordered' && t.date && t.date <= SEP2026_CUTOFF
  );
  const keep = data.transactions.filter(t => !toArchive.includes(t) && !isOpeningTx(t));
  const opening = JSON.parse(JSON.stringify(INITIAL_FLEXCON_DATA.transactions));

  data.archivedTransactions = (data.archivedTransactions || []).concat(
    toArchive.map(t => Object.assign({}, t, { archivedReason: '2026年9月末確定在庫への繰越により退避' }))
  );
  data.transactions = opening.concat(keep);
  data.migrations.sep2026Opening = new Date().toISOString();
  return true;
}

function loadFlexconData() {
  return trackFlexconBaseline(loadFlexconDataRaw());
}

// ===== 同時入力対策：差分マージ保存 =====
// 画面・モーダルが保持する data は開いた時点のスナップショットのため、丸ごと上書きすると
// その間に他端末が登録した伝票が消える。読込時点の状態（ベースライン）との差分
// （追加・変更・削除）だけを、Firestore トランザクション内でクラウド最新版に適用する。
const flexconBaselines = new WeakMap();

function snapshotTxMap(transactions) {
  const map = new Map();
  (transactions || []).forEach(t => { if (t && t.id) map.set(t.id, JSON.stringify(t)); });
  return map;
}

function trackFlexconBaseline(data) {
  if (data && Array.isArray(data.transactions)) {
    flexconBaselines.set(data, snapshotTxMap(data.transactions));
  }
  return data;
}

function computeFlexconTxOps(data) {
  const baseline = flexconBaselines.get(data);
  if (!baseline) return null; // ベースライン無し（リセット等）は全体上書き
  const upserts = [];
  const currentIds = new Set();
  data.transactions.forEach(t => {
    if (!t || !t.id) return;
    currentIds.add(t.id);
    const json = JSON.stringify(t);
    if (baseline.get(t.id) !== json) upserts.push(JSON.parse(json));
  });
  const deletes = [];
  baseline.forEach((_, id) => { if (!currentIds.has(id)) deletes.push(id); });
  return { upserts, deletes };
}

function applyFlexconTxOps(remote, ops) {
  const merged = Object.assign({}, remote);
  const deleteSet = new Set(ops.deletes);
  const upsertMap = new Map(ops.upserts.map(t => [t.id, t]));
  const list = [];
  (remote.transactions || []).forEach(t => {
    if (deleteSet.has(t.id)) return;
    if (upsertMap.has(t.id)) {
      list.push(upsertMap.get(t.id));
      upsertMap.delete(t.id);
    } else {
      list.push(t);
    }
  });
  upsertMap.forEach(t => list.push(t)); // 新規伝票は末尾に追加
  merged.transactions = list;
  return merged;
}

function isFlexconModalActive() {
  return !!(document.querySelector('.modal-overlay') ||
    document.getElementById('flexconEditModalOverlay') ||
    (document.getElementById('flexconActionModalContainer') && document.getElementById('flexconActionModalContainer').children.length > 0) ||
    (document.getElementById('purchaseOrderModalContainer') && document.getElementById('purchaseOrderModalContainer').children.length > 0));
}

function loadFlexconDataRaw() {
  refreshActiveMaster();
  // Firestore 同期リスナーを一度だけ起動
  if (!hasInitiatedSync && typeof window !== 'undefined') {
    initFirestoreSync();
  }

  const saved = localStorage.getItem('cascadia_flexcon_inventory_v6');
  if (saved) {
    try { 
      const parsed = JSON.parse(saved);
      if (parsed && Array.isArray(parsed.transactions)) {
        parsed.transactions.forEach(tx => {
          if (!tx.status) tx.status = 'delivered';
          if (tx.location === '上組 福岡支店') {
            tx.location = '上組福岡支店 須崎ふ頭東二号';
          }
        });
        // ローカル表示のみ先行反映（クラウドへの書込みはクラウド受信時に行い、古い端末データでの上書きを防ぐ）
        if (applySep2026Opening(parsed)) {
          localStorage.setItem('cascadia_flexcon_inventory_v6', JSON.stringify(parsed));
        }
        return parsed;
      }
    } catch(e){}
  }

  // 以前のv4データがあれば移行
  const v4 = localStorage.getItem('cascadia_flexcon_inventory_v5');
  if (v4) {
    try {
      const parsed = JSON.parse(v4);
      if (parsed && Array.isArray(parsed.transactions)) {
        parsed.transactions.forEach(tx => {
          if (!tx.status) tx.status = 'delivered';
          if (tx.location === '上組 福岡支店') {
            tx.location = '上組福岡支店 須崎ふ頭東二号';
          }
        });
        applySep2026Opening(parsed);
        localStorage.setItem('cascadia_flexcon_inventory_v6', JSON.stringify(parsed));
        return parsed;
      }
    } catch(e){}
  }

  // 初期データで初期化
  const freshData = JSON.parse(JSON.stringify(INITIAL_FLEXCON_DATA));
  freshData.migrations = { sep2026Opening: new Date().toISOString() };
  localStorage.setItem('cascadia_flexcon_inventory_v6', JSON.stringify(freshData));
  return freshData;
}

function saveFlexconData(data) {
  // 1. ローカルストレージに即時保存（オフライン耐性・即時応答）
  localStorage.setItem('cascadia_flexcon_inventory_v6', JSON.stringify(data));

  // 今回の変更点（差分）を算出し、以降の保存で重複適用しないようベースラインを更新
  const ops = computeFlexconTxOps(data);
  trackFlexconBaseline(data);

  // 2. クラウド（Firebase Firestore）へ非同期保存
  if (!cascadiaFirestore) return;
  if (ops && ops.upserts.length === 0 && ops.deletes.length === 0) return;

  cloudSyncStatus = 'saving';
  updateSyncBadgeUI();
  const docRef = cascadiaFirestore.collection('cascadia_flexcon').doc('shared_inventory');
  const updatedAt = new Date().toISOString();
  lastRemoteUpdatedAt = updatedAt;

  cascadiaFirestore.runTransaction((t) => t.get(docRef).then((snap) => {
    let merged;
    if (ops && snap.exists && snap.data() && Array.isArray(snap.data().transactions)) {
      // クラウド最新版に自分の差分だけを適用（他端末の登録を保持）
      merged = applyFlexconTxOps(snap.data(), ops);
    } else {
      // リセット等の明示的な全体書込み、またはクラウド未初期化
      merged = JSON.parse(JSON.stringify(data));
    }
    merged.updatedAt = updatedAt;
    t.set(docRef, merged);
    return merged;
  })).then((merged) => {
    cloudSyncStatus = 'synced';
    updateSyncBadgeUI();
    console.log('[Firestore] Saved (merged) to cloud:', updatedAt);
    // マージ結果（他端末の登録を含む）を手元にも反映
    localStorage.setItem('cascadia_flexcon_inventory_v6', JSON.stringify(merged));
    data.transactions = JSON.parse(JSON.stringify(merged.transactions));
    trackFlexconBaseline(data);
    if (!isFlexconModalActive()) renderFlexconInventory();
  }).catch((err) => {
    console.error('[Firestore Save Error]', err);
    cloudSyncStatus = 'error';
    updateSyncBadgeUI();
    if (typeof showToast === 'function') {
      showToast('⚠️ クラウド保存に失敗しました。通信状態をご確認の上、再度登録してください。', 6000);
    }
  });
}

// 状態管理
let activeFlexconTab = 'dashboard'; // 'dashboard' | 'ledger' | 'check'
let currentFlexconAsOf = 'latest'; // 'latest' or 'YYYY-MM-DD'
let ledgerFilterLoc = 'all';
let ledgerFilterType = 'all'; // 'all' | 'ordered' | 'inbound' | 'outbound'
let ledgerFilterMonth = 'all'; // 'all' | 'YYYY-MM'
let ledgerFilterOperator = 'all'; // 'all' | 担当者名
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
          <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px; flex-wrap: wrap;">
            <h1 class="page-title" style="margin: 0;">📦 フレコンバッグ資材 在庫数・在庫金額確認ツール</h1>
            <span class="cloud-sync-badge-target">
              🟡 クラウド接続中...
            </span>
          </div>
          <p class="page-subtitle" style="margin: 0;">消耗品として費用処理されるフレコンバッグ等のリアルタイム実在庫枚数・評価金額を一元管理し、発注書自動出力および納期遅延アラートに対応します。<strong>Google Cloud (Firestore) により全端末でリアルタイム自動同期されます。</strong></p>
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
        <button class="flexcon-tab-pill ${activeFlexconTab === 'master' ? 'active' : ''}" id="tabFlexconMaster" title="拠点・商品・仕入先マスターの登録・変更・安全在庫設定">
          <span>⚙️</span> マスター管理
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
        <button class="btn-action-sub" id="btnOpenTransferModal" title="拠点間の在庫移動（移動元出庫＋移動先入庫）を一括登録します">
          <span>🔄</span> 拠点間移動
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
  document.getElementById('tabFlexconMaster').addEventListener('click', () => { activeFlexconTab = 'master'; renderFlexconInventory(); });

  // アクションモーダル起動
  document.getElementById('btnOpenOrderModal').addEventListener('click', () => { openFlexconOrderModal(data); });
  document.getElementById('btnOpenInboundModal').addEventListener('click', () => { openFlexconInboundModal(data); });
  document.getElementById('btnOpenOutboundModal').addEventListener('click', () => { openFlexconOutboundModal(data); });
  document.getElementById('btnOpenTransferModal').addEventListener('click', () => { openFlexconTransferModal(data); });

  // クラウド同期バッジの更新
  updateSyncBadgeUI();

  const container = document.getElementById('flexconTabContent');

  if (activeFlexconTab === 'dashboard') renderFlexconDashboard(container, data);
  else if (activeFlexconTab === 'ledger') renderFlexconLedger(container, data);
  else if (activeFlexconTab === 'check') renderFlexconCheck(container, data);
  else if (activeFlexconTab === 'master') renderFlexconMaster(container);
  else {
    activeFlexconTab = 'dashboard';
    renderFlexconDashboard(container, data);
  }
}

// 指定月末時点の選択肢（最新リアルタイム＋各月末時点）を動的に生成
function buildAsOfSelectOptionsHtml(transactions, selectedAsOf = 'latest') {
  const monthSet = new Set([
    '2026-12', '2026-11', '2026-10', '2026-09',
    '2026-08', '2026-07', '2026-06', '2026-05'
  ]);
  const now = new Date();
  for (let offset = -2; offset <= 2; offset++) {
    const d = new Date(now.getFullYear(), now.getMonth() + offset, 1);
    const ym = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    monthSet.add(ym);
  }
  (transactions || []).forEach(tx => {
    if (tx && tx.date && tx.date.length >= 7) monthSet.add(tx.date.slice(0, 7));
    if (tx && tx.transferOutDate && tx.transferOutDate.length >= 7) monthSet.add(tx.transferOutDate.slice(0, 7));
    if (tx && tx.transferInDate && tx.transferInDate.length >= 7) monthSet.add(tx.transferInDate.slice(0, 7));
  });

  const sortedMonths = Array.from(monthSet).sort().reverse();
  const getLastDayStr = (ym) => {
    const [y, m] = ym.split('-').map(Number);
    const lastDay = new Date(y, m, 0).getDate();
    return `${ym}-${String(lastDay).padStart(2, '0')}`;
  };

  let html = `<option value="latest" ${selectedAsOf === 'latest' ? 'selected' : ''}>⚡ 最新リアルタイム（全期間）</option>`;
  sortedMonths.forEach(ym => {
    const [y, m] = ym.split('-').map(Number);
    const endDate = getLastDayStr(ym);
    const slashDate = endDate.replace(/-/g, '/');
    html += `<option value="${endDate}" ${selectedAsOf === endDate ? 'selected' : ''}>${y}年 ${m}月末 時点 (${slashDate})</option>`;
  });
  return html;
}

// 在庫計算ヘルパー（指定月末時点対応 ＆ 未納品発注残の分離 ＆ 月跨ぎ拠点間移動の未着管理）
function calculateStockMatrix(transactions, asOfDate = null) {
  const matrix = {};
  // 各拠点・品目の在庫ロットキュー（FIFO計算用）
  const fifoQueues = {};

  FLEXCON_LOCATIONS.forEach(loc => {
    matrix[loc] = {};
    fifoQueues[loc] = {};
    FLEXCON_ITEMS.forEach(item => {
      matrix[loc][item.id] = { qty: 0, totalValue: 0, lastPrice: item.defaultPrice, orderedQty: 0, inTransitInQty: 0, inTransitDetails: [] };
      fifoQueues[loc][item.id] = [];
    });
  });

  // 指定基準日(asOfDate)時点で「出荷元は出庫済（outDate <= asOfDate）だが、移動先には未入荷（inDate > asOfDate）」の月跨ぎ移動を集計
  if (asOfDate) {
    transactions.forEach(tx => {
      if (tx.type !== 'inbound' || tx.status === 'ordered') return;
      let outDate = tx.transferOutDate || null;
      if (!outDate && typeof tx.id === 'string' && tx.id.endsWith('-IN')) {
        const outId = tx.id.replace(/-IN$/, '-OUT');
        const pairedOut = transactions.find(t => t.id === outId);
        if (pairedOut) outDate = pairedOut.date;
      }
      if (outDate && outDate <= asOfDate && tx.date > asOfDate && matrix[tx.location]) {
        const items = (tx.items && tx.items.length > 0) ? tx.items : [{ item: tx.item, qty: tx.qty }];
        items.forEach(it => {
          if (!it.item || !matrix[tx.location][it.item]) return;
          matrix[tx.location][it.item].inTransitInQty = (matrix[tx.location][it.item].inTransitInQty || 0) + (it.qty || 0);
          matrix[tx.location][it.item].inTransitDetails.push({
            qty: it.qty || 0,
            outDate: outDate,
            inDate: tx.date,
            fromLoc: tx.transferFromLoc || (tx.supplier || '').replace(/^【拠点間移動】|発.*$/g, '').trim()
          });
        });
      }
    });
  }

  const filtered = transactions.filter(tx => {
    if (asOfDate && tx.date > asOfDate) return false;
    return true;
  });

  // 日付昇順（古い順）に時系列処理（先入先出 FIFO を忠実に再現）
  filtered.slice().sort((a, b) => new Date(a.date) - new Date(b.date)).forEach(tx => {
    if (!matrix[tx.location]) return;

    const items = (tx.items && tx.items.length > 0) ? tx.items : [{
      item: tx.item,
      qty: tx.qty,
      price: tx.price
    }];

    items.forEach(it => {
      const itemKey = it.item;
      if (!itemKey) return;
      const hasExplicitPrice = typeof it.price === 'number' && !isNaN(it.price) && (it.price > 0 || (tx.type === 'inbound' && it.price === 0));
      if (!matrix[tx.location][itemKey]) {
        matrix[tx.location][itemKey] = { qty: 0, totalValue: 0, lastPrice: hasExplicitPrice ? it.price : 1000, orderedQty: 0 };
        fifoQueues[tx.location][itemKey] = [];
      }

      const cell = matrix[tx.location][itemKey];
      const queue = fifoQueues[tx.location][itemKey];
      // 入庫伝票で単価が数値入力されていれば 0円 も有効な評価単価として扱う（例: 補修済品 0円評価）
      const fallbackUnit = (typeof cell.lastPrice === 'number' && !isNaN(cell.lastPrice)) ? cell.lastPrice : 1000;
      const unitPrice = hasExplicitPrice ? it.price : fallbackUnit;
      if (hasExplicitPrice) cell.lastPrice = it.price;

      if (tx.type === 'inbound') {
        if (tx.status === 'ordered') {
          // 未納品発注残
          cell.orderedQty = (cell.orderedQty || 0) + it.qty;
        } else {
          // 納品済入庫：FIFOロットキューに追加
          cell.qty += it.qty;
          queue.push({
            date: tx.date,
            qty: it.qty,
            price: unitPrice
          });
          // 在庫金額の再計算（キュー内の全残ロット合計）
          cell.totalValue = queue.reduce((sum, lot) => sum + (lot.qty * lot.price), 0);
        }
      } else if (tx.type === 'outbound') {
        // 出庫：古い入庫ロットから順に引き当て（先入先出 FIFO）
        let remainingOut = it.qty;
        cell.qty = Math.max(0, cell.qty - it.qty);

        while (remainingOut > 0 && queue.length > 0) {
          const oldestLot = queue[0];
          if (oldestLot.qty <= remainingOut) {
            remainingOut -= oldestLot.qty;
            queue.shift(); // ロット完全消費
          } else {
            oldestLot.qty -= remainingOut;
            remainingOut = 0; // ロット一部消費
          }
        }

        // 期末在庫金額の更新
        cell.totalValue = queue.reduce((sum, lot) => sum + (lot.qty * lot.price), 0);
        if (cell.qty === 0) {
          cell.totalValue = 0;
          queue.length = 0;
        }
      }
    });
  });

  // 残存ロット（FIFOキュー）を各セルに公開（払出単価の算出に使用）
  Object.keys(fifoQueues).forEach(loc => {
    Object.keys(fifoQueues[loc]).forEach(k => {
      if (matrix[loc] && matrix[loc][k]) matrix[loc][k].lots = fifoQueues[loc][k];
    });
  });

  return matrix;
}

// 先入先出（FIFO）で払い出されるロット内訳を算出（出庫・拠点間移動の単価決定用）
// 戻り値: [{ qty, price }]（古いロット順・同単価はまとめる）
function getFifoIssueLots(transactions, loc, itemId, qty, asOfDate = null) {
  const matrix = calculateStockMatrix(transactions, asOfDate);
  const cell = matrix[loc] && matrix[loc][itemId];
  const lots = (cell && cell.lots) ? cell.lots.map(l => ({ qty: l.qty, price: l.price })) : [];
  const itemObj = FLEXCON_ITEMS.find(i => i.id === itemId);
  const fallbackPrice = (cell && cell.lastPrice) || (itemObj ? itemObj.defaultPrice : 0) || 0;

  const issued = [];
  let remaining = qty;
  while (remaining > 0 && lots.length > 0) {
    const lot = lots[0];
    const take = Math.min(lot.qty, remaining);
    issued.push({ qty: take, price: lot.price });
    lot.qty -= take;
    remaining -= take;
    if (lot.qty <= 0) lots.shift();
  }
  // 在庫不足分（在庫超過で登録を続行した場合）は直近単価で計上
  if (remaining > 0) issued.push({ qty: remaining, price: fallbackPrice });

  const merged = [];
  issued.forEach(l => {
    const last = merged[merged.length - 1];
    if (last && last.price === l.price) last.qty += l.qty;
    else merged.push({ qty: l.qty, price: l.price });
  });
  return merged;
}

// FIFO払出ロットを伝票フィールドへ展開（単一単価なら単一行、複数単価ならロット別内訳 items）
function buildFifoTxFields(itemId, lots) {
  const totalQty = lots.reduce((s, l) => s + l.qty, 0);
  if (lots.length <= 1) {
    return { item: itemId, qty: totalQty, price: lots.length ? lots[0].price : 0 };
  }
  return {
    item: itemId,
    qty: totalQty,
    price: lots[0].price,
    items: lots.map(l => ({ item: itemId, qty: l.qty, price: l.price }))
  };
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

      const sStock = getSafetyStock(loc, item);
      if (sStock > 0 && cell.qty < sStock) {
        const alertObj = {
          location: loc,
          item: item,
          currentQty: cell.qty,
          orderedQty: ordQty,
          safetyStock: sStock
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

  // 未納品・手配済みの全トランザクション（期限制限なし・先日付でもすべて対象）
  const allOrderedTxs = data.transactions.filter(t => t.status === 'ordered');
  const incomingOrdersByLoc = {};
  allOrderedTxs.forEach(tx => {
    if (!incomingOrdersByLoc[tx.location]) incomingOrdersByLoc[tx.location] = [];
    incomingOrdersByLoc[tx.location].push(tx);
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
          ${buildAsOfSelectOptionsHtml(data.transactions, currentFlexconAsOf)}
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
        ${allOrderedTxs.length > 0 ? `
          <div style="font-size: 11px; color: var(--accent-blue); margin-top: 5px; border-top: 1px dashed var(--border-subtle); padding-top: 4px; font-weight: 600;">
            🚚 入荷待ち(手配済): <strong>${allOrderedTxs.length}</strong> 件
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
    ${(shortageItems.length > 0 || allOrderedTxs.length > 0) ? `
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
            <div style="max-height: 280px; overflow-y: auto; padding-right: 4px; display: flex; flex-direction: column; gap: 6px;">
              ${Object.entries(shortageByLoc).map(([loc, list]) => `
                <div style="background: var(--bg-primary); border: 1px solid rgba(239,68,68,0.15); border-radius: 6px; padding: 6px 10px; font-size: 12px;">
                  <div style="font-weight: 700; color: var(--text-primary); margin-bottom: 4px; display: flex; justify-content: space-between; align-items: center;">
                    <span>📍 ${loc}</span>
                    <span style="font-size: 11px; color: #ef4444; font-weight: 600;">${list.length}品目 要手配</span>
                  </div>
                  <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                    ${list.map(a => `
                      <button type="button" class="btn-quick-order-from-shortage" data-location="${a.location}" data-item-id="${a.item.id}" data-suggested-qty="${Math.max(a.safetyStock - a.currentQty, 0)}" style="display: inline-flex; align-items: center; gap: 5px; background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.3); border-radius: 6px; padding: 4px 8px; font-size: 11px; cursor: pointer; text-align: left; transition: all 0.15s ease;" title="クリックしてこの品目の発注書を作成（${a.location}宛）">
                        <strong>【${a.item.commonName}】</strong>
                        <span style="color: #ef4444; font-weight: 700;">残${a.currentQty}枚</span>
                        <span style="color: var(--text-muted); font-size: 10px;">(基準:${a.safetyStock})</span>
                        <span style="background: #ef4444; color: #ffffff; padding: 1px 5px; border-radius: 3px; font-size: 10px; font-weight: 700; margin-left: 2px;">📝 発注</span>
                      </button>
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
              <span>🚚</span> 入荷待ち（発注済・手配中） (${allOrderedTxs.length}件)
            </div>
            <span style="font-size: 11px; color: var(--accent-blue); font-weight: 600; background: rgba(37,99,235,0.1); padding: 2px 8px; border-radius: 10px;">手配済・到着待ち</span>
          </div>
          ${allOrderedTxs.length === 0 ? `
            <div style="font-size: 12px; color: var(--text-muted); padding: 6px 0;">現在、入荷待ちの品目はありません。</div>
          ` : `
            <div style="max-height: 280px; overflow-y: auto; padding-right: 4px; display: flex; flex-direction: column; gap: 8px;">
              ${Object.entries(incomingOrdersByLoc).map(([loc, txList]) => `
                <div style="background: var(--bg-primary); border: 1px solid rgba(37,99,235,0.18); border-radius: 6px; padding: 8px 10px; font-size: 12px;">
                  <div style="font-weight: 700; color: var(--text-primary); margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center;">
                    <span>📍 ${loc}</span>
                    <span style="font-size: 11px; color: var(--accent-blue); font-weight: 600;">${txList.length}件 手配中</span>
                  </div>
                  <div style="display: flex; flex-direction: column; gap: 6px;">
                    ${txList.map(tx => {
                      const rawItems = (tx.items && Array.isArray(tx.items) && tx.items.length > 0)
                        ? tx.items
                        : [{ item: tx.item, qty: tx.qty, price: tx.price }];
                      const summary = rawItems.map(it => {
                        const itemObj = FLEXCON_ITEMS.find(i => i.id === it.item);
                        const name = it.name || it.customName || (itemObj ? itemObj.commonName : it.item);
                        return `<strong>【${name}】</strong> <span style="color:#059669; font-weight:700;">${it.qty}枚</span>`;
                      }).join('、');
                      const isOver = tx.deliveryDueDate && tx.deliveryDueDate < today;
                      return `
                        <div style="background: rgba(37,99,235,0.03); border: 1px solid rgba(37,99,235,0.15); border-radius: 6px; padding: 6px 8px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 6px;">
                          <div style="line-height: 1.4;">
                            <div style="font-size: 11.5px; color: var(--text-primary);">${summary}</div>
                            <div style="font-size: 11px; color: ${isOver ? '#ef4444' : '#1e40af'}; font-weight: 600; display: flex; align-items: center; gap: 6px; margin-top: 2px;">
                              <span>📅 納品予定: <strong>${tx.deliveryDueDate || '未定'}</strong></span>
                              ${tx.isEarliestDelivery ? '<span style="font-size: 10px; background: #dbeafe; color: #1e40af; padding: 1px 4px; border-radius: 3px;">⚡最短希望</span>' : ''}
                              ${isOver ? '<span style="font-size: 10px; background: #fee2e2; color: #dc2626; padding: 1px 4px; border-radius: 3px;">⚠️ 納期超過</span>' : ''}
                              <span style="font-weight: normal; color: var(--text-muted);">(${tx.supplier || '仕入先未設定'})</span>
                            </div>
                          </div>
                          <div style="display: flex; gap: 4px; align-items: center;">
                            <button type="button" class="btn btn-secondary btn-quick-change-duedate" data-id="${tx.id}" data-duedate="${tx.deliveryDueDate || ''}" style="padding: 3px 8px; font-size: 11px; color: #1e40af; border-color: #93c5fd; background: #f8fafc; cursor: pointer;" title="納品予定日を変更する">
                              📅 納期変更
                            </button>
                            <button type="button" class="btn btn-primary btn-quick-deliver" data-id="${tx.id}" style="padding: 3px 8px; font-size: 11px; background: var(--accent-green); border-color: var(--accent-green); cursor: pointer;" title="納品受入を完了し実在庫に反映">
                              ✅ 受入
                            </button>
                          </div>
                        </div>
                      `;
                    }).join('')}
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
                    const sStock = getSafetyStock(loc, item);
                    const isAlert = sStock > 0 && cell.qty < sStock;
                    return `
                      <td style="padding: 8px 10px; text-align: right; ${isAlert ? 'background: rgba(239,68,68,0.06);' : ''}">
                        <div style="font-size: 14px; font-weight: 700; color: ${isAlert ? '#ef4444' : 'var(--text-primary)'};">
                          ${cell.qty.toLocaleString()} <span style="font-size: 11px; font-weight: normal;">枚</span>
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted);">¥${Math.round(cell.totalValue).toLocaleString()}</div>
                        ${sStock > 0 ? `<div style="font-size: 9.5px; color: ${isAlert ? '#ef4444' : 'var(--text-muted)'}; margin-top: 1px;">(基準 ${sStock}枚)</div>` : ''}
                        ${cell.orderedQty > 0 ? `
                          <div style="font-size: 10px; color: var(--accent-green); font-weight: 600; margin-top: 2px;">
                            (入荷待 +${cell.orderedQty}枚)
                          </div>
                        ` : ''}
                        ${cell.inTransitInQty > 0 ? `
                          <div style="font-size: 10px; color: var(--accent-blue); font-weight: 700; margin-top: 2px;" title="${(cell.inTransitDetails || []).map(d => `${d.fromLoc ? d.fromLoc + 'より ' : ''}${d.outDate}出荷 → ${d.inDate}入荷 (${d.qty}枚)`).join(' / ')}">
                            (🔄移動未着 +${cell.inTransitInQty}枚${cell.inTransitDetails && cell.inTransitDetails[0] ? ` [${cell.inTransitDetails[0].inDate.slice(5).replace('-', '/')}着]` : ''})
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
      const button = e.currentTarget || e.target.closest('.btn-quick-deliver');
      const id = button ? button.dataset.id : null;
      if (id) markOrderDelivered(id, data);
    });
  });

  // 安全在庫アラートからの発注書作成連動
  container.querySelectorAll('.btn-quick-order-from-shortage').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const b = e.currentTarget || e.target.closest('.btn-quick-order-from-shortage');
      if (!b) return;
      const loc = b.dataset.location;
      const itemId = b.dataset.itemId;
      const suggestedQty = parseInt(b.dataset.suggestedQty, 10) || 100;
      openFlexconOrderModal(data, {
        location: loc,
        itemId: itemId,
        suggestedQty: suggestedQty
      });
    });
  });

  // 入荷待ちアラートからの納品予定日変更
  container.querySelectorAll('.btn-quick-change-duedate').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const b = e.currentTarget || e.target.closest('.btn-quick-change-duedate');
      if (!b) return;
      const id = b.dataset.id;
      const currentDueDate = b.dataset.duedate || '';
      const newDate = prompt(`【納品予定日の変更】\n新しい納品予定日を入力してください (YYYY-MM-DD):`, currentDueDate);
      if (newDate !== null && newDate.trim()) {
        const trimmed = newDate.trim();
        const targetTx = data.transactions.find(t => t.id === id);
        if (targetTx) {
          targetTx.deliveryDueDate = trimmed;
          saveFlexconData(data);
          showToast(`📅 納品予定日を「${trimmed}」に更新しました`);
          renderFlexconInventory();
        }
      }
    });
  });
}

// 納品完了処理（複数品目対応・納品予定日を反映）
function markOrderDelivered(txId, data) {
  const tx = data.transactions.find(t => t.id === txId);
  if (!tx) return;
  const today = new Date().toISOString().split('T')[0];
  const effectiveDate = tx.deliveryDueDate || tx.orderDate || today;

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

  if (confirm(`発注番号 ${tx.orderNo || tx.id} (${tx.location}宛: ${itemsSummary}) の納品受入を完了しますか？\n（納品予定日 ${effectiveDate} 付で実在庫に計上されます）`)) {
    tx.status = 'delivered';
    tx.date = effectiveDate;
    saveFlexconData(data);
    showToast(`✨ 納品受入を完了しました（${effectiveDate}付で実在庫に計上されました）`);
    renderFlexconInventory();
  }
}

// 2. 資材発注・発注書自動出力モーダル（複数品目対応・自由入力対応・プリセット連動）
function openFlexconOrderModal(data, options = {}) {
  const modalContainer = document.getElementById('flexconActionModalContainer');
  const today = new Date().toISOString().split('T')[0];
  const targetDate = new Date();
  targetDate.setDate(targetDate.getDate() + 14);
  const defaultDueDate = targetDate.toISOString().split('T')[0];
  const autoPoNo = "PO-" + today.replace(/-/g, '') + "-" + String(Math.floor(Math.random() * 90) + 10);

  const defaultSup = FLEXCON_SUPPLIERS[0];
  const defaultLoc = (options && options.location) ? options.location : FLEXCON_LOCATIONS[0];

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
                ${FLEXCON_LOCATIONS.map(l => `<option value="${l}" ${l === defaultLoc ? 'selected' : ''}>${l}</option>`).join('')}
              </select>
            </div>
            <div class="tool-group">
              <label for="mPoOurContact">当社担当者</label>
              <select id="mPoOurContact" required style="font-weight: 600;">
                ${FLEXCON_OPERATORS.map(op => `<option value="${op}" ${op === (options.ourContact || '畑山') ? 'selected' : ''}>👤 ${op}</option>`).join('')}
              </select>
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

  // 初期行として1件追加（指定品目・数量があれば優先セット）
  const initialItem = (options && options.itemId)
    ? (FLEXCON_ITEMS.find(i => i.id === options.itemId) || FLEXCON_ITEMS[0])
    : FLEXCON_ITEMS[0];
  const initialQty = (options && options.suggestedQty && options.suggestedQty > 0)
    ? options.suggestedQty
    : (initialItem.id.includes('BAG') ? 150 : 100);

  addPoItemRow({
    item: initialItem.id,
    qty: initialQty,
    price: initialItem.defaultPrice || 1000,
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
      operator: document.getElementById('mPoOurContact').value,
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
            <img src="src/cti-logo.jpg" alt="CTI Logo" class="po-issuer-logo-img">
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
    .po-issuer-logo-img { width: 24px; height: 24px; object-fit: contain; }
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
    .po-actual-table tfoot tr:first-child .total-empty { border-top: 1px solid #111827 !important; }
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

          ${renderOperatorSelectHtml('mInOperator', '入力担当者')}
          ${renderNoteSelectHtml('mInNotePreset', 'mInNote')}

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
  setupModalOperatorAndNote('mInOperator', 'mInNotePreset', 'mInNote');

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
      operator: getSelectedOperator('mInOperator'),
      purpose: "",
      note: document.getElementById('mInNote').value
    };
    newTx.ourContact = newTx.operator;

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

          ${renderOperatorSelectHtml('mOutOperator', '入力担当者')}
          ${renderNoteSelectHtml('mOutNotePreset', 'mOutNote')}

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
  setupModalOperatorAndNote('mOutOperator', 'mOutNotePreset', 'mOutNote');

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

    const outDate = document.getElementById('mOutDate').value;
    const operator = getSelectedOperator('mOutOperator');
    // 先入先出（FIFO）で払い出すロット単価を算出
    const issueLots = getFifoIssueLots(data.transactions, loc, itemId, qty, outDate);
    const newTx = Object.assign({
      id: "TX-" + Date.now().toString().slice(-6),
      date: outDate,
      type: "outbound",
      status: "delivered",
      location: loc,
      supplier: "",
      operator: operator,
      ourContact: operator,
      purpose: document.getElementById('mOutPurpose').value,
      note: document.getElementById('mOutNote').value
    }, buildFifoTxFields(itemId, issueLots));

    data.transactions.push(newTx);
    saveFlexconData(data);
    closeModal();
    showToast("📤 出庫データを正常に登録しました");
    renderFlexconInventory();
  });
}

// 5. 拠点間移動モーダル（出庫＋入庫を一括生成・出荷日と入荷日の個別入力対応・単価欄ロック）
function openFlexconTransferModal(data) {
  const modalContainer = document.getElementById('flexconActionModalContainer');
  const today = new Date().toISOString().split('T')[0];

  modalContainer.innerHTML = `
    <div class="flexcon-modal-overlay" id="flexconTransferModalOverlay">
      <div class="flexcon-modal-box" style="max-width: 640px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 20px;">🔄</span>
            <h3 style="margin: 0; font-size: 17px; font-weight: 800;">フレコン資材 拠点間移動登録</h3>
          </div>
          <button type="button" id="btnCloseTransferModal" style="background: none; border: none; font-size: 22px; cursor: pointer; color: var(--text-muted); line-height: 1;">✕</button>
        </div>

        <form id="modalTransferForm" class="tool-form" novalidate>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
            <div class="tool-group">
              <label for="mTransferFromLoc">📤 出荷元拠点（出庫場所） <span style="color:#ef4444;">*</span></label>
              <select id="mTransferFromLoc" required>
                ${FLEXCON_LOCATIONS.map(l => `<option value="${l}">${l}</option>`).join('')}
              </select>
            </div>
            <div class="tool-group">
              <label for="mTransferToLoc">📥 納品先拠点（受入場所） <span style="color:#ef4444;">*</span></label>
              <select id="mTransferToLoc" required>
                ${FLEXCON_LOCATIONS.map((l, idx) => `<option value="${l}" ${idx === 1 ? 'selected' : ''}>${l}</option>`).join('')}
              </select>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
            <div class="tool-group">
              <label for="mTransferOutDate">📤 出荷日（移動元の出庫日） <span style="color:#ef4444;">*</span></label>
              <input type="date" id="mTransferOutDate" value="${today}" required>
              <div style="font-size: 10.5px; color: var(--text-muted); margin-top: 3px;">※この日付で出荷元の在庫から減算されます</div>
            </div>
            <div class="tool-group">
              <label for="mTransferInDate">📥 入荷日（納品先の受入日） <span style="color:#ef4444;">*</span></label>
              <input type="date" id="mTransferInDate" value="${today}" required>
              <div style="font-size: 10.5px; color: var(--text-muted); margin-top: 3px;">※月を跨ぐ場合は到着月の日付を指定してください</div>
            </div>
          </div>

          <div id="mTransferDateNotice" style="display: none; background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.35); border-left: 4px solid #f59e0b; border-radius: 8px; padding: 9px 12px; margin-bottom: 12px; font-size: 11.5px; color: #92400e; line-height: 1.45;"></div>

          <div class="tool-group">
            <label for="mTransferItem">対象資材（品目） <span style="color:#ef4444;">*</span></label>
            <select id="mTransferItem" required>
              ${FLEXCON_ITEMS.map(i => `<option value="${i.id}">【${i.commonName}】 ${i.id} - ${i.name.split('　')[0]}</option>`).join('')}
            </select>
            <div id="mTransferStockInfo" style="font-size: 11.5px; color: var(--accent-blue); font-weight: 600; margin-top: 4px;"></div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
            <div class="tool-group">
              <label for="mTransferQty">移動数量 (枚) <span style="color:#ef4444;">*</span></label>
              <input type="number" id="mTransferQty" min="1" max="99999" placeholder="例: 100" required>
            </div>
            <div class="tool-group">
              <label for="mTransferPrice" style="color: var(--text-muted);">単価 (円) <span style="font-size: 10px; font-weight: normal;">※入力不可（自動引継）</span></label>
              <input type="text" id="mTransferPrice" value="※拠点間移動のため入力不要" disabled style="background: #f1f5f9; color: #64748b; cursor: not-allowed; border-color: #cbd5e1;">
            </div>
          </div>

          ${renderOperatorSelectHtml('mTransferOperator', '入力担当者')}
          ${renderNoteSelectHtml('mTransferNotePreset', 'mTransferNote')}

          <div style="background: rgba(37,99,235,0.04); border: 1px solid rgba(37,99,235,0.18); border-radius: 8px; padding: 10px 14px; margin-top: 10px; font-size: 11.5px; color: var(--text-secondary); line-height: 1.45;">
            💡 <strong>登録の仕組み:</strong> 出荷元拠点からの「出庫（出荷日付）」と納品先拠点への「入庫（入荷日付）」の2レコードが自動作成されます。入出庫日が月を跨ぐ場合（例：出荷日 10/31・入荷日 11/5）も、それぞれの月の月末在庫に正確に反映されます。
          </div>

          <div style="display: flex; gap: 10px; margin-top: 20px;">
            <button type="button" id="btnCancelTransferModal" class="btn btn-secondary" style="flex: 1; padding: 11px;">キャンセル</button>
            <button type="submit" class="btn btn-primary" style="flex: 2; padding: 11px; font-size: 14px; background: linear-gradient(135deg, var(--accent-blue), #1d4ed8);">🔄 拠点間移動を登録する</button>
          </div>
        </form>
      </div>
    </div>
  `;

  const closeModal = () => { modalContainer.innerHTML = ''; };
  document.getElementById('btnCloseTransferModal').addEventListener('click', closeModal);
  document.getElementById('btnCancelTransferModal').addEventListener('click', closeModal);
  document.getElementById('flexconTransferModalOverlay').addEventListener('click', (e) => {
    if (e.target.id === 'flexconTransferModalOverlay') closeModal();
  });

  const fromLocSelect = document.getElementById('mTransferFromLoc');
  const toLocSelect = document.getElementById('mTransferToLoc');
  const outDateInput = document.getElementById('mTransferOutDate');
  const inDateInput = document.getElementById('mTransferInDate');
  const dateNoticeDiv = document.getElementById('mTransferDateNotice');
  const itemSelect = document.getElementById('mTransferItem');
  const stockInfoDiv = document.getElementById('mTransferStockInfo');

  const updateTransferDateNotice = () => {
    const outDate = outDateInput.value;
    const inDate = inDateInput.value;
    const fromLoc = fromLocSelect.value;
    const toLoc = toLocSelect.value;
    if (!outDate || !inDate || outDate === inDate) {
      dateNoticeDiv.style.display = 'none';
      return;
    }
    dateNoticeDiv.style.display = 'block';
    if (inDate < outDate) {
      dateNoticeDiv.style.background = 'rgba(239, 68, 68, 0.08)';
      dateNoticeDiv.style.borderColor = 'rgba(239, 68, 68, 0.35)';
      dateNoticeDiv.style.borderLeft = '4px solid #ef4444';
      dateNoticeDiv.style.color = '#b91c1c';
      dateNoticeDiv.innerHTML = `⚠️ <strong>日付の確認:</strong> 入荷日（${inDate}）が出荷日（${outDate}）より前の日付になっています。`;
    } else {
      const isCrossMonth = outDate.slice(0, 7) !== inDate.slice(0, 7);
      dateNoticeDiv.style.background = 'rgba(245, 158, 11, 0.08)';
      dateNoticeDiv.style.borderColor = 'rgba(245, 158, 11, 0.35)';
      dateNoticeDiv.style.borderLeft = '4px solid #f59e0b';
      dateNoticeDiv.style.color = '#92400e';
      dateNoticeDiv.innerHTML = `📅 <strong>${isCrossMonth ? '月跨ぎ移動の計上' : '出荷日・入荷日の個別計上'}:</strong> 出荷元【${fromLoc}】は <strong>${outDate}</strong> に出庫減算され、納品先【${toLoc}】は <strong>${inDate}</strong> に入庫加算されます。`;
    }
  };

  const updateCurrentStockInfo = () => {
    const fromLoc = fromLocSelect.value;
    const itemId = itemSelect.value;
    const asOfOutDate = outDateInput.value || null;
    const matrix = calculateStockMatrix(data.transactions, asOfOutDate);
    const avail = (matrix[fromLoc] && matrix[fromLoc][itemId]) ? matrix[fromLoc][itemId].qty : 0;
    const itemObj = FLEXCON_ITEMS.find(i => i.id === itemId);
    const itemName = itemObj ? itemObj.commonName : itemId;
    stockInfoDiv.innerHTML = `📍 出荷元【${fromLoc}】の在庫（${asOfOutDate || '現在'}時点）: <strong>${avail.toLocaleString()}</strong> 枚 (${itemName})`;
    stockInfoDiv.dataset.avail = avail;
    updateTransferDateNotice();
  };

  outDateInput.addEventListener('change', () => {
    if (!inDateInput.dataset.userEdited || (inDateInput.value && inDateInput.value < outDateInput.value)) {
      inDateInput.value = outDateInput.value;
    }
    updateCurrentStockInfo();
  });
  inDateInput.addEventListener('change', () => {
    inDateInput.dataset.userEdited = 'true';
    updateTransferDateNotice();
  });

  fromLocSelect.addEventListener('change', updateCurrentStockInfo);
  toLocSelect.addEventListener('change', updateTransferDateNotice);
  itemSelect.addEventListener('change', updateCurrentStockInfo);
  updateCurrentStockInfo();
  setupModalOperatorAndNote('mTransferOperator', 'mTransferNotePreset', 'mTransferNote');

  document.getElementById('modalTransferForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const fromLoc = fromLocSelect.value;
    const toLoc = toLocSelect.value;
    const itemId = itemSelect.value;
    const qty = parseInt(document.getElementById('mTransferQty').value, 10);
    const outDate = outDateInput.value;
    const inDate = inDateInput.value;
    const note = document.getElementById('mTransferNote').value.trim();
    const operator = getSelectedOperator('mTransferOperator');

    if (!outDate || !inDate) {
      alert("出荷日と入荷日をそれぞれ入力してください。");
      return;
    }
    if (inDate < outDate) {
      alert(`⚠️ 入荷日（${inDate}）が出荷日（${outDate}）より前の日付になっています。日付をご確認ください。`);
      return;
    }
    if (fromLoc === toLoc) {
      alert("⚠️ 出荷元拠点と納品先拠点が同じです。異なる拠点を選択してください。");
      return;
    }
    if (!qty || qty <= 0) {
      alert("移動数量を1枚以上で入力してください。");
      return;
    }

    const avail = parseInt(stockInfoDiv.dataset.avail || '0', 10);
    if (qty > avail) {
      if (!confirm(`⚠️ 在庫超過警告: 出荷元 (${fromLoc}) の現在庫は ${avail} 枚です。\n移動数量 (${qty} 枚) が現在庫を超えていますが、登録を続行しますか？`)) {
        return;
      }
    }

    // 移動元の在庫を出荷日時点で先入先出（FIFO）で払い出し、そのロット単価をそのまま移動先へ引き継ぐ
    const issueLots = getFifoIssueLots(data.transactions, fromLoc, itemId, qty, outDate);
    const lotFields = buildFifoTxFields(itemId, issueLots);

    const baseId = Date.now().toString().slice(-6);
    const pairId = "TX-" + baseId;
    const dateDiffNote = outDate !== inDate ? `（出荷:${outDate} → 入荷:${inDate}）` : '';

    // 1. 移動元からの出庫（出荷日付で計上）
    const outboundTx = Object.assign({
      id: pairId + "-OUT",
      transferPairId: pairId,
      transferOutDate: outDate,
      transferInDate: inDate,
      transferFromLoc: fromLoc,
      transferToLoc: toLoc,
      date: outDate,
      type: "outbound",
      status: "delivered",
      location: fromLoc,
      supplier: "",
      operator: operator,
      ourContact: operator,
      purpose: `【拠点間移動】${toLoc}宛${dateDiffNote}`,
      note: note ? `移動先: ${toLoc}${dateDiffNote} / ${note}` : `移動先: ${toLoc}へ振替${dateDiffNote}`
    }, JSON.parse(JSON.stringify(lotFields)));

    // 2. 移動先への入庫（入荷日付で計上・移動元のロット単価を引継ぎ）
    const inboundTx = Object.assign({
      id: pairId + "-IN",
      transferPairId: pairId,
      transferOutDate: outDate,
      transferInDate: inDate,
      transferFromLoc: fromLoc,
      transferToLoc: toLoc,
      date: inDate,
      type: "inbound",
      status: "delivered",
      location: toLoc,
      operator: operator,
      ourContact: operator,
      supplier: `【拠点間移動】${fromLoc}発${dateDiffNote}`,
      purpose: "",
      note: note ? `移動元: ${fromLoc}${dateDiffNote} / ${note}` : `移動元: ${fromLoc}より受入${dateDiffNote}`
    }, JSON.parse(JSON.stringify(lotFields)));

    data.transactions.push(outboundTx, inboundTx);
    saveFlexconData(data);
    closeModal();
    const toastDateMsg = outDate !== inDate ? ` [出荷:${outDate} → 入荷:${inDate}]` : '';
    showToast(`🔄 拠点間移動を登録しました（${fromLoc} → ${toLoc} : ${qty}枚${toastDateMsg}）`);
    renderFlexconInventory();
  });
}

// 6. トランザクション変更モーダル（発注内容・受入内容・数量・納品予定日・拠点間移動ペア日付の変更）
function openEditTransactionModal(txId, data) {
  const tx = data.transactions.find(t => t.id === txId);
  if (!tx) return;
  const modalContainer = document.getElementById('flexconActionModalContainer');
  const isOrdered = tx.status === 'ordered';
  const isInbound = tx.type === 'inbound';

  // 拠点間移動ペア（-OUT / -IN）の自動検出
  const pairedTxId = (typeof tx.id === 'string' && tx.id.endsWith('-OUT'))
    ? tx.id.replace(/-OUT$/, '-IN')
    : ((typeof tx.id === 'string' && tx.id.endsWith('-IN')) ? tx.id.replace(/-IN$/, '-OUT') : null);
  const pairedTx = pairedTxId ? data.transactions.find(t => t.id === pairedTxId) : null;
  const isTransferPair = !!pairedTx;
  const transferOutTx = isTransferPair ? (tx.type === 'outbound' ? tx : pairedTx) : null;
  const transferInTx = isTransferPair ? (tx.type === 'inbound' ? tx : pairedTx) : null;

  const rawItems = (tx.items && Array.isArray(tx.items) && tx.items.length > 0)
    ? JSON.parse(JSON.stringify(tx.items))
    : [{
        item: tx.item || FLEXCON_ITEMS[0].id,
        name: (FLEXCON_ITEMS.find(i => i.id === tx.item) || {}).commonName || tx.item || '',
        spec: (FLEXCON_ITEMS.find(i => i.id === tx.item) || {}).spec || '',
        qty: tx.qty || 0,
        price: tx.price || 0,
        quoteNo: tx.quoteNo || ''
      }];

  modalContainer.innerHTML = `
    <div class="flexcon-modal-overlay" id="flexconEditModalOverlay">
      <div class="flexcon-modal-box" style="max-width: 720px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 20px;">${isTransferPair ? '🔄' : '✏️'}</span>
            <h3 style="margin: 0; font-size: 17px; font-weight: 800;">
              ${isTransferPair ? '拠点間移動データの変更（出荷日・入荷日対応）' : (isOrdered ? '発注・受入内容の変更' : (isInbound ? '入庫データの変更' : '出庫データの変更'))}
            </h3>
            <span style="font-size: 11px; background: rgba(37,99,235,0.1); color: var(--accent-blue); padding: 2px 8px; border-radius: 4px; font-weight: 700;">
              ${tx.orderNo || tx.id}
            </span>
          </div>
          <button type="button" id="btnCloseEditModal" style="background: none; border: none; font-size: 22px; cursor: pointer; color: var(--text-muted); line-height: 1;">✕</button>
        </div>

        <form id="modalEditForm" class="tool-form" novalidate>
          ${isTransferPair ? `
            <div style="background: rgba(37,99,235,0.05); border: 1px solid rgba(37,99,235,0.22); border-radius: 8px; padding: 12px 14px; margin-bottom: 14px;">
              <div style="font-size: 12px; font-weight: 800; color: var(--accent-blue); margin-bottom: 8px;">
                🔄 拠点間移動ペア設定（出荷元と納品先の日付・拠点を一括更新します）
              </div>
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 10px;">
                <div class="tool-group" style="margin: 0;">
                  <label for="mEditTransferFromLoc">📤 出荷元拠点（出庫） <span style="color:#ef4444;">*</span></label>
                  <select id="mEditTransferFromLoc" required>
                    ${FLEXCON_LOCATIONS.map(l => `<option value="${l}" ${l === transferOutTx.location ? 'selected' : ''}>${l}</option>`).join('')}
                  </select>
                </div>
                <div class="tool-group" style="margin: 0;">
                  <label for="mEditTransferToLoc">📥 納品先拠点（入庫） <span style="color:#ef4444;">*</span></label>
                  <select id="mEditTransferToLoc" required>
                    ${FLEXCON_LOCATIONS.map(l => `<option value="${l}" ${l === transferInTx.location ? 'selected' : ''}>${l}</option>`).join('')}
                  </select>
                </div>
              </div>
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                <div class="tool-group" style="margin: 0;">
                  <label for="mEditTransferOutDate">📤 出荷日（移動元の出庫日） <span style="color:#ef4444;">*</span></label>
                  <input type="date" id="mEditTransferOutDate" value="${transferOutTx.date}" required>
                </div>
                <div class="tool-group" style="margin: 0;">
                  <label for="mEditTransferInDate">📥 入荷日（納品先の受入日） <span style="color:#ef4444;">*</span></label>
                  <input type="date" id="mEditTransferInDate" value="${transferInTx.date}" required>
                </div>
              </div>
            </div>
          ` : `
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
            <div class="tool-group">
              <label for="mEditDate">${isOrdered ? '発注日' : '取引日'} <span style="color:#ef4444;">*</span></label>
              <input type="date" id="mEditDate" value="${tx.orderDate || tx.date}" required>
            </div>
            ${isOrdered ? `
              <div class="tool-group">
                <label for="mEditDueDate">納品予定日 <span style="color:#ef4444;">*</span></label>
                <input type="date" id="mEditDueDate" value="${tx.deliveryDueDate || tx.date}" required>
              </div>
            ` : `
              <div class="tool-group">
                <label for="mEditLocation">対象拠点 <span style="color:#ef4444;">*</span></label>
                <select id="mEditLocation" required>
                  ${FLEXCON_LOCATIONS.map(l => `<option value="${l}" ${l === tx.location ? 'selected' : ''}>${l}</option>`).join('')}
                </select>
              </div>
            `}
          </div>

          ${isOrdered ? `
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
              <div class="tool-group">
                <label for="mEditLocation">受入拠点 <span style="color:#ef4444;">*</span></label>
                <select id="mEditLocation" required>
                  ${FLEXCON_LOCATIONS.map(l => `<option value="${l}" ${l === tx.location ? 'selected' : ''}>${l}</option>`).join('')}
                </select>
              </div>
              <div class="tool-group">
                <label for="mEditSupplier">仕入先企業 <span style="color:#ef4444;">*</span></label>
                <select id="mEditSupplier" required>
                  ${FLEXCON_SUPPLIERS.map(s => `<option value="${s.name}" ${s.name === tx.supplier ? 'selected' : ''}>${s.name}</option>`).join('')}
                </select>
              </div>
            </div>
          ` : `
            <div class="tool-group">
              <label for="mEditParty">${isInbound ? '仕入先 / 納品元' : '出庫用途 / 納品先'}</label>
              <input type="text" id="mEditParty" value="${tx.supplier || tx.purpose || ''}">
            </div>
          `}
          `}

          <!-- 品目・数量・単価の内訳一覧 -->
          <div style="margin: 14px 0; background: var(--bg-primary); border: 1px solid var(--border-medium); border-radius: 8px; padding: 12px 14px;">
            <div style="font-size: 13px; font-weight: 800; color: var(--text-primary); margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
              <span>📦 明細・数量・単価の修正</span>
            </div>
            <div id="editItemsContainer" style="display: flex; flex-direction: column; gap: 8px;">
              ${rawItems.map((it, idx) => `
                <div class="edit-item-row" data-idx="${idx}" style="background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: 6px; padding: 8px 10px; display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 8px; align-items: center;">
                  <div>
                    <select class="edit-item-select" style="width: 100%; font-size: 12px; padding: 4px 6px;">
                      ${FLEXCON_ITEMS.map(i => `<option value="${i.id}" ${i.id === it.item ? 'selected' : ''}>【${i.commonName}】 ${i.name.split('　')[0]}</option>`).join('')}
                    </select>
                  </div>
                  <div>
                    <label style="font-size: 10px; color: var(--text-muted); display: block;">数量(枚)</label>
                    <input type="number" class="edit-item-qty" min="1" max="99999" value="${it.qty || 0}" style="width: 100%; font-size: 12px; padding: 4px 6px; font-weight: 700;">
                  </div>
                  <div>
                    <label style="font-size: 10px; color: var(--text-muted); display: block;">単価(円)</label>
                    <input type="number" class="edit-item-price" min="0" step="0.1" value="${it.price || 0}" style="width: 100%; font-size: 12px; padding: 4px 6px;">
                  </div>
                </div>
              `).join('')}
            </div>
          </div>

          ${renderOperatorSelectHtml('mEditOperator', '入力担当者 / 発注担当者', tx.operator || tx.ourContact || '畑山')}

          ${renderNoteSelectHtml('mEditNotePreset', 'mEditNote', (tx.note || '').replace(/"/g, '&quot;'))}

          <div style="display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap;">
            <button type="button" id="btnCancelEditModal" class="btn btn-secondary" style="flex: 1; padding: 11px;">キャンセル</button>
            <button type="submit" id="btnSaveEditOnly" class="btn btn-primary" style="flex: 2; padding: 11px; font-size: 13.5px; background: #2563eb;">💾 変更内容を保存する</button>
            ${isOrdered ? `
              <button type="button" id="btnSaveAndDeliver" class="btn btn-primary" style="flex: 2; padding: 11px; font-size: 13.5px; background: var(--accent-green); border-color: var(--accent-green);" title="修正した内容で直ちに納品受入を確定し、実在庫に反映します">
                ✅ この内容で受入完了にする
              </button>
            ` : ''}
          </div>
        </form>
      </div>
    </div>
  `;

  const closeModal = () => { modalContainer.innerHTML = ''; };
  document.getElementById('btnCloseEditModal').addEventListener('click', closeModal);
  setupModalOperatorAndNote('mEditOperator', 'mEditNotePreset', 'mEditNote');
  document.getElementById('btnCancelEditModal').addEventListener('click', closeModal);
  document.getElementById('flexconEditModalOverlay').addEventListener('click', (e) => {
    if (e.target.id === 'flexconEditModalOverlay') closeModal();
  });

  const collectEditedData = () => {
    const updatedRows = [];
    modalContainer.querySelectorAll('.edit-item-row').forEach(row => {
      const itId = row.querySelector('.edit-item-select').value;
      const itQty = parseInt(row.querySelector('.edit-item-qty').value, 10) || 0;
      const itPrice = parseFloat(row.querySelector('.edit-item-price').value) || 0;
      const itObj = FLEXCON_ITEMS.find(i => i.id === itId);
      updatedRows.push({
        item: itId,
        name: itObj ? itObj.commonName : itId,
        spec: itObj ? itObj.spec : '',
        qty: itQty,
        price: itPrice
      });
    });

    const noteVal = document.getElementById('mEditNote').value.trim();
    const opVal = getSelectedOperator('mEditOperator');

    if (isTransferPair) {
      const outDateVal = document.getElementById('mEditTransferOutDate').value;
      const inDateVal = document.getElementById('mEditTransferInDate').value;
      const fromLocVal = document.getElementById('mEditTransferFromLoc').value;
      const toLocVal = document.getElementById('mEditTransferToLoc').value;

      if (inDateVal < outDateVal) {
        alert(`⚠️ 入荷日（${inDateVal}）が出荷日（${outDateVal}）より前の日付になっています。`);
        return false;
      }
      if (fromLocVal === toLocVal) {
        alert(`⚠️ 出荷元拠点と納品先拠点が同じです。異なる拠点を選択してください。`);
        return false;
      }

      const dateDiffNote = outDateVal !== inDateVal ? `（出荷:${outDateVal} → 入荷:${inDateVal}）` : '';
      transferOutTx.date = outDateVal;
      transferOutTx.location = fromLocVal;
      transferOutTx.transferOutDate = outDateVal;
      transferOutTx.transferInDate = inDateVal;
      transferOutTx.transferFromLoc = fromLocVal;
      transferOutTx.transferToLoc = toLocVal;
      transferOutTx.purpose = `【拠点間移動】${toLocVal}宛${dateDiffNote}`;
      transferOutTx.operator = opVal;
      transferOutTx.ourContact = opVal;

      transferInTx.date = inDateVal;
      transferInTx.location = toLocVal;
      transferInTx.transferOutDate = outDateVal;
      transferInTx.transferInDate = inDateVal;
      transferInTx.transferFromLoc = fromLocVal;
      transferInTx.transferToLoc = toLocVal;
      transferInTx.supplier = `【拠点間移動】${fromLocVal}発${dateDiffNote}`;
      transferInTx.operator = opVal;
      transferInTx.ourContact = opVal;

      tx.note = noteVal;
      if (updatedRows.length > 0) {
        const totalQ = updatedRows.reduce((s, it) => s + it.qty, 0);
        [transferOutTx, transferInTx].forEach(target => {
          target.items = JSON.parse(JSON.stringify(updatedRows));
          target.item = updatedRows[0].item;
          target.qty = totalQ;
          target.price = updatedRows[0].price;
        });
      }
      return true;
    }

    const dateVal = document.getElementById('mEditDate').value;
    const locVal = document.getElementById('mEditLocation').value;

    tx.date = dateVal;
    tx.location = locVal;
    tx.note = noteVal;
    tx.operator = opVal;
    tx.ourContact = opVal;
    if (isOrdered) {
      tx.orderDate = dateVal;
      tx.deliveryDueDate = document.getElementById('mEditDueDate').value;
      tx.supplier = document.getElementById('mEditSupplier').value;
    } else {
      const party = document.getElementById('mEditParty').value.trim();
      if (isInbound) tx.supplier = party;
      else tx.purpose = party;
    }

    if (updatedRows.length > 0) {
      tx.items = updatedRows;
      tx.item = updatedRows[0].item;
      tx.qty = updatedRows.reduce((s, it) => s + it.qty, 0);
      tx.price = updatedRows[0].price;
    }
    return true;
  };

  // 1. 変更保存のみ
  document.getElementById('modalEditForm').addEventListener('submit', (e) => {
    e.preventDefault();
    if (collectEditedData() === false) return;
    saveFlexconData(data);
    closeModal();
    showToast("💾 データを正常に更新・保存しました");
    renderFlexconInventory();
  });

  // 2. この内容で受入完了にする
  if (isOrdered && document.getElementById('btnSaveAndDeliver')) {
    document.getElementById('btnSaveAndDeliver').addEventListener('click', () => {
      if (collectEditedData() === false) return;
      const effectiveDate = tx.deliveryDueDate || tx.orderDate || new Date().toISOString().split('T')[0];
      tx.status = 'delivered';
      tx.date = effectiveDate;
      saveFlexconData(data);
      closeModal();
      showToast(`✨ 変更内容を保存し、納品受入を完了しました（${effectiveDate}付で実在庫に計上）`);
      renderFlexconInventory();
    });
  }
}

// 7. 入出庫全履歴帳簿（ソート＆保管場所フィルター対応）
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
    if (ledgerFilterOperator !== 'all') {
      const op = tx.operator || tx.ourContact || '畑山';
      if (op !== ledgerFilterOperator) return false;
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
        <button class="btn btn-secondary" id="btnResetFlexconData" style="font-size: 11px; color: #ef4444; border-color: rgba(239,68,68,0.3);">🔄 9月末確定データにリセット</button>
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
          <label for="ledgerFilterOperatorSelect" style="font-size: 12px; font-weight: 700; color: #7c3aed;">👤 担当者:</label>
          <select id="ledgerFilterOperatorSelect" style="padding: 4px 10px; font-size: 12px; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-card); color: var(--text-primary); font-weight: 700;">
            <option value="all" ${ledgerFilterOperator === 'all' ? 'selected' : ''}>すべての担当者（全員）</option>
            ${FLEXCON_OPERATORS.map(op => `<option value="${op}" ${ledgerFilterOperator === op ? 'selected' : ''}>👤 ${op} 担当分のみ</option>`).join('')}
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

        ${(ledgerFilterMonth !== 'all' || ledgerFilterLoc !== 'all' || ledgerFilterType !== 'all' || ledgerFilterOperator !== 'all') ? `
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
              <th style="padding: 8px; text-align: center;">担当者</th>
              <th style="padding: 8px;">仕入先 / 発注日 / 用途</th>
              <th style="padding: 8px;">備考 / 発注No</th>
              <th style="padding: 8px; text-align: center; min-width: 110px;">操作</th>
            </tr>
          </thead>
          <tbody>
            ${filteredList.length === 0 ? `
              <tr>
                <td colspan="11" style="text-align: center; padding: 24px; color: var(--text-muted);">
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
              const isTransferTx = !!(tx.transferPairId || (typeof tx.id === 'string' && (tx.id.endsWith('-OUT') || tx.id.endsWith('-IN'))) || (tx.supplier && tx.supplier.startsWith('【拠点間移動】')) || (tx.purpose && tx.purpose.startsWith('【拠点間移動】')));
              const hasSplitTransferDates = isTransferTx && tx.transferOutDate && tx.transferInDate && tx.transferOutDate !== tx.transferInDate;

              return `
                <tr style="${isOverdue ? 'background: rgba(239,68,68,0.04);' : (isOrdered ? 'background: rgba(245,158,11,0.03);' : '')}">
                  <td style="padding: 8px; font-weight: 600;">
                    <div>${displayDate}</div>
                    ${hasSplitTransferDates ? `
                      <span style="font-size: 10px; color: var(--accent-blue); font-weight: 700; display: block; line-height: 1.25; margin-top: 2px;">
                        ${isInbound ? `📤出荷: ${tx.transferOutDate}` : `📥入荷: ${tx.transferInDate}`}
                      </span>
                    ` : ''}
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
                        ${isTransferTx ? (isInbound ? '🔄 移動入庫' : '🔄 移動出庫') : (isInbound ? '📥 入庫' : '📤 出庫')}
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
                  <td style="padding: 8px; text-align: center; white-space: nowrap;">
                    <span style="display: inline-flex; align-items: center; gap: 3px; padding: 2px 8px; border-radius: 12px; background: rgba(124,58,237,0.08); color: #6d28d9; font-size: 11px; font-weight: 800; border: 1px solid rgba(124,58,237,0.2);">
                      👤 ${tx.operator || tx.ourContact || '畑山'}
                    </span>
                  </td>
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
                      <button class="btn btn-secondary btn-ledger-edit" data-id="${tx.id}" style="padding: 3px 8px; font-size: 11.5px; display: inline-flex; align-items: center; gap: 3px; font-weight: 700; color: #334155; border-color: #cbd5e1; background: #f8fafc; cursor: pointer;" title="数量・内容・納品予定日を変更">
                        ✏️ 変更
                      </button>
                      ${(isInbound && !isTransferTx) ? `
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
  document.getElementById('ledgerFilterOperatorSelect').addEventListener('change', (e) => {
    ledgerFilterOperator = e.target.value;
    renderFlexconLedger(container, data);
  });

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
      ledgerFilterOperator = 'all';
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

  // 変更ボタン（発注・受入・入出庫データの修正）
  container.querySelectorAll('.btn-ledger-edit').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const button = e.currentTarget || e.target.closest('.btn-ledger-edit');
      const id = button ? button.dataset.id : null;
      if (id) openEditTransactionModal(id, data);
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

  // レコード削除（拠点間移動ペアの場合は出庫・入庫ペア一括削除に対応）
  container.querySelectorAll('.btn-delete-tx').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const button = e.currentTarget || e.target.closest('.btn-delete-tx');
      const id = button ? button.dataset.id : null;
      if (!id) return;
      const pairedId = (typeof id === 'string' && id.endsWith('-OUT'))
        ? id.replace(/-OUT$/, '-IN')
        : ((typeof id === 'string' && id.endsWith('-IN')) ? id.replace(/-IN$/, '-OUT') : null);
      const hasPair = pairedId && data.transactions.some(t => t.id === pairedId);
      const msg = hasPair
        ? "このレコードは拠点間移動のペア伝票です。\n在庫相違を防ぐため、対応する出庫・入庫の両方のレコードを削除しますか？"
        : "このレコードを削除してもよろしいですか？";
      if (confirm(msg)) {
        data.transactions = data.transactions.filter(t => t.id !== id && (!hasPair || t.id !== pairedId));
        saveFlexconData(data);
        showToast(hasPair ? "🗑️ 拠点間移動ペアレコードを削除しました" : "🗑️ レコードを削除しました");
        renderFlexconInventory();
      }
    });
  });

  // リセットボタン
  document.getElementById('btnResetFlexconData').addEventListener('click', () => {
    if (confirm("2026年9月末の確定在庫データにリセットしますか？\n10月以降に追加・変更されたトランザクションは消去され、全端末（クラウド）に反映されます。")) {
      const resetData = JSON.parse(JSON.stringify(INITIAL_FLEXCON_DATA));
      resetData.migrations = { sep2026Opening: new Date().toISOString() };
      saveFlexconData(resetData);
      showToast("🔄 9月末確定データにリセットしました");
      renderFlexconInventory();
    }
  });
}

// 7. 月末棚卸し＆CSVエクスポート
function renderFlexconCheck(container, data) {
  const asOf = currentFlexconAsOf === 'latest' ? null : currentFlexconAsOf;
  const matrix = calculateStockMatrix(data.transactions, asOf);

  container.innerHTML = `
    <div class="tool-card" style="margin-bottom: 20px;">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 14px;">
        <h3 style="margin: 0;">📑 月末実在庫 棚卸し照合・差額調整 (${currentFlexconAsOf === 'latest' ? '現在時点' : currentFlexconAsOf + ' 時点'})</h3>
        <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
          <select id="asOfSelectCheck" style="padding: 6px 12px; font-size: 12.5px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-medium); background: var(--bg-primary); color: var(--text-primary);">
            ${buildAsOfSelectOptionsHtml(data.transactions, currentFlexconAsOf)}
          </select>
          <button class="btn btn-primary" id="btnExportFlexconCSV" style="background: linear-gradient(135deg, var(--accent-green), #107c41); color: #fff; padding: 8px 16px; font-size: 13px;">
            📥 全在庫・入出庫データをCSVエクスポート
          </button>
        </div>
      </div>
      <p style="font-size: 12px; color: var(--text-muted); margin-top: 0; margin-bottom: 16px;">
        各拠点の月末棚卸カウント数を入力し、指定基準日時点のシステム帳簿理論在庫との差額を照合します。
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

  const asOfSelectCheck = document.getElementById('asOfSelectCheck');
  if (asOfSelectCheck) {
    asOfSelectCheck.addEventListener('change', (e) => {
      currentFlexconAsOf = e.target.value;
      renderFlexconCheck(container, data);
    });
  }

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

// ===== 4. マスター管理画面描画（セルフメンテナンス機能） =====
let activeMasterSubTab = 'locations'; // 'locations', 'items', 'suppliers', 'backup'

function renderFlexconMaster(container) {
  refreshActiveMaster();

  container.innerHTML = `
    <div style="background: #ffffff; border-radius: 12px; border: 1px solid var(--border-medium); padding: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.04); margin-bottom: 24px;">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px; margin-bottom: 20px;">
        <div>
          <h2 style="font-size: 18px; font-weight: 800; color: var(--text-primary); margin: 0 0 6px 0; display: flex; align-items: center; gap: 8px;">
            <span>⚙️</span> マスター管理（登録・変更・安全在庫設定）
          </h2>
          <p style="font-size: 13px; color: var(--text-muted); margin: 0;">
            拠点、商品（資材）、仕入先のマスター情報を直接追加・編集・削除できます。拠点ごとの安全在庫数の調整も即時反映されます。
          </p>
        </div>
        <div style="display: flex; gap: 8px;">
          <button id="btnResetMasterDefault" style="padding: 7px 14px; font-size: 12.5px; font-weight: 600; background: #fff1f2; color: #e11d48; border: 1px solid #fecdd3; border-radius: 8px; cursor: pointer;">
            🔄 初期マスターへ復元
          </button>
        </div>
      </div>

      <!-- サブタブ切替バー -->
      <div style="display: flex; gap: 8px; border-bottom: 2px solid var(--border-subtle); padding-bottom: 12px; margin-bottom: 20px; overflow-x: auto;">
        <button class="master-subtab-btn ${activeMasterSubTab === 'locations' ? 'active' : ''}" data-tab="locations" style="padding: 8px 16px; font-size: 13.5px; font-weight: 700; border-radius: 8px; border: none; cursor: pointer; transition: all 0.2s; ${activeMasterSubTab === 'locations' ? 'background: #7c3aed; color: #ffffff;' : 'background: #f1f5f9; color: #475569;'}">
          🏢 拠点マスター (${FLEXCON_LOCATIONS.length}件)
        </button>
        <button class="master-subtab-btn ${activeMasterSubTab === 'items' ? 'active' : ''}" data-tab="items" style="padding: 8px 16px; font-size: 13.5px; font-weight: 700; border-radius: 8px; border: none; cursor: pointer; transition: all 0.2s; ${activeMasterSubTab === 'items' ? 'background: #7c3aed; color: #ffffff;' : 'background: #f1f5f9; color: #475569;'}">
          📦 商品マスター (${FLEXCON_ITEMS.length}品目)
        </button>
                <button class="master-subtab-btn ${activeMasterSubTab === 'suppliers' ? 'active' : ''}" data-tab="suppliers" style="padding: 8px 16px; font-size: 13.5px; font-weight: 700; border-radius: 8px; border: none; cursor: pointer; transition: all 0.2s; ${activeMasterSubTab === 'suppliers' ? 'background: #7c3aed; color: #ffffff;' : 'background: #f1f5f9; color: #475569;'}">
          🏭 仕入先マスター (${FLEXCON_SUPPLIERS.length}社)
        </button>
        <button class="master-subtab-btn ${activeMasterSubTab === 'notes' ? 'active' : ''}" data-tab="notes" style="padding: 8px 16px; font-size: 13.5px; font-weight: 700; border-radius: 8px; border: none; cursor: pointer; transition: all 0.2s; ${activeMasterSubTab === 'notes' ? 'background: #7c3aed; color: #ffffff;' : 'background: #f1f5f9; color: #475569;'}">
          📝 備考マスター (${FLEXCON_NOTE_PRESETS.length}件)
        </button>
        <button class="master-subtab-btn ${activeMasterSubTab === 'operators' ? 'active' : ''}" data-tab="operators" style="padding: 8px 16px; font-size: 13.5px; font-weight: 700; border-radius: 8px; border: none; cursor: pointer; transition: all 0.2s; ${activeMasterSubTab === 'operators' ? 'background: #7c3aed; color: #ffffff;' : 'background: #f1f5f9; color: #475569;'}">
          👤 担当者マスター (${FLEXCON_OPERATORS.length}名)
        </button>
        <button class="master-subtab-btn ${activeMasterSubTab === 'backup' ? 'active' : ''}" data-tab="backup" style="padding: 8px 16px; font-size: 13.5px; font-weight: 700; border-radius: 8px; border: none; cursor: pointer; transition: all 0.2s; ${activeMasterSubTab === 'backup' ? 'background: #7c3aed; color: #ffffff;' : 'background: #f1f5f9; color: #475569;'}">
          💾 バックアップ・データ取込
        </button>
      </div>

      <!-- 各サブタブコンテンツ -->
      <div id="masterSubTabContent"></div>
    </div>
  `;

  // サブタブイベント
  container.querySelectorAll('.master-subtab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      activeMasterSubTab = btn.dataset.tab;
      renderFlexconMaster(container);
    });
  });

  // 初期復元ボタン
  document.getElementById('btnResetMasterDefault').addEventListener('click', () => {
    if (confirm("2026年10月13日提出の初期マスター状態（全9拠点・全9商品・全3仕入先）にリセットしますか？\n※個別に変更した内容がある場合は初期化されます。")) {
      localStorage.removeItem('cascadia_flexcon_master_v6');
      refreshActiveMaster();
      showToast("🔄 初期マスターに復元しました");
      renderFlexconMaster(container);
    }
  });

  const subContainer = document.getElementById('masterSubTabContent');
    if (activeMasterSubTab === 'locations') renderMasterLocations(subContainer);
  else if (activeMasterSubTab === 'items') renderMasterItems(subContainer);
  else if (activeMasterSubTab === 'suppliers') renderMasterSuppliers(subContainer);
  else if (activeMasterSubTab === 'notes') renderMasterNotes(subContainer);
  else if (activeMasterSubTab === 'operators') renderMasterOperators(subContainer);
  else if (activeMasterSubTab === 'backup') renderMasterBackup(subContainer);
}

// ① 拠点マスター画面
function renderMasterLocations(container) {
  let html = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <div style="font-size: 14px; font-weight: 700; color: var(--text-primary);">
        全 ${FLEXCON_LOCATIONS.length} 拠点一覧（取扱商品・安全在庫設定）
      </div>
      <button id="btnAddNewLocation" style="padding: 7px 15px; font-size: 13px; font-weight: 700; background: #7c3aed; color: #ffffff; border: none; border-radius: 8px; cursor: pointer;">
        ➕ 新規拠点を追加
      </button>
    </div>

    <div style="display: flex; flex-direction: column; gap: 16px;">
  `;

  FLEXCON_LOCATIONS.forEach(loc => {
    const detail = FLEXCON_LOCATION_DETAILS[loc] || {};
    const itemStocks = detail.itemStocks || {};
    const itemKeys = Object.keys(itemStocks);

    html += `
      <div style="background: #faf5ff; border: 1px solid #e9d5ff; border-radius: 10px; padding: 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.03);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px; margin-bottom: 12px; border-bottom: 1px solid #f3e8ff; padding-bottom: 10px;">
          <div>
            <div style="font-size: 16px; font-weight: 800; color: #581c87; display: flex; align-items: center; gap: 8px;">
              <span>🏢</span> ${loc}
            </div>
            <div style="font-size: 12.5px; color: #6b21a8; margin-top: 3px;">
              ${detail.postalCode || ''} ${detail.address || '(住所未登録)'}
              ${detail.tel ? ` / TEL: ${detail.tel}` : ''}
              ${detail.recipient ? ` / 受取担当: ${detail.recipient}` : ''}
              ${detail.deliveryNote ? ` / <span style="color:#b91c1c; font-weight:600;">※${detail.deliveryNote}</span>` : ''}
            </div>
          </div>
          <div style="display: flex; gap: 6px;">
            <button class="btn-edit-loc" data-loc="${loc}" style="padding: 5px 10px; font-size: 12px; font-weight: 600; background: #ffffff; color: #7c3aed; border: 1px solid #c084fc; border-radius: 6px; cursor: pointer;">
              ✏️ 拠点情報編集
            </button>
            <button class="btn-del-loc" data-loc="${loc}" style="padding: 5px 10px; font-size: 12px; font-weight: 600; background: #ffffff; color: #ef4444; border: 1px solid #fca5a5; border-radius: 6px; cursor: pointer;">
              🗑️ 削除
            </button>
          </div>
        </div>

        <div>
          <div style="font-size: 12.5px; font-weight: 700; color: #6b21a8; margin-bottom: 8px;">
            取扱資材および安全在庫数（下回ると要手配アラートが点灯）:
          </div>
          <div style="display: flex; flex-wrap: wrap; gap: 12px;">
            ${itemKeys.length > 0 ? itemKeys.map(k => `
              <div style="background: #ffffff; border: 1px solid #d8b4fe; border-radius: 8px; padding: 8px 12px; display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 12.5px; font-weight: 600; color: #374151;">${k}:</span>
                <input type="number" class="input-safety-stock" data-loc="${loc}" data-item="${k}" value="${itemStocks[k]}" min="0" style="width: 75px; padding: 4px 6px; font-size: 13px; font-weight: 700; text-align: right; border: 1px solid #cbd5e1; border-radius: 4px;">
                <span style="font-size: 11px; color: #64748b;">枚</span>
              </div>
            `).join('') : '<div style="font-size: 12px; color: #94a3b8;">取扱商品の安全在庫は未登録です</div>'}
            <button class="btn-save-stock" data-loc="${loc}" style="padding: 6px 12px; font-size: 12px; font-weight: 700; background: #9333ea; color: #ffffff; border: none; border-radius: 6px; cursor: pointer;">
              💾 この拠点の安全在庫を保存
            </button>
          </div>
        </div>
      </div>
    `;
  });

  html += `</div>`;
  container.innerHTML = html;

  // 安全在庫保存
  container.querySelectorAll('.btn-save-stock').forEach(btn => {
    btn.addEventListener('click', () => {
      const loc = btn.dataset.loc;
      const inputs = container.querySelectorAll(`.input-safety-stock[data-loc="${loc}"]`);
      inputs.forEach(inp => {
        const itemKey = inp.dataset.item;
        const val = parseInt(inp.value, 10) || 0;
        if (!activeFlexconMaster.locations[loc].itemStocks) activeFlexconMaster.locations[loc].itemStocks = {};
        activeFlexconMaster.locations[loc].itemStocks[itemKey] = val;
      });
      saveFlexconMaster(activeFlexconMaster);
      showToast(`✅ ${loc} の安全在庫設定を保存しました`);
    });
  });

  // 拠点編集
  container.querySelectorAll('.btn-edit-loc').forEach(btn => {
    btn.addEventListener('click', () => {
      openLocationEditModal(btn.dataset.loc);
    });
  });

  // 拠点削除
  container.querySelectorAll('.btn-del-loc').forEach(btn => {
    btn.addEventListener('click', () => {
      const loc = btn.dataset.loc;
      if (confirm(`拠点「${loc}」を削除しますか？\n※既存の入出庫履歴にこの拠点が含まれている場合はご注意ください。`)) {
        delete activeFlexconMaster.locations[loc];
        saveFlexconMaster(activeFlexconMaster);
        showToast(`🗑️ ${loc} を削除しました`);
        renderMasterLocations(container);
      }
    });
  });

  // 新規拠点追加
  document.getElementById('btnAddNewLocation').addEventListener('click', () => {
    openLocationEditModal(null);
  });
}

// 拠点編集モーダル
function openLocationEditModal(locKey) {
  const isNew = !locKey;
  const detail = isNew ? {
    company: "",
    recipient: "",
    postalCode: "",
    address: "",
    tel: "",
    deliveryNote: "",
    itemStocks: {}
  } : (FLEXCON_LOCATION_DETAILS[locKey] || {});

  const modalOverlay = document.createElement('div');
  modalOverlay.style.cssText = 'position: fixed; inset: 0; background: rgba(15,23,42,0.6); backdrop-filter: blur(4px); z-index: 99999; display: flex; align-items: center; justify-content: center; padding: 20px;';

  modalOverlay.innerHTML = `
    <div style="background: #ffffff; border-radius: 14px; max-width: 560px; width: 100%; max-height: 90vh; overflow-y: auto; padding: 24px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.2);">
      <h3 style="font-size: 17px; font-weight: 800; color: #1e293b; margin: 0 0 16px 0;">
        ${isNew ? '🏢 新規拠点の追加' : `🏢 拠点情報の編集: ${locKey}`}
      </h3>
      <form id="formLocEdit" style="display: flex; flex-direction: column; gap: 12px;">
        <div>
          <label style="font-size: 12.5px; font-weight: 700; color: #475569;">拠点名（必須）</label>
          <input type="text" id="mLocName" value="${locKey || ''}" required style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
        </div>
        <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 10px;">
          <div>
            <label style="font-size: 12.5px; font-weight: 700; color: #475569;">郵便番号</label>
            <input type="text" id="mLocPostal" value="${detail.postalCode || ''}" placeholder="例: 〒810-0071" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
          </div>
          <div>
            <label style="font-size: 12.5px; font-weight: 700; color: #475569;">電話番号</label>
            <input type="text" id="mLocTel" value="${detail.tel || ''}" placeholder="例: 092-752-5586" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
          </div>
        </div>
        <div>
          <label style="font-size: 12.5px; font-weight: 700; color: #475569;">納品先住所（倉庫・ビル名まで）</label>
          <input type="text" id="mLocAddress" value="${detail.address || ''}" placeholder="例: 福岡県福岡市中央区那の津5丁目9-23" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
          <div>
            <label style="font-size: 12.5px; font-weight: 700; color: #475569;">受取担当者名</label>
            <input type="text" id="mLocRecipient" value="${detail.recipient || ''}" placeholder="例: 営業１課　祐谷様" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
          </div>
          <div>
            <label style="font-size: 12.5px; font-weight: 700; color: #475569;">納品受入の注意点</label>
            <input type="text" id="mLocNote" value="${detail.deliveryNote || ''}" placeholder="例: 受入れは平日のみ" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
          </div>
        </div>

        <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 14px;">
          <button type="button" id="btnCancelLocEdit" style="padding: 8px 16px; font-size: 13px; font-weight: 600; background: #f1f5f9; color: #475569; border: none; border-radius: 6px; cursor: pointer;">
            キャンセル
          </button>
          <button type="submit" style="padding: 8px 18px; font-size: 13px; font-weight: 700; background: #7c3aed; color: #ffffff; border: none; border-radius: 6px; cursor: pointer;">
            💾 保存する
          </button>
        </div>
      </form>
    </div>
  `;

  document.body.appendChild(modalOverlay);

  document.getElementById('btnCancelLocEdit').addEventListener('click', () => {
    document.body.removeChild(modalOverlay);
  });

  document.getElementById('formLocEdit').addEventListener('submit', (e) => {
    e.preventDefault();
    const newName = document.getElementById('mLocName').value.trim();
    if (!newName) return;

    const postal = document.getElementById('mLocPostal').value.trim();
    const tel = document.getElementById('mLocTel').value.trim();
    const address = document.getElementById('mLocAddress').value.trim();
    const recipient = document.getElementById('mLocRecipient').value.trim();
    const note = document.getElementById('mLocNote').value.trim();

    // 既存拠点のキー名変更時
    if (!isNew && locKey !== newName) {
      delete activeFlexconMaster.locations[locKey];
    }

    const prevStocks = detail.itemStocks || {};
    activeFlexconMaster.locations[newName] = {
      company: newName,
      recipient: recipient,
      contacts: recipient ? [recipient] : ["業務ご担当者様"],
      postalCode: postal,
      address: address,
      tel: tel,
      deliveryNote: note,
      itemStocks: prevStocks,
      presets: [
        {
          name: `${newName}（標準）`,
          company: newName,
          recipient: recipient,
          postalCode: postal,
          address: address,
          tel: tel
        }
      ]
    };

    saveFlexconMaster(activeFlexconMaster);
    document.body.removeChild(modalOverlay);
    showToast(`✅ 拠点「${newName}」を保存しました`);
    const container = document.getElementById('masterSubTabContent');
    if (container) renderMasterLocations(container);
  });
}

// ② 商品マスター画面
function renderMasterItems(container) {
  let html = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <div style="font-size: 14px; font-weight: 700; color: var(--text-primary);">
        全 ${FLEXCON_ITEMS.length} 品目一覧（社内通称・正式品名・基準単価・主な仕入先）
      </div>
      <button id="btnAddNewItem" style="padding: 7px 15px; font-size: 13px; font-weight: 700; background: #7c3aed; color: #ffffff; border: none; border-radius: 8px; cursor: pointer;">
        ➕ 新規商品を追加
      </button>
    </div>

    <div style="overflow-x: auto; background: #ffffff; border: 1px solid var(--border-medium); border-radius: 10px;">
      <table style="width: 100%; border-collapse: collapse; font-size: 13px; text-align: left;">
        <thead>
          <tr style="background: #f8fafc; border-bottom: 2px solid var(--border-medium); color: #475569; font-weight: 700;">
            <th style="padding: 10px 12px;">社内通称（画面表示）</th>
            <th style="padding: 10px 12px;">正式品名（発注書用）</th>
            <th style="padding: 10px 12px;">規格・仕様</th>
            <th style="padding: 10px 12px; text-align: right;">基準単価</th>
            <th style="padding: 10px 12px;">主な仕入先</th>
            <th style="padding: 10px 12px;">備考</th>
            <th style="padding: 10px 12px; text-align: center;">操作</th>
          </tr>
        </thead>
        <tbody>
  `;

  FLEXCON_ITEMS.forEach(it => {
    html += `
      <tr style="border-bottom: 1px solid var(--border-subtle);">
        <td style="padding: 10px 12px; font-weight: 700; color: #1e293b;">${it.commonName}</td>
        <td style="padding: 10px 12px; color: #334155;">${it.name || '-'}</td>
        <td style="padding: 10px 12px; color: #64748b; font-size: 12px;">${it.spec || '-'}</td>
        <td style="padding: 10px 12px; text-align: right; font-weight: 700; color: #7c3aed;">
          ${it.defaultPrice > 0 ? `¥${it.defaultPrice.toLocaleString()}` : '-'}
        </td>
        <td style="padding: 10px 12px; color: #475569;">${it.defaultSupplier || '-'}</td>
        <td style="padding: 10px 12px; color: #64748b; font-size: 11.5px;">${it.note || '-'}</td>
        <td style="padding: 10px 12px; text-align: center;">
          <div style="display: flex; gap: 4px; justify-content: center;">
            <button class="btn-edit-item" data-id="${it.id}" style="padding: 4px 8px; font-size: 11.5px; background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; border-radius: 4px; cursor: pointer;">✏️</button>
            <button class="btn-del-item" data-id="${it.id}" style="padding: 4px 8px; font-size: 11.5px; background: #fff1f2; color: #ef4444; border: 1px solid #fecdd3; border-radius: 4px; cursor: pointer;">🗑️</button>
          </div>
        </td>
      </tr>
    `;
  });

  html += `
        </tbody>
      </table>
    </div>
  `;

  container.innerHTML = html;

  container.querySelectorAll('.btn-edit-item').forEach(b => {
    b.addEventListener('click', () => {
      openItemEditModal(b.dataset.id);
    });
  });

  container.querySelectorAll('.btn-del-item').forEach(b => {
    b.addEventListener('click', () => {
      const id = b.dataset.id;
      if (confirm(`商品「${id}」を削除しますか？`)) {
        activeFlexconMaster.items = activeFlexconMaster.items.filter(i => i.id !== id);
        saveFlexconMaster(activeFlexconMaster);
        showToast(`🗑️ 商品を削除しました`);
        renderMasterItems(container);
      }
    });
  });

  document.getElementById('btnAddNewItem').addEventListener('click', () => {
    openItemEditModal(null);
  });
}

function openItemEditModal(itemId) {
  const isNew = !itemId;
  const itemObj = isNew ? {
    id: "",
    commonName: "",
    name: "",
    spec: "",
    defaultPrice: 1000,
    defaultSupplier: "株式会社シオヤ",
    note: ""
  } : (FLEXCON_ITEMS.find(i => i.id === itemId) || {});

  const modalOverlay = document.createElement('div');
  modalOverlay.style.cssText = 'position: fixed; inset: 0; background: rgba(15,23,42,0.6); backdrop-filter: blur(4px); z-index: 99999; display: flex; align-items: center; justify-content: center; padding: 20px;';

  modalOverlay.innerHTML = `
    <div style="background: #ffffff; border-radius: 14px; max-width: 520px; width: 100%; padding: 24px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.2);">
      <h3 style="font-size: 17px; font-weight: 800; color: #1e293b; margin: 0 0 16px 0;">
        ${isNew ? '📦 新規商品（資材）の追加' : `📦 商品情報の編集: ${itemObj.commonName}`}
      </h3>
      <form id="formItemEdit" style="display: flex; flex-direction: column; gap: 12px;">
        <div>
          <label style="font-size: 12.5px; font-weight: 700; color: #475569;">社内通称（画面表示・必須）</label>
          <input type="text" id="mItemCommon" value="${itemObj.commonName || ''}" required placeholder="例: フレコンSNS-1" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
        </div>
        <div>
          <label style="font-size: 12.5px; font-weight: 700; color: #475569;">正式品名（発注書印字用・必須）</label>
          <input type="text" id="mItemFormal" value="${itemObj.name || ''}" required placeholder="例: フレコンワンウェイバッグSNS-1 上下全開タイプ" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
        </div>
        <div>
          <label style="font-size: 12.5px; font-weight: 700; color: #475569;">規格・仕様</label>
          <input type="text" id="mItemSpec" value="${itemObj.spec || ''}" placeholder="例: φ1100×1200 / 耐荷重1t" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
          <div>
            <label style="font-size: 12.5px; font-weight: 700; color: #475569;">基準単価（円）</label>
            <input type="number" id="mItemPrice" value="${itemObj.defaultPrice || 0}" step="0.1" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
          </div>
          <div>
            <label style="font-size: 12.5px; font-weight: 700; color: #475569;">主な仕入先</label>
            <input type="text" id="mItemSup" value="${itemObj.defaultSupplier || ''}" placeholder="例: 株式会社シオヤ" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
          </div>
        </div>
        <div>
          <label style="font-size: 12.5px; font-weight: 700; color: #475569;">備考</label>
          <input type="text" id="mItemNote" value="${itemObj.note || ''}" placeholder="例: 直送分 9/8見積書" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
        </div>

        <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 14px;">
          <button type="button" id="btnCancelItemEdit" style="padding: 8px 16px; font-size: 13px; font-weight: 600; background: #f1f5f9; color: #475569; border: none; border-radius: 6px; cursor: pointer;">
            キャンセル
          </button>
          <button type="submit" style="padding: 8px 18px; font-size: 13px; font-weight: 700; background: #7c3aed; color: #ffffff; border: none; border-radius: 6px; cursor: pointer;">
            💾 保存する
          </button>
        </div>
      </form>
    </div>
  `;

  document.body.appendChild(modalOverlay);

  document.getElementById('btnCancelItemEdit').addEventListener('click', () => {
    document.body.removeChild(modalOverlay);
  });

  document.getElementById('formItemEdit').addEventListener('submit', (e) => {
    e.preventDefault();
    const common = document.getElementById('mItemCommon').value.trim();
    const formal = document.getElementById('mItemFormal').value.trim();
    const spec = document.getElementById('mItemSpec').value.trim();
    const price = parseFloat(document.getElementById('mItemPrice').value) || 0;
    const sup = document.getElementById('mItemSup').value.trim();
    const note = document.getElementById('mItemNote').value.trim();

    const id = isNew ? common.replace(/[\s\(\)（）]/g, '_') : itemId;

    const newItem = {
      id: id,
      commonName: common,
      name: formal,
      spec: spec,
      defaultPrice: price,
      defaultSupplier: sup,
      note: note
    };

    if (isNew) {
      activeFlexconMaster.items.push(newItem);
    } else {
      const idx = activeFlexconMaster.items.findIndex(i => i.id === itemId);
      if (idx >= 0) activeFlexconMaster.items[idx] = newItem;
    }

    saveFlexconMaster(activeFlexconMaster);
    document.body.removeChild(modalOverlay);
    showToast(`✅ 商品「${common}」を保存しました`);
    const container = document.getElementById('masterSubTabContent');
    if (container) renderMasterItems(container);
  });
}

// ③ 仕入先マスター画面
function renderMasterSuppliers(container) {
  let html = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <div style="font-size: 14px; font-weight: 700; color: var(--text-primary);">
        全 ${FLEXCON_SUPPLIERS.length} 社一覧（発注先名・所在地・連絡先・担当者名）
      </div>
      <button id="btnAddNewSupplier" style="padding: 7px 15px; font-size: 13px; font-weight: 700; background: #7c3aed; color: #ffffff; border: none; border-radius: 8px; cursor: pointer;">
        ➕ 新規仕入先を追加
      </button>
    </div>

    <div style="overflow-x: auto; background: #ffffff; border: 1px solid var(--border-medium); border-radius: 10px;">
      <table style="width: 100%; border-collapse: collapse; font-size: 13px; text-align: left;">
        <thead>
          <tr style="background: #f8fafc; border-bottom: 2px solid var(--border-medium); color: #475569; font-weight: 700;">
            <th style="padding: 10px 12px;">仕入先名</th>
            <th style="padding: 10px 12px;">郵便番号・住所</th>
            <th style="padding: 10px 12px;">電話番号</th>
            <th style="padding: 10px 12px;">先方担当者名（発注書印字）</th>
            <th style="padding: 10px 12px; text-align: center;">操作</th>
          </tr>
        </thead>
        <tbody>
  `;

  FLEXCON_SUPPLIERS.forEach(s => {
    html += `
      <tr style="border-bottom: 1px solid var(--border-subtle);">
        <td style="padding: 10px 12px; font-weight: 700; color: #1e293b;">${s.name}</td>
        <td style="padding: 10px 12px; color: #475569;">${s.postalCode || ''} ${s.address || '-'}</td>
        <td style="padding: 10px 12px; color: #475569;">${s.tel || '-'}</td>
        <td style="padding: 10px 12px; font-weight: 600; color: #7c3aed;">${s.contactPerson || '-'}</td>
        <td style="padding: 10px 12px; text-align: center;">
          <div style="display: flex; gap: 4px; justify-content: center;">
            <button class="btn-edit-sup" data-name="${s.name}" style="padding: 4px 8px; font-size: 11.5px; background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; border-radius: 4px; cursor: pointer;">✏️</button>
            <button class="btn-del-sup" data-name="${s.name}" style="padding: 4px 8px; font-size: 11.5px; background: #fff1f2; color: #ef4444; border: 1px solid #fecdd3; border-radius: 4px; cursor: pointer;">🗑️</button>
          </div>
        </td>
      </tr>
    `;
  });

  html += `
        </tbody>
      </table>
    </div>
  `;

  container.innerHTML = html;

  container.querySelectorAll('.btn-edit-sup').forEach(b => {
    b.addEventListener('click', () => {
      openSupplierEditModal(b.dataset.name);
    });
  });

  container.querySelectorAll('.btn-del-sup').forEach(b => {
    b.addEventListener('click', () => {
      const name = b.dataset.name;
      if (confirm(`仕入先「${name}」を削除しますか？`)) {
        activeFlexconMaster.suppliers = activeFlexconMaster.suppliers.filter(s => s.name !== name);
        saveFlexconMaster(activeFlexconMaster);
        showToast(`🗑️ 仕入先を削除しました`);
        renderMasterSuppliers(container);
      }
    });
  });

  document.getElementById('btnAddNewSupplier').addEventListener('click', () => {
    openSupplierEditModal(null);
  });
}

function openSupplierEditModal(supName) {
  const isNew = !supName;
  const supObj = isNew ? {
    name: "",
    postalCode: "",
    address: "",
    tel: "",
    contactPerson: ""
  } : (FLEXCON_SUPPLIERS.find(s => s.name === supName) || {});

  const modalOverlay = document.createElement('div');
  modalOverlay.style.cssText = 'position: fixed; inset: 0; background: rgba(15,23,42,0.6); backdrop-filter: blur(4px); z-index: 99999; display: flex; align-items: center; justify-content: center; padding: 20px;';

  modalOverlay.innerHTML = `
    <div style="background: #ffffff; border-radius: 14px; max-width: 500px; width: 100%; padding: 24px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.2);">
      <h3 style="font-size: 17px; font-weight: 800; color: #1e293b; margin: 0 0 16px 0;">
        ${isNew ? '🏭 新規仕入先の追加' : `🏭 仕入先情報の編集: ${supName}`}
      </h3>
      <form id="formSupEdit" style="display: flex; flex-direction: column; gap: 12px;">
        <div>
          <label style="font-size: 12.5px; font-weight: 700; color: #475569;">仕入先名（必須）</label>
          <input type="text" id="mSupName" value="${supObj.name || ''}" required placeholder="例: 株式会社シオヤ" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
          <div>
            <label style="font-size: 12.5px; font-weight: 700; color: #475569;">郵便番号</label>
            <input type="text" id="mSupPostal" value="${supObj.postalCode || ''}" placeholder="例: 〒454-0027" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
          </div>
          <div>
            <label style="font-size: 12.5px; font-weight: 700; color: #475569;">電話番号</label>
            <input type="text" id="mSupTel" value="${supObj.tel || ''}" placeholder="例: 052-351-0531" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
          </div>
        </div>
        <div>
          <label style="font-size: 12.5px; font-weight: 700; color: #475569;">住所</label>
          <input type="text" id="mSupAddress" value="${supObj.address || ''}" placeholder="例: 愛知県名古屋市中川区広川町5-1" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
        </div>
        <div>
          <label style="font-size: 12.5px; font-weight: 700; color: #475569;">先方ご担当者様名（発注書印字用）</label>
          <input type="text" id="mSupContact" value="${supObj.contactPerson || ''}" placeholder="例: 太田様" style="width: 100%; box-sizing: border-box; padding: 8px 10px; font-size: 13.5px; border: 1px solid #cbd5e1; border-radius: 6px;">
        </div>

        <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 14px;">
          <button type="button" id="btnCancelSupEdit" style="padding: 8px 16px; font-size: 13px; font-weight: 600; background: #f1f5f9; color: #475569; border: none; border-radius: 6px; cursor: pointer;">
            キャンセル
          </button>
          <button type="submit" style="padding: 8px 18px; font-size: 13px; font-weight: 700; background: #7c3aed; color: #ffffff; border: none; border-radius: 6px; cursor: pointer;">
            💾 保存する
          </button>
        </div>
      </form>
    </div>
  `;

  document.body.appendChild(modalOverlay);

  document.getElementById('btnCancelSupEdit').addEventListener('click', () => {
    document.body.removeChild(modalOverlay);
  });

  document.getElementById('formSupEdit').addEventListener('submit', (e) => {
    e.preventDefault();
    const name = document.getElementById('mSupName').value.trim();
    const postal = document.getElementById('mSupPostal').value.trim();
    const tel = document.getElementById('mSupTel').value.trim();
    const address = document.getElementById('mSupAddress').value.trim();
    const contact = document.getElementById('mSupContact').value.trim();

    const newSup = {
      name: name,
      postalCode: postal,
      address: address,
      tel: tel,
      contactPerson: contact
    };

    if (isNew) {
      activeFlexconMaster.suppliers.push(newSup);
    } else {
      const idx = activeFlexconMaster.suppliers.findIndex(s => s.name === supName);
      if (idx >= 0) activeFlexconMaster.suppliers[idx] = newSup;
    }

    saveFlexconMaster(activeFlexconMaster);
    document.body.removeChild(modalOverlay);
    showToast(`✅ 仕入先「${name}」を保存しました`);
    const container = document.getElementById('masterSubTabContent');
    if (container) renderMasterSuppliers(container);
  });
}

// ④ バックアップ・取込画面
function renderMasterBackup(container) {
  container.innerHTML = `
    <div style="max-width: 680px; display: flex; flex-direction: column; gap: 20px;">
      <div style="background: #f8fafc; border: 1px solid var(--border-medium); border-radius: 10px; padding: 20px;">
        <h4 style="font-size: 15px; font-weight: 700; color: #1e293b; margin: 0 0 8px 0; display: flex; align-items: center; gap: 6px;">
          <span>📥</span> マスター設定のエクスポート（バックアップ）
        </h4>
        <p style="font-size: 13px; color: #64748b; margin: 0 0 14px 0;">
          現在設定されている全拠点・全商品・全仕入先のマスターデータ（安全在庫含む）をJSON形式のファイルとしてPCに保存します。他PCへの共有やバックアップ用にご活用ください。
        </p>
        <button id="btnExportMasterJson" style="padding: 8px 18px; font-size: 13px; font-weight: 700; background: #7c3aed; color: #ffffff; border: none; border-radius: 6px; cursor: pointer;">
          💾 マスターJSONをダウンロード
        </button>
      </div>

      <div style="background: #f8fafc; border: 1px solid var(--border-medium); border-radius: 10px; padding: 20px;">
        <h4 style="font-size: 15px; font-weight: 700; color: #1e293b; margin: 0 0 8px 0; display: flex; align-items: center; gap: 6px;">
          <span>📤</span> マスター設定のインポート（ファイル取込）
        </h4>
        <p style="font-size: 13px; color: #64748b; margin: 0 0 14px 0;">
          エクスポートしたマスター設定JSONファイルを選択して読み込み、現在のツールへ反映します。
        </p>
        <input type="file" id="inputImportMasterJson" accept=".json" style="font-size: 13px;">
      </div>
    </div>
  `;

  document.getElementById('btnExportMasterJson').addEventListener('click', () => {
    const jsonStr = JSON.stringify(activeFlexconMaster, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cascadia_flexcon_master_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("💾 マスター設定ファイルをダウンロードしました");
  });

  document.getElementById('inputImportMasterJson').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const parsed = JSON.parse(evt.target.result);
        if (parsed.locations && parsed.items && parsed.suppliers) {
          saveFlexconMaster(parsed);
          showToast("✅ マスター設定を取り込みました");
          renderFlexconMaster(document.getElementById('contentArea') || document.getElementById('flexconAppContent'));
        } else {
          alert("マスターファイルの形式が正しくありません（locations, items, suppliersが必要です）");
        }
      } catch (err) {
        alert("JSONファイルの解析に失敗しました: " + err.message);
      }
    };
    reader.readAsText(file);
  });
}


// ④ 備考マスター画面（定型選択肢の登録・変更・削除）
function renderMasterNotes(container) {
  let html = `
    <div style="background: #ffffff; border: 1px solid var(--border-medium); border-radius: 10px; padding: 20px; margin-bottom: 20px;">
      <h3 style="margin: 0 0 8px 0; font-size: 16px; font-weight: 800; color: #0f172a; display: flex; align-items: center; gap: 8px;">
        <span>📝</span> 備考マスター一覧（登録・追加・削除）
      </h3>
      <p style="font-size: 13px; color: var(--text-muted); margin: 0 0 16px 0;">
        入庫・出庫・拠点間移動・発注の各登録画面の「備考」プルダウンに表示される選択肢を直接管理できます。
      </p>

      <form id="formAddNotePreset" style="display: flex; gap: 10px; margin-bottom: 20px; max-width: 600px;">
        <input type="text" id="newNoteText" placeholder="新しい定型備考を入力（例: 破損交換、至急手配）" required style="flex: 1; padding: 9px 14px; border: 1px solid var(--border-medium); border-radius: 8px; font-size: 13.5px;">
        <button type="submit" style="padding: 9px 18px; font-size: 13px; font-weight: 700; background: #7c3aed; color: #ffffff; border: none; border-radius: 8px; cursor: pointer; white-space: nowrap;">
          ➕ 備考を追加
        </button>
      </form>

      <div style="border: 1px solid var(--border-subtle); border-radius: 8px; overflow: hidden;">
        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
          <thead>
            <tr style="background: #f8fafc; border-bottom: 1px solid var(--border-subtle); text-align: left;">
              <th style="padding: 10px 14px; width: 60px; text-align: center;">No.</th>
              <th style="padding: 10px 14px;">定型備考名称</th>
              <th style="padding: 10px 14px; text-align: center; width: 100px;">操作</th>
            </tr>
          </thead>
          <tbody>
            ${FLEXCON_NOTE_PRESETS.length === 0 ? `
              <tr><td colspan="3" style="text-align: center; padding: 20px; color: var(--text-muted);">備考マスターが未登録です。</td></tr>
            ` : FLEXCON_NOTE_PRESETS.map((note, idx) => `
              <tr style="border-bottom: 1px solid var(--border-subtle);">
                <td style="padding: 10px 14px; text-align: center; color: var(--text-muted); font-weight: 600;">${idx + 1}</td>
                <td style="padding: 10px 14px; font-weight: 600; color: #1e293b;">
                  <span>🏷️ ${note}</span>
                </td>
                <td style="padding: 10px 14px; text-align: center;">
                  <button class="btn-del-note" data-idx="${idx}" style="padding: 4px 10px; font-size: 11.5px; background: #fff1f2; color: #e11d48; border: 1px solid #fecdd3; border-radius: 6px; cursor: pointer; font-weight: 600;">
                    🗑️ 削除
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;

  container.innerHTML = html;

  // 新規備考登録イベント
  document.getElementById('formAddNotePreset').addEventListener('submit', (e) => {
    e.preventDefault();
    const val = document.getElementById('newNoteText').value.trim();
    if (!val) return;
    if (FLEXCON_NOTE_PRESETS.includes(val)) {
      alert("すでに登録済みの備考です。");
      return;
    }
    FLEXCON_NOTE_PRESETS.push(val);
    activeFlexconMaster.notePresets = FLEXCON_NOTE_PRESETS;
    saveFlexconMaster(activeFlexconMaster);
    showToast(`📝 備考マスターに「${val}」を追加しました`);
    renderMasterNotes(container);
  });

  // 備考削除イベント
  container.querySelectorAll('.btn-del-note').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx, 10);
      const targetNote = FLEXCON_NOTE_PRESETS[idx];
      if (confirm(`備考「${targetNote}」をマスターから削除しますか？`)) {
        FLEXCON_NOTE_PRESETS.splice(idx, 1);
        activeFlexconMaster.notePresets = FLEXCON_NOTE_PRESETS;
        saveFlexconMaster(activeFlexconMaster);
        showToast(`🗑️ 備考「${targetNote}」を削除しました`);
        renderMasterNotes(container);
      }
    });
  });
}

// ⑤ 担当者マスター画面（社内担当者・拠点担当者の管理）
function renderMasterOperators(container) {
  let html = `
    <div style="background: #ffffff; border: 1px solid var(--border-medium); border-radius: 10px; padding: 20px; margin-bottom: 20px;">
      <h3 style="margin: 0 0 8px 0; font-size: 16px; font-weight: 800; color: #0f172a; display: flex; align-items: center; gap: 8px;">
        <span>👤</span> 業務担当者マスター一覧
      </h3>
      <p style="font-size: 13px; color: var(--text-muted); margin: 0 0 16px 0;">
        入出庫登録時や発注書作成時に選択できる担当者（カスケディア業務部・各拠点担当者）を管理します。
      </p>

      <form id="formAddOperator" style="display: flex; gap: 10px; margin-bottom: 20px; max-width: 600px;">
        <input type="text" id="newOperatorText" placeholder="新しい担当者名を入力（例: 山田、佐藤）" required style="flex: 1; padding: 9px 14px; border: 1px solid var(--border-medium); border-radius: 8px; font-size: 13.5px;">
        <button type="submit" style="padding: 9px 18px; font-size: 13px; font-weight: 700; background: #7c3aed; color: #ffffff; border: none; border-radius: 8px; cursor: pointer; white-space: nowrap;">
          ➕ 担当者を追加
        </button>
      </form>

      <div style="border: 1px solid var(--border-subtle); border-radius: 8px; overflow: hidden;">
        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
          <thead>
            <tr style="background: #f8fafc; border-bottom: 1px solid var(--border-subtle); text-align: left;">
              <th style="padding: 10px 14px; width: 60px; text-align: center;">No.</th>
              <th style="padding: 10px 14px;">担当者名</th>
              <th style="padding: 10px 14px; text-align: center; width: 100px;">操作</th>
            </tr>
          </thead>
          <tbody>
            ${FLEXCON_OPERATORS.length === 0 ? `
              <tr><td colspan="3" style="text-align: center; padding: 20px; color: var(--text-muted);">担当者マスターが未登録です。</td></tr>
            ` : FLEXCON_OPERATORS.map((op, idx) => `
              <tr style="border-bottom: 1px solid var(--border-subtle);">
                <td style="padding: 10px 14px; text-align: center; color: var(--text-muted); font-weight: 600;">${idx + 1}</td>
                <td style="padding: 10px 14px; font-weight: 700; color: #1e293b;">
                  <span>👤 ${op}</span>
                </td>
                <td style="padding: 10px 14px; text-align: center;">
                  <button class="btn-del-operator" data-idx="${idx}" style="padding: 4px 10px; font-size: 11.5px; background: #fff1f2; color: #e11d48; border: 1px solid #fecdd3; border-radius: 6px; cursor: pointer; font-weight: 600;">
                    🗑️ 削除
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;

  container.innerHTML = html;

  // 新規担当者登録イベント
  document.getElementById('formAddOperator').addEventListener('submit', (e) => {
    e.preventDefault();
    const val = document.getElementById('newOperatorText').value.trim();
    if (!val) return;
    if (FLEXCON_OPERATORS.includes(val)) {
      alert("すでに登録済みの担当者です。");
      return;
    }
    FLEXCON_OPERATORS.push(val);
    activeFlexconMaster.operators = FLEXCON_OPERATORS;
    saveFlexconMaster(activeFlexconMaster);
    showToast(`👤 担当者マスターに「${val}」を追加しました`);
    renderMasterOperators(container);
  });

  // 担当者削除イベント
  container.querySelectorAll('.btn-del-operator').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx, 10);
      const targetOp = FLEXCON_OPERATORS[idx];
      if (FLEXCON_OPERATORS.length <= 1) {
        alert("最低1名の担当者は保持する必要があります。");
        return;
      }
      if (confirm(`担当者「${targetOp}」をマスターから削除しますか？`)) {
        FLEXCON_OPERATORS.splice(idx, 1);
        activeFlexconMaster.operators = FLEXCON_OPERATORS;
        saveFlexconMaster(activeFlexconMaster);
        showToast(`🗑️ 担当者「${targetOp}」を削除しました`);
        renderMasterOperators(container);
      }
    });
  });
}
