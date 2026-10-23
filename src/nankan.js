// src/nankan.js - 熊本南関工場「トロピカル」製造・原料/製品在庫管理システム
// ・日次バッチ製造の一括登録（配合レシピから原料消費を自動算出／原料ロットFIFO自動引当）
// ・原料入庫／製品出荷（出庫指図書）／隔週棚卸し・差異突合・月末調整
// ・KuKuRu様向け在庫報告書・在庫集計・倉庫料計算・製造記録書の印刷出力
// ・Cloud Firestore によるリアルタイム共有（差分マージ保存）
// ※ flexcon.js と同一ページで読み込まれてもグローバル名が衝突しないよう IIFE で閉じています。
(function () {
  'use strict';

  // ===== 定数 =====
  const NK_DATA_KEY = 'cascadia_nankan_data_v1';
  const NK_MASTER_KEY = 'cascadia_nankan_master_v1';
  const NK_OPERATOR_KEY = 'cascadia_nankan_operator';
  const NK_COLLECTION = 'cascadia_nankan';
  const BAG_KG = 250;
  const BATCH_KG = 1750;
  const BAGS_PER_BATCH = 7;
  const VIEW_ONLY = '（閲覧のみ）';
  const EPS = 0.005;

  const NK_FIREBASE_CONFIG = {
    apiKey: 'AIzaSyDuRK-JlfLdnSW8RAUyptNk_BIx39U3Lns',
    authDomain: 'cascadia-trading-flexcon.firebaseapp.com',
    projectId: 'cascadia-trading-flexcon',
    storageBucket: 'cascadia-trading-flexcon.firebasestorage.app',
    messagingSenderId: '913475294878',
    appId: '1:913475294878:web:d20f0d40154ab44e6d0d8f'
  };

  const KIND_META = {
    raw_open:    { label: '繰越（原料）',   cls: 'nk-k-open' },
    raw_in:      { label: '原料入庫',       cls: 'nk-k-in' },
    raw_out:     { label: '製造消費',       cls: 'nk-k-out' },
    raw_adjust:  { label: '棚卸調整（原料）', cls: 'nk-k-adj' },
    raw_ship:    { label: '原料出荷（同送）', cls: 'nk-k-ship' },
    prod_open:   { label: '繰越（製品）',   cls: 'nk-k-open' },
    prod_in:     { label: '製品入庫（製造）', cls: 'nk-k-prod' },
    prod_out:    { label: '製品出荷',       cls: 'nk-k-ship' },
    prod_adjust: { label: '調整（製品）',   cls: 'nk-k-adj' }
  };

  // ===== マスター初期値（2026/10/16 ご提出Excel「バッチ数と使用重量確認」「③製造記録書」準拠） =====
  const DEFAULT_MASTER = {
    materials: [
      { id: 'oats',     name: 'オーツヘイ',               prefix: 'オーツヘイ',           unit: 'ベール', kana: 'おーつへい',       step: '①', order: 10 },
      { id: 'timothy',  name: 'チモシーヘイ',             prefix: 'チモシー',             unit: 'ベール', kana: 'ちもしー',         step: '①', order: 20 },
      { id: 'alfalfa',  name: 'アルファルファヘイ',       prefix: 'アルファルファ',       unit: 'ベール', kana: 'あるふぁるふぁ',   step: '①', order: 30 },
      { id: 'wcs',      name: 'イネWCS',                  prefix: 'イネWCS',              unit: '本',     kana: 'いね だぶりゅしーえす', step: '②', order: 40 },
      { id: 'straw',    name: '稲わら',                   prefix: '稲わら',               unit: 'ベール', kana: 'いなわら',         step: '②', order: 50 },
      { id: 'corn',     name: 'コーンサイレージ',         prefix: 'コーンサイレージ',     unit: '本',     kana: 'こーんさいれーじ', step: '②', order: 60 },
      { id: 'apple',    name: 'りんご飼料',               prefix: 'りんご',               unit: '本',     kana: 'りんごしりょう',   step: '②', order: 65 },
      { id: 'kinoko',   name: 'きのこ菌床粕',             prefix: 'きのこ菌床',           unit: '本',     kana: 'きのこきんしょうかす', step: '②', order: 70 },
      { id: 'shoyu',    name: '醤油粕',                   prefix: '醤油粕',               unit: '本',     kana: 'しょうゆかす',     step: '②', order: 80 },
      { id: 'csl',      name: 'CSL(コーンスティープリカー)', prefix: 'CSL',               unit: '本',     kana: 'しーえすえる',     step: '②', order: 90 },
      { id: 'bagasse',  name: '発酵バガス',               prefix: '発酵バガス',           unit: '袋',     kana: 'はっこうばがす',   step: '③', order: 100 },
      { id: 'gyulab',   name: '配合飼料 GYU LAB ベース',  prefix: '配合飼料 GYU LAB',     unit: '本',     kana: 'ぎゅうらぼべーす', step: '③', order: 110 },
      { id: 'absoy',    name: 'アブソイ',                 prefix: 'アブソイ',             unit: '本',     kana: 'あぶそい',         step: '③', order: 120 },
      { id: 'zeolite',  name: 'ゼオライト',               prefix: 'ゼオライト',           unit: '袋',     kana: 'ぜおらいと',       step: '④', order: 130 },
      { id: 'exkoji',   name: 'EXこうじ90',               prefix: 'EXこうじ',             unit: '袋',     kana: 'いーえっくすこうじ', step: '④', order: 140 },
      { id: 'cymaster', name: 'サイマスターSPパウダー',   prefix: 'サイマスター',         unit: '袋',     kana: 'さいますたー',     step: '④', order: 150 },
      { id: 'procal_l', name: 'プロピオン酸カルシウム（液状）', prefix: 'プロピオン酸カルシウム（液', unit: '個', kana: 'ぷろかる（えき）', step: '⑤', order: 160 },
      { id: 'procal_p', name: 'プロピオン酸カルシウム（粉剤）', prefix: 'プロピオン酸カルシウム（粉', unit: '袋', kana: 'ぷろかる（こな）', step: '⑤', order: 170 }
    ],
    recipes: [
      {
        id: 'R20260601', name: '標準配合（2026/6/1〜）', validFrom: '2026-06-01', status: 'active',
        note: 'Excel「バッチ数と使用重量確認」2026/6/1列（10月実績の消費量と一致）',
        lines: [
          { mat: 'oats', kg: 747.25 }, { mat: 'timothy', kg: 105 }, { mat: 'alfalfa', kg: 70 },
          { mat: 'wcs', kg: 105 }, { mat: 'straw', kg: 87.5 }, { mat: 'kinoko', kg: 122.5 },
          { mat: 'shoyu', kg: 35 }, { mat: 'csl', kg: 67.81 }, { mat: 'bagasse', kg: 52.5 },
          { mat: 'gyulab', kg: 210 }, { mat: 'absoy', kg: 122.5 }, { mat: 'zeolite', kg: 15.75 },
          { mat: 'exkoji', kg: 5.25 }, { mat: 'cymaster', kg: 1.05 }, { mat: 'procal_l', kg: 1.14 },
          { mat: 'procal_p', kg: 1.75 }
        ]
      },
      {
        id: 'R20261022', name: 'りんご飼料配合（2026/10/22〜）※暫定・要確認', validFrom: '2026-10-22', status: 'draft',
        note: '10/23打合せ：イネWCS切れにより青森のりんご飼料（140kg/バッチ）へ切替。他原料の増減は山田様にご確認のうえ「有効」に変更してください。',
        lines: [
          { mat: 'oats', kg: 747.25 }, { mat: 'timothy', kg: 105 }, { mat: 'alfalfa', kg: 70 },
          { mat: 'apple', kg: 140 }, { mat: 'straw', kg: 87.5 }, { mat: 'kinoko', kg: 122.5 },
          { mat: 'shoyu', kg: 35 }, { mat: 'csl', kg: 67.81 }, { mat: 'bagasse', kg: 52.5 },
          { mat: 'gyulab', kg: 210 }, { mat: 'absoy', kg: 122.5 }, { mat: 'zeolite', kg: 15.75 },
          { mat: 'exkoji', kg: 5.25 }, { mat: 'cymaster', kg: 1.05 }, { mat: 'procal_l', kg: 1.14 },
          { mat: 'procal_p', kg: 1.75 }
        ]
      }
    ],
    operators: ['山田', '兼行', '荒井', '大舟', '現場担当'],
    company: {
      client: '株式会社　KuKuRu　御中',
      issuer: '株式会社　カスケディア・トレーディング',
      factory: '熊本南関工場',
      tel: 'TEL：0968-82-7287　FAX：0968-82-7288',
      warehouse: 'KuKuRu南関倉庫',
      productName: 'トロピカル　250㎏　FB',
      // 出庫指図書（2026/10/23 山田様ご提供様式）
      shipTo: '株式会社 KuKuRu　様',
      hqPostal: '〒330-0063',
      hqAddress1: '埼玉県さいたま市浦和区高砂2-11-13',
      hqAddress2: '新和ビル3F',
      hqTel: 'TEL:048-762-9340 FAX:048-762-9360'
    },
    slipNextNo: 84,
    holdLots: []
  };

  // ===== ユーティリティ =====
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const r4 = (n) => Math.round((Number(n) || 0) * 10000) / 10000;
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function fmt(n, digits = 2) {
    const v = Number(n) || 0;
    return v.toLocaleString('ja-JP', { maximumFractionDigits: digits, minimumFractionDigits: 0 });
  }
  function todayStr() {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  }
  function jpDate(s) {
    if (!s) return '';
    const [y, m, d] = s.split('-').map(Number);
    return `${y}年${m}月${d}日`;
  }
  function slashDate(s) { return s ? s.replace(/-/g, '/') : ''; }
  function lotFromDate(date, seq = '501') {
    const [y, m, d] = date.split('-');
    return `K${y.slice(2)}${m}${d}${seq}`;
  }
  function dateFromLot(lot) {
    const m = /^K(\d{2})(\d{2})(\d{2})/.exec(lot || '');
    return m ? `20${m[1]}-${m[2]}-${m[3]}` : '';
  }
  function monthEnd(ym) {
    const [y, m] = ym.split('-').map(Number);
    const d = new Date(y, m, 0);
    return `${y}-${String(m).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  }
  function daysBetween(a, b) {
    return Math.round((new Date(b) - new Date(a)) / 86400000);
  }
  function newId(prefix) {
    return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
  }
  function toast(msg, ms = 3200) {
    if (typeof window.showToast === 'function') { window.showToast(msg, ms); return; }
    let c = document.getElementById('nkToastContainer');
    if (!c) {
      c = document.createElement('div');
      c.id = 'nkToastContainer';
      c.className = 'nk-toast-container';
      document.body.appendChild(c);
    }
    const t = document.createElement('div');
    t.className = 'nk-toast';
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(() => t.remove(), ms);
  }

  // ===== スタイル注入（総合ポータル・専用ポータル共通） =====
  function injectStyles() {
    if (document.getElementById('nkStyles')) return;
    const st = document.createElement('style');
    st.id = 'nkStyles';
    st.textContent = `
.nk-root{--nk-green:#047857;--nk-green-bg:rgba(5,150,105,.08);--nk-border:#e2e8f0;--nk-muted:#64748b;font-size:14px;color:#1e293b}
.nk-hero{padding:22px 24px;margin-bottom:18px;background:linear-gradient(135deg,rgba(5,150,105,.10),rgba(16,185,129,.04));border:1px solid rgba(5,150,105,.22);border-radius:14px;display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;align-items:flex-start}
.nk-hero h1{margin:0 0 6px;font-size:21px;font-weight:800}
.nk-hero p{margin:0;color:var(--nk-muted);font-size:13px;line-height:1.6}
.nk-hero-side{display:flex;flex-direction:column;gap:8px;align-items:flex-end}
.nk-operator{display:flex;align-items:center;gap:8px;font-size:12.5px;font-weight:700;color:#334155;background:#fff;border:1px solid var(--nk-border);border-radius:10px;padding:6px 10px}
.nk-operator select{border:1px solid #cbd5e1;border-radius:6px;padding:4px 6px;font-weight:700}
.nk-sync{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:20px;font-size:11.5px;font-weight:700;border:1px solid #fef08a;background:#fefce8;color:#854d0e}
.nk-sync.ok{background:#ecfdf5;color:#065f46;border-color:#a7f3d0}.nk-sync.saving{background:#eff6ff;color:#1e40af;border-color:#bfdbfe}.nk-sync.off{background:#f8fafc;color:#64748b;border-color:#cbd5e1}.nk-sync.err{background:#fef2f2;color:#991b1b;border-color:#fecaca}
.nk-navbar{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:16px;align-items:center}
.nk-tabs{display:flex;gap:6px;flex-wrap:wrap;background:#f1f5f9;padding:5px;border-radius:12px}
.nk-tab{border:0;background:transparent;padding:8px 14px;border-radius:9px;font-weight:700;font-size:13px;color:#475569;cursor:pointer}
.nk-tab.active{background:#fff;color:var(--nk-green);box-shadow:0 1px 3px rgba(15,23,42,.12)}
.nk-actions{display:flex;gap:8px;flex-wrap:wrap}
.nk-btn{display:inline-flex;align-items:center;gap:6px;border:1px solid #cbd5e1;background:#fff;color:#334155;padding:8px 14px;border-radius:9px;font-weight:700;font-size:13px;cursor:pointer;line-height:1.2}
.nk-btn:hover{background:#f8fafc;border-color:#94a3b8}
.nk-btn:disabled{opacity:.45;cursor:not-allowed}
.nk-btn-primary{background:linear-gradient(135deg,#059669,#047857);color:#fff;border-color:#047857}
.nk-btn-primary:hover{background:linear-gradient(135deg,#047857,#065f46)}
.nk-btn-danger{color:#b91c1c;border-color:#fecaca}.nk-btn-danger:hover{background:#fef2f2}
.nk-btn-sm{padding:4px 9px;font-size:12px;border-radius:7px}
.nk-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-bottom:18px}
.nk-kpi{background:#fff;border:1px solid var(--nk-border);border-radius:12px;padding:14px 16px}
.nk-kpi-label{font-size:12px;color:var(--nk-muted);font-weight:700}
.nk-kpi-value{font-size:22px;font-weight:800;margin-top:4px}
.nk-kpi-sub{font-size:11.5px;color:var(--nk-muted);margin-top:2px}
.nk-card{background:#fff;border:1px solid var(--nk-border);border-radius:12px;padding:16px 18px;margin-bottom:18px}
.nk-card h2{font-size:15.5px;margin:0 0 4px;font-weight:800}
.nk-card .nk-card-desc{font-size:12.5px;color:var(--nk-muted);margin:0 0 12px}
.nk-card-head{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.nk-grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:18px}
.nk-table-wrap{overflow:auto;max-inline-size:100%;max-block-size:min(620px,75vh);border:1px solid var(--nk-border);border-radius:10px;container-type:inline-size}
.nk-table{border-collapse:separate;border-spacing:0;width:100%;font-size:13px}
.nk-table caption{text-align:left;font-weight:700;padding:8px 10px;color:#334155}
.nk-table thead{position:sticky;inset-block-start:0;z-index:1}
.nk-table th{background:#f8fafc;color:#475569;font-weight:700;text-align:left;padding:8px 10px;border-bottom:1px solid var(--nk-border);white-space:nowrap}
.nk-table td{padding:7px 10px;border-bottom:1px solid #f1f5f9;vertical-align:middle}
.nk-table tbody tr:hover td{background:#f8fafc}
.nk-table .num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.nk-table input,.nk-table select{width:100%;box-sizing:border-box;border:1px solid #cbd5e1;border-radius:6px;padding:5px 7px;font-size:13px}
.nk-table input.num{text-align:right}
.nk-table tfoot td{font-weight:800;background:#f8fafc;border-top:2px solid var(--nk-border)}
.nk-badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11.5px;font-weight:700;white-space:nowrap}
.nk-k-open{background:#f1f5f9;color:#475569}.nk-k-in{background:#dbeafe;color:#1e40af}.nk-k-out{background:#ffedd5;color:#9a3412}.nk-k-adj{background:#dcfce7;color:#166534}.nk-k-prod{background:#d1fae5;color:#065f46}.nk-k-ship{background:#ede9fe;color:#5b21b6}
.nk-alert-red{background:#fee2e2;color:#991b1b}.nk-alert-amber{background:#fef3c7;color:#92400e}.nk-alert-ok{background:#dcfce7;color:#166534}.nk-alert-gray{background:#f1f5f9;color:#64748b}
.nk-diff-pos{color:#047857;font-weight:700}.nk-diff-neg{color:#b91c1c;font-weight:700}
.nk-filters{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:12px}
.nk-field{display:flex;flex-direction:column;gap:4px;font-size:12px;font-weight:700;color:#475569}
.nk-field input,.nk-field select,.nk-field textarea{border:1px solid #cbd5e1;border-radius:7px;padding:7px 9px;font-size:13.5px;font-weight:500;color:#0f172a;background:#fff}
.nk-field textarea{min-height:56px;resize:vertical}
.nk-form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:14px}
.nk-note{font-size:12px;color:var(--nk-muted);line-height:1.6}
.nk-warn{background:#fffbeb;border:1px solid #fde68a;color:#92400e;border-radius:9px;padding:9px 12px;font-size:12.5px;margin:10px 0;line-height:1.6}
.nk-info{background:#eff6ff;border:1px solid #bfdbfe;color:#1e40af;border-radius:9px;padding:9px 12px;font-size:12.5px;margin:10px 0;line-height:1.6}
.nk-danger{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:9px;padding:9px 12px;font-size:12.5px;margin:10px 0;line-height:1.6}
.nk-dialog{border:0;border-radius:14px;padding:0;width:min(1080px,96vw);max-height:92vh;box-shadow:0 25px 50px -12px rgba(15,23,42,.45)}
.nk-dialog::backdrop{background:rgba(15,23,42,.5)}
.nk-dialog-head{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;border-bottom:1px solid var(--nk-border,#e2e8f0);position:sticky;top:0;background:#fff;z-index:2}
.nk-dialog-head h3{margin:0;font-size:16px;font-weight:800}
.nk-dialog-body{padding:16px 20px}
.nk-dialog-foot{display:flex;justify-content:flex-end;gap:8px;padding:12px 20px;border-top:1px solid #e2e8f0;position:sticky;bottom:0;background:#fff}
.nk-subtabs{display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap}
.nk-bar{height:10px;border-radius:5px;background:#10b981;display:inline-block;vertical-align:middle}
.nk-bar.ship{background:#8b5cf6}
.nk-report-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
.nk-report-card{border:1px solid var(--nk-border);border-radius:12px;padding:14px 16px;background:#fff;display:flex;flex-direction:column;gap:10px}
.nk-report-card h3{margin:0;font-size:14.5px;font-weight:800}
.nk-report-card p{margin:0;font-size:12.5px;color:var(--nk-muted);line-height:1.6}
.nk-toast-container{position:fixed;bottom:24px;right:24px;z-index:99999;display:flex;flex-direction:column;gap:8px}
.nk-toast{background:#0f172a;color:#fff;padding:11px 18px;border-radius:10px;font-size:13px;font-weight:600;box-shadow:0 10px 25px -5px rgba(0,0,0,.4)}
.nk-empty{padding:24px;text-align:center;color:var(--nk-muted);font-size:13px}
.nk-row-zero td{color:#94a3b8}
@container (width < 640px){
  .nk-table.nk-stack thead{display:none}
  .nk-table.nk-stack,.nk-table.nk-stack tbody,.nk-table.nk-stack tr,.nk-table.nk-stack td{display:block}
  .nk-table.nk-stack tr{border-bottom:1px solid var(--nk-border);padding:6px 0}
  .nk-table.nk-stack td{border:0;padding:3px 10px}
  .nk-table.nk-stack td[data-label]::before{content:attr(data-label) "： ";font-weight:700;color:#64748b}
}
@media (max-width:640px){.nk-grid2{grid-template-columns:1fr}}
`;
    document.head.appendChild(st);
  }

  // ===== マスター =====
  function loadMaster() {
    let m = null;
    try { m = JSON.parse(localStorage.getItem(NK_MASTER_KEY) || 'null'); } catch (e) { m = null; }
    if (!m || !Array.isArray(m.materials) || !Array.isArray(m.recipes)) m = clone(DEFAULT_MASTER);
    if (!Array.isArray(m.operators) || !m.operators.length) m.operators = clone(DEFAULT_MASTER.operators);
    m.company = Object.assign({}, DEFAULT_MASTER.company, m.company || {});
    if (!Array.isArray(m.holdLots)) m.holdLots = [];
    if (!(Number(m.slipNextNo) > 0)) m.slipNextNo = DEFAULT_MASTER.slipNextNo;
    return m;
  }
  function saveMaster(m, opts = {}) {
    localStorage.setItem(NK_MASTER_KEY, JSON.stringify(m));
    if (!opts.skipCloud) pushMasterToCloud(m);
  }
  function sortedMaterials(m) {
    return m.materials.slice().sort((a, b) => (a.order || 0) - (b.order || 0));
  }
  function matById(m, id) { return m.materials.find((x) => x.id === id); }
  function matOfItem(m, item) {
    let best = null;
    m.materials.forEach((x) => {
      if (x.prefix && String(item || '').startsWith(x.prefix) && (!best || x.prefix.length > best.prefix.length)) best = x;
    });
    return best;
  }
  function recipeById(m, id) { return m.recipes.find((r) => r.id === id); }
  function recipeForDate(m, date) {
    const act = m.recipes.filter((r) => r.status === 'active' && (!r.validFrom || r.validFrom <= date))
      .sort((a, b) => (b.validFrom || '').localeCompare(a.validFrom || ''));
    return act[0] || m.recipes.find((r) => r.status === 'active') || m.recipes[0];
  }
  function recipeTotal(r) { return r4((r.lines || []).reduce((s, l) => s + (Number(l.kg) || 0), 0)); }

  function getOperator() {
    const m = loadMaster();
    const saved = localStorage.getItem(NK_OPERATOR_KEY);
    if (saved && (saved === VIEW_ONLY || m.operators.includes(saved))) return saved;
    return m.operators[0] || '山田';
  }
  function canEdit() { return getOperator() !== VIEW_ONLY; }

  // ===== データ（ローカル＋クラウド差分マージ） =====
  const baselines = new WeakMap();
  function trackBaseline(data) {
    const map = new Map();
    (data.transactions || []).forEach((t) => { if (t && t.id) map.set(t.id, JSON.stringify(t)); });
    baselines.set(data, map);
    return data;
  }
  function computeOps(data) {
    const base = baselines.get(data);
    if (!base) return null;
    const upserts = [];
    const ids = new Set();
    data.transactions.forEach((t) => {
      ids.add(t.id);
      const j = JSON.stringify(t);
      if (base.get(t.id) !== j) upserts.push(JSON.parse(j));
    });
    const deletes = [];
    base.forEach((_, id) => { if (!ids.has(id)) deletes.push(id); });
    return { upserts, deletes };
  }
  function applyOps(remote, ops, patch) {
    const merged = Object.assign({}, remote);
    const del = new Set(ops.deletes);
    const up = new Map(ops.upserts.map((t) => [t.id, t]));
    const list = [];
    (remote.transactions || []).forEach((t) => {
      if (del.has(t.id)) return;
      if (up.has(t.id)) { list.push(up.get(t.id)); up.delete(t.id); } else list.push(t);
    });
    up.forEach((t) => list.push(t));
    merged.transactions = list;
    applyPatch(merged, patch);
    return merged;
  }
  function applyPatch(d, patch) {
    if (!patch) return;
    if (patch.wipKg !== undefined) d.wipKg = patch.wipKg;
    if (patch.stocktake) {
      d.stocktakes = Object.assign({}, d.stocktakes || {});
      if (patch.stocktake.value === null) delete d.stocktakes[patch.stocktake.date];
      else d.stocktakes[patch.stocktake.date] = patch.stocktake.value;
    }
  }

  function freshData() {
    const init = window.NANKAN_INITIAL_DATA ? clone(window.NANKAN_INITIAL_DATA) : { transactions: [], wipKg: 0 };
    init.stocktakes = init.stocktakes || {};
    return init;
  }
  function loadData() {
    initSync();
    let d = null;
    try { d = JSON.parse(localStorage.getItem(NK_DATA_KEY) || 'null'); } catch (e) { d = null; }
    if (!d || !Array.isArray(d.transactions)) {
      d = freshData();
      localStorage.setItem(NK_DATA_KEY, JSON.stringify(d));
    }
    d.stocktakes = d.stocktakes || {};
    return trackBaseline(d);
  }
  function saveData(data, patch, opts = {}) {
    applyPatch(data, patch);
    localStorage.setItem(NK_DATA_KEY, JSON.stringify(data));
    const ops = opts.fullOverwrite ? null : computeOps(data);
    trackBaseline(data);
    if (!nkDb) { rerender(); return; }
    if (ops && !ops.upserts.length && !ops.deletes.length && !patch) { rerender(); return; }
    setSync('saving');
    const ref = nkDb.collection(NK_COLLECTION).doc('shared_data');
    const updatedAt = new Date().toISOString();
    lastRemoteAt = updatedAt;
    nkDb.runTransaction((t) => t.get(ref).then((snap) => {
      let merged;
      if (ops && snap.exists && Array.isArray((snap.data() || {}).transactions)) merged = applyOps(snap.data(), ops, patch);
      else merged = clone(data);
      merged.updatedAt = updatedAt;
      merged.updatedBy = getOperator();
      t.set(ref, merged);
      return merged;
    })).then((merged) => {
      setSync('ok');
      localStorage.setItem(NK_DATA_KEY, JSON.stringify(merged));
      rerender();
    }).catch((err) => {
      console.error('[Nankan] cloud save error', err);
      setSync('err');
      toast('⚠️ クラウド保存に失敗しました（端末内には保存済み）。通信状態を確認してください。', 6000);
      rerender();
    });
  }

  // ===== Firestore 同期 =====
  let nkDb = null;
  let syncStarted = false;
  let syncState = 'connecting';
  let lastRemoteAt = null;
  let lastRemoteMasterAt = null;

  function setSync(s) {
    syncState = s;
    const map = {
      ok: ['ok', '🟢 クラウド自動同期中'], saving: ['saving', '⏳ クラウド保存中...'],
      connecting: ['', '🟡 クラウド接続中...'], off: ['off', '⚪ ローカル保存（オフライン）'], err: ['err', '🔴 クラウド保存エラー']
    };
    const [cls, text] = map[s] || map.connecting;
    document.querySelectorAll('.nk-sync-target, .nankan-cloud-sync-badge').forEach((b) => {
      b.className = b.classList.contains('nankan-cloud-sync-badge') ? 'nankan-cloud-sync-badge nk-sync ' + cls : 'nk-sync nk-sync-target ' + cls;
      b.textContent = text;
    });
  }
  function dialogOpen() { return !!document.querySelector('dialog.nk-dialog[open]'); }
  function initSync() {
    if (syncStarted) return;
    syncStarted = true;
    if (typeof firebase === 'undefined') { setSync('off'); return; }
    try {
      if (!firebase.apps || !firebase.apps.length) firebase.initializeApp(NK_FIREBASE_CONFIG);
      nkDb = firebase.firestore();
      const ref = nkDb.collection(NK_COLLECTION).doc('shared_data');
      ref.onSnapshot((snap) => {
        if (!snap.exists) {
          // クラウド未作成：初期データ（9月末確定在庫＋10月実績）で共有DBを構築
          let local = null;
          try { local = JSON.parse(localStorage.getItem(NK_DATA_KEY) || 'null'); } catch (e) { local = null; }
          const init = (local && Array.isArray(local.transactions)) ? local : freshData();
          init.updatedAt = new Date().toISOString();
          init.updatedBy = '初期セットアップ';
          lastRemoteAt = init.updatedAt;
          ref.set(init).then(() => setSync('ok')).catch(() => setSync('err'));
          return;
        }
        const remote = snap.data();
        if (!remote || !Array.isArray(remote.transactions)) return;
        const at = remote.updatedAt || 'initial';
        setSync('ok');
        if (at === lastRemoteAt) return;
        lastRemoteAt = at;
        localStorage.setItem(NK_DATA_KEY, JSON.stringify(remote));
        if (!dialogOpen()) rerender();
      }, (err) => { console.warn('[Nankan] listener', err); setSync('off'); });

      const mref = nkDb.collection(NK_COLLECTION).doc('shared_master');
      mref.onSnapshot((snap) => {
        if (!snap.exists) { pushMasterToCloud(loadMaster()); return; }
        const remote = snap.data();
        if (!remote || !Array.isArray(remote.materials)) return;
        const at = remote.updatedAt || 'initial';
        if (at === lastRemoteMasterAt) return;
        lastRemoteMasterAt = at;
        const m = clone(remote);
        delete m.updatedAt;
        saveMaster(m, { skipCloud: true });
        if (!dialogOpen()) rerender();
      });
    } catch (e) {
      console.error('[Nankan] Firestore init', e);
      setSync('err');
    }
  }
  function pushMasterToCloud(m) {
    if (!nkDb) return;
    const payload = clone(m);
    payload.updatedAt = new Date().toISOString();
    lastRemoteMasterAt = payload.updatedAt;
    nkDb.collection(NK_COLLECTION).doc('shared_master').set(payload).catch((e) => console.error('[Nankan] master save', e));
  }

  // ===== 在庫計算 =====
  function prodDelta(t) {
    if (t.kind === 'prod_open' || t.kind === 'prod_in') return Number(t.bags) || 0;
    if (t.kind === 'prod_out') return -(Number(t.bags) || 0);
    if (t.kind === 'prod_adjust') return Number(t.bags) || 0;
    return 0;
  }
  // 原料ロット別在庫（asOf: その日を含む時点）
  function rawStock(data, master, asOf, excludeIds) {
    const map = new Map();
    data.transactions.forEach((t) => {
      if (!t.kind || !t.kind.startsWith('raw')) return;
      if (asOf && t.date > asOf) return;
      if (excludeIds && excludeIds.has(t.id)) return;
      let s = map.get(t.item);
      if (!s) {
        const mat = matOfItem(master, t.item);
        s = { item: t.item, kg: 0, pkg: null, pkgDate: '', first: t.lotOrder || t.date, mat };
        map.set(t.item, s);
      }
      s.kg += Number(t.kg) || 0;
      if (t.pkg && (t.kind === 'raw_in' || t.kind === 'raw_open') && (t.date >= s.pkgDate)) { s.pkg = Number(t.pkg); s.pkgDate = t.date; }
      else if (t.pkg && !s.pkg) s.pkg = Number(t.pkg);
      const o = t.lotOrder || t.date;
      if (o < s.first) s.first = o;
    });
    map.forEach((s) => { s.kg = r4(s.kg); });
    return map;
  }
  function lotsOfMaterial(stockMap, matId) {
    return Array.from(stockMap.values()).filter((s) => s.mat && s.mat.id === matId)
      .sort((a, b) => (a.first || '').localeCompare(b.first || '') || a.item.localeCompare(b.item, 'ja'));
  }
  // FIFO引当：古いロットから使い切り、不足分は次ロットへ
  function allocateFifo(stockMap, matId, kg, master) {
    const lots = lotsOfMaterial(stockMap, matId);
    const res = [];
    let remain = r4(kg);
    for (const l of lots) {
      if (remain <= EPS) break;
      if (l.kg <= EPS) continue;
      const take = r4(Math.min(l.kg, remain));
      res.push({ item: l.item, kg: take, pkg: l.pkg });
      remain = r4(remain - take);
    }
    let shortage = 0;
    if (remain > EPS) {
      shortage = remain;
      const last = lots[lots.length - 1];
      const mat = matById(master, matId);
      const target = last ? last.item : (mat ? mat.name : matId);
      const ex = res.find((x) => x.item === target);
      if (ex) ex.kg = r4(ex.kg + remain); else res.push({ item: target, kg: remain, pkg: last ? last.pkg : null });
    }
    return { allocations: res, shortage };
  }
  function prodStock(data, asOf) {
    const map = new Map();
    data.transactions.forEach((t) => {
      if (!t.kind || !t.kind.startsWith('prod')) return;
      if (asOf && t.date > asOf) return;
      const k = t.lot || '(ロット不明)';
      map.set(k, (map.get(k) || 0) + prodDelta(t));
    });
    return Array.from(map.entries()).map(([lot, bags]) => ({ lot, bags, date: dateFromLot(lot) }))
      .sort((a, b) => a.lot.localeCompare(b.lot));
  }
  function fifoProductLots(data, bags, asOf, holdLots) {
    const hold = new Set(holdLots || []);
    const lots = prodStock(data, asOf).filter((l) => l.bags > 0 && !hold.has(l.lot));
    const res = [];
    let remain = bags;
    for (const l of lots) {
      if (remain <= 0) break;
      const take = Math.min(l.bags, remain);
      res.push({ lot: l.lot, bags: take });
      remain -= take;
    }
    return { allocations: res, shortage: remain };
  }
  // 直近30日の1稼働日あたり平均バッチ数
  function avgBatchesPerDay(data, asOf) {
    const end = asOf || todayStr();
    const start = new Date(end); start.setDate(start.getDate() - 30);
    const s = `${start.getFullYear()}-${String(start.getMonth() + 1).padStart(2, '0')}-${String(start.getDate()).padStart(2, '0')}`;
    const byDate = {};
    data.transactions.forEach((t) => {
      if (t.kind === 'prod_in' && t.date > s && t.date <= end) {
        byDate[t.date] = (byDate[t.date] || 0) + (Number(t.batches) || (Number(t.bags) * BAG_KG / BATCH_KG));
      }
    });
    const days = Object.keys(byDate).length;
    if (!days) return 3;
    return Object.values(byDate).reduce((a, b) => a + b, 0) / days;
  }
  function lastTxDate(data, prefix) {
    let d = '';
    data.transactions.forEach((t) => { if (t.kind && t.kind.startsWith(prefix) && t.date > d) d = t.date; });
    return d;
  }

  // ===== 画面状態 =====
  const ui = {
    tab: 'dashboard', asOf: '', ledgerMonth: 'all', ledgerKind: 'all', ledgerText: '',
    stockDate: '', masterSub: 'recipes', editRecipeId: null
  };
  let rootRef = null;

  function rerender() {
    if (rootRef && document.body.contains(rootRef)) renderNankanSystem(rootRef);
  }

  // ===== メイン描画 =====
  function renderNankanSystem(targetEl) {
    injectStyles();
    const root = targetEl || document.getElementById('contentArea');
    if (!root) return;
    rootRef = root;
    const data = loadData();
    const master = loadMaster();
    const op = getOperator();
    const isStandalone = /nankan/.test(window.location.pathname);
    const editable = canEdit();

    root.innerHTML = `
      <div class="nk-root" id="nkRoot">
        <div class="nk-hero">
          <div style="flex:1;min-width:280px;">
            <h1>🏭 熊本南関工場「トロピカル」製造・在庫管理</h1>
            <p>日次バッチ製造の一括登録（配合レシピ→原料消費の自動計算・ロット先入れ先出し）、原料入庫、製品出荷・出庫指図書、隔週棚卸し・差異突合・月末調整、KuKuRu様向け在庫報告書の出力までを一元管理します。データは全端末でリアルタイム共有されます。</p>
          </div>
          <div class="nk-hero-side">
            <span class="nk-sync nk-sync-target">🟡 クラウド接続中...</span>
            <label class="nk-operator">👤 入力担当者
              <select id="nkOperator">
                ${master.operators.map((o) => `<option ${o === op ? 'selected' : ''}>${esc(o)}</option>`).join('')}
                <option ${op === VIEW_ONLY ? 'selected' : ''}>${VIEW_ONLY}</option>
              </select>
            </label>
            ${!isStandalone ? `<a class="nk-btn nk-btn-sm" href="nankan.html" target="_blank" rel="noopener noreferrer">🚀 専用ポータルで開く ↗</a>` : ''}
          </div>
        </div>
        <div class="nk-navbar">
          <div class="nk-tabs" role="tablist">
            ${[['dashboard', '📊 在庫ダッシュボード'], ['ledger', '📋 製造・入出庫台帳'], ['stocktake', '🔍 棚卸し・月末調整'], ['reports', '📄 報告書・指示書'], ['master', '⚙️ 配合レシピ・マスター']]
              .map(([k, l]) => `<button type="button" role="tab" class="nk-tab ${ui.tab === k ? 'active' : ''}" aria-selected="${ui.tab === k}" data-tab="${k}">${l}</button>`).join('')}
          </div>
          <div class="nk-actions">
            <button type="button" class="nk-btn nk-btn-primary" id="nkBtnBatch" ${editable ? '' : 'disabled'} title="バッチ数を選ぶだけで原料消費と製品入庫を一括登録">⚡ 日次製造（バッチ）登録</button>
            <button type="button" class="nk-btn" id="nkBtnRawIn" ${editable ? '' : 'disabled'}>📥 原料入庫</button>
            <button type="button" class="nk-btn" id="nkBtnShip" ${editable ? '' : 'disabled'}>🚚 製品出荷・出庫指図書</button>
            <button type="button" class="nk-btn" id="nkBtnAdjust" ${editable ? '' : 'disabled'}>✏️ 個別調整</button>
          </div>
        </div>
        ${!editable ? `<div class="nk-info">👁️ 閲覧モードです。登録・編集するには右上の「入力担当者」を選択してください。</div>` : ''}
        <div id="nkTabContent"></div>
      </div>`;

    setSync(syncState);
    root.querySelector('#nkOperator').addEventListener('change', (e) => {
      localStorage.setItem(NK_OPERATOR_KEY, e.target.value);
      toast(`入力担当者を「${e.target.value}」に設定しました（この端末に記憶されます）`);
      rerender();
    });
    root.querySelectorAll('.nk-tab').forEach((b) => b.addEventListener('click', () => { ui.tab = b.dataset.tab; rerender(); }));
    root.querySelector('#nkBtnBatch').addEventListener('click', () => openBatchDialog());
    root.querySelector('#nkBtnRawIn').addEventListener('click', () => openRawInDialog());
    root.querySelector('#nkBtnShip').addEventListener('click', () => openShipDialog());
    root.querySelector('#nkBtnAdjust').addEventListener('click', () => openAdjustDialog());

    const c = root.querySelector('#nkTabContent');
    if (ui.tab === 'ledger') renderLedger(c, data, master);
    else if (ui.tab === 'stocktake') renderStocktake(c, data, master);
    else if (ui.tab === 'reports') renderReports(c, data, master);
    else if (ui.tab === 'master') renderMaster(c, data, master);
    else renderDashboard(c, data, master);
  }

  // ===== タブ①：在庫ダッシュボード =====
  function renderDashboard(c, data, master) {
    const asOf = ui.asOf || '';
    const asOfLabel = asOf ? jpDate(asOf) + ' 時点' : '最新（全登録分）';
    const stock = rawStock(data, master, asOf || null);
    const prod = prodStock(data, asOf || null).filter((l) => l.bags !== 0);
    const totalBags = prod.reduce((s, l) => s + l.bags, 0);
    const recipe = recipeForDate(master, asOf || todayStr());
    const perBatch = {};
    (recipe ? recipe.lines : []).forEach((l) => { perBatch[l.mat] = (perBatch[l.mat] || 0) + Number(l.kg); });
    const avg = avgBatchesPerDay(data, asOf || null);
    const totalRawKg = Array.from(stock.values()).reduce((s, x) => s + Math.max(0, x.kg), 0);
    const ym = (asOf || todayStr()).slice(0, 7);
    let mBatches = 0, mBags = 0, mShip = 0;
    data.transactions.forEach((t) => {
      if (!t.date || t.date.slice(0, 7) !== ym || (asOf && t.date > asOf)) return;
      if (t.kind === 'prod_in') { mBags += Number(t.bags) || 0; mBatches += Number(t.batches) || (Number(t.bags) * BAG_KG / BATCH_KG); }
      if (t.kind === 'prod_out') mShip += Number(t.bags) || 0;
    });
    const lastRaw = lastTxDate(data, 'raw');
    const lastProd = lastTxDate(data, 'prod');
    const behind = lastRaw && daysBetween(lastRaw, todayStr()) > 3;

    // 原料別行
    const rows = [];
    sortedMaterials(master).forEach((mat) => {
      const lots = lotsOfMaterial(stock, mat.id).filter((l) => Math.abs(l.kg) > EPS);
      const used = perBatch[mat.id] || 0;
      if (!lots.length && !used) return;
      const total = r4(lots.reduce((s, l) => s + l.kg, 0));
      const remainBatches = used ? total / used : null;
      const remainDays = used ? remainBatches / (avg || 3) : null;
      let alert = '<span class="nk-badge nk-alert-gray">配合外</span>';
      if (used) {
        if (total <= EPS) alert = '<span class="nk-badge nk-alert-red">在庫なし</span>';
        else if (remainDays < 5) alert = `<span class="nk-badge nk-alert-red">残り約${fmt(remainDays, 1)}稼働日</span>`;
        else if (remainDays < 10) alert = `<span class="nk-badge nk-alert-amber">残り約${fmt(remainDays, 1)}稼働日</span>`;
        else alert = `<span class="nk-badge nk-alert-ok">残り約${fmt(remainDays, 0)}稼働日</span>`;
      }
      const lotHtml = lots.length ? lots.map((l, i) => `${i === 0 ? '▶ ' : ''}${esc(l.item)}：<b>${fmt(l.kg)}</b> kg${l.pkg ? `（約${fmt(l.kg / l.pkg, 1)}${esc(mat.unit)}・荷姿${fmt(l.pkg, 3)}kg）` : ''}`).join('<br>') : '<span style="color:#b91c1c">—</span>';
      rows.push(`<tr>
        <td data-label="原料"><b>${esc(mat.name)}</b><div class="nk-note">${esc(mat.step || '')} ${esc(mat.unit)}</div></td>
        <td data-label="ロット別在庫（▶使用中）" style="font-size:12.5px;line-height:1.6">${lotHtml}</td>
        <td data-label="在庫合計" class="num"><b>${fmt(total)}</b> kg</td>
        <td data-label="1バッチ使用量" class="num">${used ? fmt(used) + ' kg' : '—'}</td>
        <td data-label="残バッチ数" class="num">${used ? fmt(remainBatches, 1) : '—'}</td>
        <td data-label="状況">${alert}</td>
      </tr>`);
    });
    // 配合マスター外の未分類ロット
    Array.from(stock.values()).filter((s) => !s.mat && Math.abs(s.kg) > EPS).forEach((s) => {
      rows.push(`<tr><td data-label="原料"><b>${esc(s.item)}</b><div class="nk-note">原料マスター未登録</div></td><td>${esc(s.item)}</td><td class="num"><b>${fmt(s.kg)}</b> kg</td><td class="num">—</td><td class="num">—</td><td><span class="nk-badge nk-alert-amber">マスター要登録</span></td></tr>`);
    });

    // 月別推移（製造・出荷）
    const months = {};
    data.transactions.forEach((t) => {
      if (!t.date || (t.kind !== 'prod_in' && t.kind !== 'prod_out')) return;
      const k = t.date.slice(0, 7);
      months[k] = months[k] || { made: 0, ship: 0 };
      if (t.kind === 'prod_in') months[k].made += Number(t.bags) || 0; else months[k].ship += Number(t.bags) || 0;
    });
    const mKeys = Object.keys(months).sort();
    const maxM = Math.max(1, ...mKeys.map((k) => Math.max(months[k].made, months[k].ship)));

    c.innerHTML = `
      <div class="nk-filters">
        <label class="nk-field">表示時点
          <input type="date" id="nkAsOf" value="${esc(asOf)}">
        </label>
        <button type="button" class="nk-btn nk-btn-sm" id="nkAsOfClear">最新に戻す</button>
        <span class="nk-note">現在の表示：<b>${asOfLabel}</b>／適用レシピ：<b>${esc(recipe ? recipe.name : '未設定')}</b>／直近30日の平均：<b>${fmt(avg, 2)}バッチ/稼働日</b></span>
      </div>
      ${behind ? `<div class="nk-warn">⚠️ 原料台帳の最終登録日は <b>${slashDate(lastRaw)}</b>（製品台帳：${slashDate(lastProd)}）です。それ以降の製造・入出庫が未登録の場合は「⚡ 日次製造（バッチ）登録」から追記してください。</div>` : ''}
      <div class="nk-kpis">
        <div class="nk-kpi"><div class="nk-kpi-label">製品「トロピカル」在庫</div><div class="nk-kpi-value">${fmt(totalBags, 0)} 袋</div><div class="nk-kpi-sub">${fmt(totalBags * BAG_KG, 0)} kg（250kg FB）／${prod.filter((l) => l.bags > 0).length}ロット</div></div>
        <div class="nk-kpi"><div class="nk-kpi-label">仕掛品（端数）</div><div class="nk-kpi-value">${fmt(data.wipKg || 0)} kg</div><div class="nk-kpi-sub">製造登録・棚卸し時に更新</div></div>
        <div class="nk-kpi"><div class="nk-kpi-label">原料在庫 合計重量</div><div class="nk-kpi-value">${fmt(totalRawKg / 1000, 2)} t</div><div class="nk-kpi-sub">${fmt(totalRawKg, 0)} kg</div></div>
        <div class="nk-kpi"><div class="nk-kpi-label">${ym.replace('-', '年')}月 製造実績</div><div class="nk-kpi-value">${fmt(mBatches, 1)} バッチ</div><div class="nk-kpi-sub">${fmt(mBags, 0)}袋 製造／${fmt(mShip, 0)}袋 出荷</div></div>
      </div>
      <div class="nk-card">
        <div class="nk-card-head"><div><h2>🌾 原料在庫（ロット別・先入れ先出し順）</h2><p class="nk-card-desc">▶ が次回製造で優先的に使用されるロットです。残稼働日数は「適用レシピの1バッチ使用量 × 直近平均バッチ数」から推計しています。</p></div></div>
        <div class="nk-table-wrap" tabindex="0" role="region" aria-label="原料在庫一覧">
          <table class="nk-table nk-stack">
            <thead><tr><th>原料</th><th>ロット別在庫（▶使用中）</th><th class="num">在庫合計</th><th class="num">1バッチ使用量</th><th class="num">残バッチ数</th><th>状況</th></tr></thead>
            <tbody>${rows.join('') || '<tr><td colspan="6" class="nk-empty">原料在庫がありません</td></tr>'}</tbody>
          </table>
        </div>
      </div>
      <div class="nk-grid2">
        <div class="nk-card">
          <h2>📦 製品「トロピカル」ロット別在庫（倉庫料計算）</h2>
          <p class="nk-card-desc">ロット番号は「K＋製造年月日(YYMMDD)＋501」。出荷時は古いロットから自動で引当てます。</p>
          <div class="nk-table-wrap" tabindex="0" role="region" aria-label="製品ロット別在庫">
            <table class="nk-table">
              <thead><tr><th>ロット番号</th><th>製造日</th><th class="num">経過日数</th><th class="num">在庫数</th><th class="num">在庫重量</th><th>出荷引当</th></tr></thead>
              <tbody>${prod.map((l) => {
                const age = l.date ? daysBetween(l.date, asOf || todayStr()) : null;
                const held = (master.holdLots || []).includes(l.lot);
                return `<tr><td><b>${esc(l.lot)}</b></td><td>${slashDate(l.date)}</td><td class="num">${age != null ? `<span class="nk-badge ${age > 60 ? 'nk-alert-red' : age > 30 ? 'nk-alert-amber' : 'nk-alert-gray'}">${age}日</span>` : '—'}</td><td class="num">${fmt(l.bags, 0)} 袋</td><td class="num">${fmt(l.bags * BAG_KG, 0)} kg</td>
                  <td><button type="button" class="nk-btn nk-btn-sm" data-hold="${esc(l.lot)}" ${canEdit() ? '' : 'disabled'} title="特別保管・試験用など、出荷の自動引当から除外します">${held ? '🔒 保管中' : '自動'}</button></td></tr>`;
              }).join('') || '<tr><td colspan="6" class="nk-empty">製品在庫はありません</td></tr>'}</tbody>
              <tfoot><tr><td colspan="3">総計</td><td class="num">${fmt(totalBags, 0)} 袋</td><td class="num">${fmt(totalBags * BAG_KG, 0)} kg</td><td></td></tr></tfoot>
            </table>
          </div>
        </div>
        <div class="nk-card">
          <h2>📈 月別 製造・出荷推移（袋）</h2>
          <p class="nk-card-desc"><span class="nk-bar" style="width:14px"></span> 製造　<span class="nk-bar ship" style="width:14px"></span> 出荷（本システム登録分）</p>
          <div class="nk-table-wrap" tabindex="0" role="region" aria-label="月別推移">
            <table class="nk-table">
              <thead><tr><th>年月</th><th>製造／出荷</th><th class="num">製造</th><th class="num">出荷</th></tr></thead>
              <tbody>${mKeys.map((k) => `<tr><td>${k.replace('-', '/')}</td><td style="min-width:160px">
                <div><span class="nk-bar" style="width:${Math.round(months[k].made / maxM * 100)}%"></span></div>
                <div><span class="nk-bar ship" style="width:${Math.round(months[k].ship / maxM * 100)}%"></span></div></td>
                <td class="num">${fmt(months[k].made, 0)}</td><td class="num">${fmt(months[k].ship, 0)}</td></tr>`).join('') || '<tr><td colspan="4" class="nk-empty">データなし</td></tr>'}</tbody>
            </table>
          </div>
        </div>
      </div>`;
    c.querySelector('#nkAsOf').addEventListener('change', (e) => { ui.asOf = e.target.value; rerender(); });
    c.querySelector('#nkAsOfClear').addEventListener('click', () => { ui.asOf = ''; rerender(); });
    c.querySelectorAll('[data-hold]').forEach((b) => b.addEventListener('click', () => {
      const m = loadMaster();
      const set = new Set(m.holdLots || []);
      const lot = b.dataset.hold;
      if (set.has(lot)) set.delete(lot); else set.add(lot);
      m.holdLots = Array.from(set);
      saveMaster(m);
      toast(set.has(lot) ? `🔒 ${lot} を出荷の自動引当から除外しました（特別保管）` : `${lot} を自動引当の対象に戻しました`);
      rerender();
    }));
  }

  // ===== タブ②：製造・入出庫台帳 =====
  function txQtyHtml(t) {
    if (t.kind.startsWith('raw')) {
      const kg = Number(t.kg) || 0;
      return `<span class="${kg < 0 ? 'nk-diff-neg' : 'nk-diff-pos'}">${kg > 0 ? '+' : ''}${fmt(kg)} kg</span>`;
    }
    const b = prodDelta(t);
    return `<span class="${b < 0 ? 'nk-diff-neg' : 'nk-diff-pos'}">${b > 0 ? '+' : ''}${fmt(b, 0)} 袋</span><div class="nk-note">${fmt(b * BAG_KG, 0)} kg</div>`;
  }
  function renderLedger(c, data, master) {
    const months = Array.from(new Set(data.transactions.map((t) => (t.date || '').slice(0, 7)).filter(Boolean))).sort().reverse();
    const text = ui.ledgerText.trim();
    let list = data.transactions.filter((t) => {
      if (ui.ledgerMonth !== 'all' && (t.date || '').slice(0, 7) !== ui.ledgerMonth) return false;
      if (ui.ledgerKind === 'raw' && !t.kind.startsWith('raw')) return false;
      if (ui.ledgerKind === 'prod' && !t.kind.startsWith('prod')) return false;
      if (!['all', 'raw', 'prod'].includes(ui.ledgerKind) && t.kind !== ui.ledgerKind) return false;
      if (text) {
        const hay = [t.item, t.lot, t.note, t.dest, t.operator, t.batchId, t.shipmentId].join(' ');
        if (!hay.includes(text)) return false;
      }
      return true;
    });
    list = list.slice().sort((a, b) => (b.date || '').localeCompare(a.date || '') || (a.kind.startsWith('prod') ? 1 : 0) - (b.kind.startsWith('prod') ? 1 : 0));
    const shown = list.slice(0, 600);
    const editable = canEdit();

    c.innerHTML = `
      <div class="nk-card">
        <div class="nk-card-head">
          <div><h2>📋 製造・入出庫台帳</h2><p class="nk-card-desc">Excel「④在庫管理表（原料）」「⑤在庫管理表（トロピカル）」に相当します。最下部までのスクロールやコピー＆ペーストは不要です（新しい順に表示）。</p></div>
          <button type="button" class="nk-btn nk-btn-sm" id="nkCsv">⬇ CSV出力（表示中の条件）</button>
        </div>
        <div class="nk-filters">
          <label class="nk-field">年月<select id="nkLm"><option value="all">すべて</option>${months.map((m) => `<option value="${m}" ${ui.ledgerMonth === m ? 'selected' : ''}>${m.replace('-', '年')}月</option>`).join('')}</select></label>
          <label class="nk-field">区分<select id="nkLk">
            <option value="all">すべて</option><option value="raw" ${ui.ledgerKind === 'raw' ? 'selected' : ''}>原料のみ</option><option value="prod" ${ui.ledgerKind === 'prod' ? 'selected' : ''}>製品のみ</option>
            ${Object.entries(KIND_META).map(([k, v]) => `<option value="${k}" ${ui.ledgerKind === k ? 'selected' : ''}>└ ${v.label}</option>`).join('')}
          </select></label>
          <label class="nk-field" style="flex:1;min-width:200px">キーワード（品目・ロット・備考・出荷先・担当者）<input type="search" id="nkLt" value="${esc(ui.ledgerText)}" placeholder="例：オーツヘイ、K261001501、KBS"></label>
          <span class="nk-note">${fmt(list.length, 0)}件${list.length > shown.length ? `（先頭${shown.length}件を表示）` : ''}</span>
        </div>
        <div class="nk-table-wrap" tabindex="0" role="region" aria-label="入出庫台帳">
          <table class="nk-table nk-stack">
            <thead><tr><th>日付</th><th>区分</th><th>品目・ロット</th><th class="num">数量</th><th>荷姿換算</th><th>関連</th><th>担当</th><th>備考</th><th>操作</th></tr></thead>
            <tbody>${shown.map((t) => {
              const meta = KIND_META[t.kind] || { label: t.kind, cls: '' };
              const conv = t.kind.startsWith('raw') && t.pkg ? `${fmt(Math.abs(t.kg) / t.pkg, 2)} × ${fmt(t.pkg, 3)}kg` : '';
              const rel = t.batchId ? `🏭 ${esc(t.batchId.replace('BATCH-', ''))}${t.batches ? `（${fmt(t.batches, 2)}B）` : ''}` : t.shipmentId ? `🚚 ${esc(t.dest || '出荷')}` : (t.stocktakeRef ? `🔍 ${slashDate(t.stocktakeRef)}棚卸` : '');
              return `<tr>
                <td data-label="日付">${slashDate(t.date)}</td>
                <td data-label="区分"><span class="nk-badge ${meta.cls}">${meta.label}</span></td>
                <td data-label="品目">${esc(t.item || ('トロピカル ' + (t.lot || '')))}</td>
                <td data-label="数量" class="num">${txQtyHtml(t)}</td>
                <td data-label="換算" class="nk-note">${conv}</td>
                <td data-label="関連" class="nk-note">${rel}</td>
                <td data-label="担当">${esc(t.operator || '')}</td>
                <td data-label="備考" class="nk-note">${esc(t.note || '')}</td>
                <td data-label="操作" style="white-space:nowrap">
                  <button type="button" class="nk-btn nk-btn-sm" data-edit="${esc(t.id)}" ${editable ? '' : 'disabled'} aria-label="編集">✏️</button>
                  <button type="button" class="nk-btn nk-btn-sm nk-btn-danger" data-del="${esc(t.id)}" ${editable ? '' : 'disabled'} aria-label="削除">🗑</button>
                  ${t.shipmentId ? `<button type="button" class="nk-btn nk-btn-sm" data-ship="${esc(t.shipmentId)}" title="出庫指図書">🖨</button>` : ''}
                </td></tr>`;
            }).join('') || '<tr><td colspan="9" class="nk-empty">該当するデータがありません</td></tr>'}</tbody>
          </table>
        </div>
      </div>`;

    c.querySelector('#nkLm').addEventListener('change', (e) => { ui.ledgerMonth = e.target.value; rerender(); });
    c.querySelector('#nkLk').addEventListener('change', (e) => { ui.ledgerKind = e.target.value; rerender(); });
    let tm = null;
    c.querySelector('#nkLt').addEventListener('input', (e) => {
      clearTimeout(tm);
      tm = setTimeout(() => {
        ui.ledgerText = e.target.value; rerender();
        const el = document.getElementById('nkLt'); if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); }
      }, 350);
    });
    c.querySelector('#nkCsv').addEventListener('click', () => exportLedgerCsv(list));
    c.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => openEditDialog(b.dataset.edit)));
    c.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', () => deleteTx(b.dataset.del)));
    c.querySelectorAll('[data-ship]').forEach((b) => b.addEventListener('click', () => printShippingInstruction(b.dataset.ship)));
  }

  function deleteTx(id) {
    const data = loadData();
    const t = data.transactions.find((x) => x.id === id);
    if (!t) return;
    const group = t.batchId ? data.transactions.filter((x) => x.batchId === t.batchId)
      : t.shipmentId ? data.transactions.filter((x) => x.shipmentId === t.shipmentId) : [t];
    let targets = [t];
    if (group.length > 1) {
      const all = confirm(`この伝票は${t.batchId ? '同日の製造登録' : '同一出荷'}（${group.length}件）の一部です。\n\n［OK］関連する${group.length}件をまとめて削除\n［キャンセル］この1件だけを削除（次の確認へ）`);
      if (all) targets = group;
      else if (!confirm('この1件のみ削除します。よろしいですか？')) return;
    } else if (!confirm(`${slashDate(t.date)}「${t.item || t.lot}」の伝票を削除します。よろしいですか？`)) return;
    const ids = new Set(targets.map((x) => x.id));
    data.transactions = data.transactions.filter((x) => !ids.has(x.id));
    saveData(data);
    toast(`🗑 ${targets.length}件の伝票を削除しました`);
  }

  function exportLedgerCsv(list) {
    const head = ['日付', '区分', '品目', 'ロット', '数量(kg)', '袋数', '荷姿(kg)', '関連ID', '出荷先', '担当', '備考'];
    const lines = [head];
    list.forEach((t) => {
      lines.push([t.date, (KIND_META[t.kind] || {}).label || t.kind, t.item || 'トロピカル', t.lot || '',
        t.kind.startsWith('raw') ? t.kg : prodDelta(t) * BAG_KG, t.kind.startsWith('prod') ? prodDelta(t) : '',
        t.pkg || (t.kind.startsWith('prod') ? BAG_KG : ''), t.batchId || t.shipmentId || t.stocktakeRef || '', t.dest || '', t.operator || '', t.note || '']);
    });
    const csv = '\uFEFF' + lines.map((r) => r.map((v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`).join(',')).join('\r\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = `南関トロピカル_入出庫台帳_${todayStr()}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  // ===== タブ③：隔週棚卸し・差異突合・月末調整 =====
  function stocktakeRows(data, master, date) {
    const stock = rawStock(data, master, date);
    const rows = [];
    sortedMaterials(master).forEach((mat) => {
      lotsOfMaterial(stock, mat.id).forEach((l) => { if (Math.abs(l.kg) > EPS) rows.push({ item: l.item, mat, pkg: l.pkg, book: l.kg }); });
    });
    Array.from(stock.values()).filter((s) => !s.mat && Math.abs(s.kg) > EPS).forEach((s) => rows.push({ item: s.item, mat: null, pkg: s.pkg, book: s.kg }));
    return rows;
  }
  function renderStocktake(c, data, master) {
    const date = ui.stockDate || todayStr();
    const saved = (data.stocktakes || {})[date] || null;
    const counts = saved ? saved.counts || {} : {};
    // 既に保存済みの棚卸に含まれる品目（帳簿0でも）も表示
    const rows = stocktakeRows(data, master, date);
    Object.keys(counts).forEach((item) => {
      if (item !== '__product__' && !rows.find((r) => r.item === item)) {
        const st = rawStock(data, master, date).get(item);
        rows.push({ item, mat: matOfItem(master, item), pkg: st ? st.pkg : null, book: st ? st.kg : 0 });
      }
    });
    const adjusted = data.transactions.some((t) => t.stocktakeRef === date);
    const prodBags = prodStock(data, date).reduce((s, l) => s + l.bags, 0);
    const pc = counts.__product__ || {};
    const savedDates = Object.keys(data.stocktakes || {}).sort().reverse();
    const editable = canEdit() && !adjusted;

    c.innerHTML = `
      <div class="nk-card">
        <div class="nk-card-head">
          <div><h2>🔍 隔週棚卸し・差異突合・月末調整</h2>
          <p class="nk-card-desc">① 現場用棚卸表を印刷 → ② 現場の実数（数量＋端数 または 重量）を入力 → ③ 差異を確認して「在庫集計」を印刷・報告 → ④ 月末は「差異を調整として登録」で帳簿在庫を実在庫にリセットします。<br>在庫がある原料ロットだけが自動で並ぶため、ピボットのフィルタ操作や並べ替えは不要です。</p></div>
        </div>
        <div class="nk-filters">
          <label class="nk-field">棚卸実施日（この日の終業時点の帳簿と比較）<input type="date" id="nkStDate" value="${esc(date)}"></label>
          ${savedDates.length ? `<label class="nk-field">保存済みの棚卸<select id="nkStSaved"><option value="">選択…</option>${savedDates.map((d) => `<option value="${d}" ${d === date ? 'selected' : ''}>${slashDate(d)}${data.transactions.some((t) => t.stocktakeRef === d) ? '（調整済）' : ''}</option>`).join('')}</select></label>` : ''}
          <button type="button" class="nk-btn" id="nkStPrint">🖨 現場用棚卸表を印刷</button>
          <label class="nk-note" style="display:flex;gap:6px;align-items:center"><input type="checkbox" id="nkStShowBook"> 棚卸表に帳簿数量を印字する</label>
        </div>
        ${adjusted ? `<div class="nk-info">✅ ${slashDate(date)} の棚卸差異は調整登録済みです（台帳の「棚卸調整（原料）」）。修正する場合は台帳から該当調整伝票を削除してください。</div>` : ''}
        ${saved ? `<div class="nk-note" style="margin-bottom:8px">💾 最終保存：${esc(saved.savedBy || '')}　${esc((saved.savedAt || '').replace('T', ' ').slice(0, 16))}</div>` : ''}
        <div class="nk-table-wrap" tabindex="0" role="region" aria-label="棚卸入力">
          <table class="nk-table" id="nkStTable">
            <thead><tr><th>商品名（ロット）</th><th class="num">荷姿(kg)</th><th class="num">帳簿在庫(kg)</th><th class="num">実数</th><th class="num">端数(kg)</th><th class="num">実棚重量(kg)</th><th class="num">差異(kg)</th><th>備考</th></tr></thead>
            <tbody>
              ${rows.map((r, i) => {
                const cn = counts[r.item] || {};
                return `<tr data-i="${i}" data-item="${esc(r.item)}" data-pkg="${r.pkg || ''}" data-book="${r.book}">
                  <td><b>${esc(r.item)}</b><div class="nk-note">${esc(r.mat ? r.mat.kana : '')}</div></td>
                  <td class="num">${r.pkg ? fmt(r.pkg, 3) : '—'}</td>
                  <td class="num">${fmt(r.book)}</td>
                  <td style="width:90px"><input class="num nk-st-count" type="number" step="any" min="0" value="${cn.count ?? ''}" placeholder="${esc(r.mat ? r.mat.unit : '')}" ${editable ? '' : 'disabled'}></td>
                  <td style="width:100px"><input class="num nk-st-frac" type="number" step="any" value="${cn.frac ?? ''}" ${editable ? '' : 'disabled'}></td>
                  <td style="width:130px"><input class="num nk-st-kg" type="number" step="any" min="0" value="${cn.kg ?? ''}" placeholder="自動計算" ${editable ? '' : 'disabled'}></td>
                  <td class="num nk-st-diff">—</td>
                  <td style="min-width:120px"><input class="nk-st-note" type="text" value="${esc(cn.note || '')}" ${editable ? '' : 'disabled'}></td>
                </tr>`;
              }).join('')}
              <tr data-product="1" data-book="${prodBags}">
                <td><b>製品 トロピカル（250kg）</b><div class="nk-note">袋数で入力</div></td><td class="num">250</td>
                <td class="num">${fmt(prodBags, 0)} 袋</td>
                <td><input class="num nk-st-pbags" type="number" step="1" min="0" value="${pc.bags ?? ''}" placeholder="袋" ${editable ? '' : 'disabled'}></td>
                <td></td><td class="num nk-st-pkg">—</td><td class="num nk-st-pdiff">—</td>
                <td><input class="nk-st-pnote" type="text" value="${esc(pc.note || '')}" ${editable ? '' : 'disabled'}></td>
              </tr>
              <tr><td><b>仕掛品（端数）</b></td><td></td><td class="num">${fmt(data.wipKg || 0)} kg</td><td></td><td></td>
                <td><input class="num" id="nkStWip" type="number" step="any" min="0" value="${pc.wipKg ?? ''}" placeholder="kg" ${editable ? '' : 'disabled'}></td><td></td><td></td></tr>
            </tbody>
            <tfoot><tr><td colspan="2">原料合計</td><td class="num" id="nkStBookSum">—</td><td></td><td></td><td class="num" id="nkStActSum">—</td><td class="num" id="nkStDiffSum">—</td><td></td></tr></tfoot>
          </table>
        </div>
        <p class="nk-note">実棚重量は「実数 × 荷姿 ＋ 端数」で自動計算されます。計量した重量を直接入力した場合はそちらが優先されます。未入力の行は差異計算・調整の対象外です。</p>
        <div class="nk-actions" style="justify-content:flex-end;margin-top:10px">
          <button type="button" class="nk-btn" id="nkStSave" ${editable ? '' : 'disabled'}>💾 入力内容を保存（共有）</button>
          <button type="button" class="nk-btn" id="nkStReport">🖨 在庫集計（差異報告）を印刷</button>
          <button type="button" class="nk-btn nk-btn-primary" id="nkStAdjust" ${editable ? '' : 'disabled'}>✅ 差異を調整として登録（帳簿を実在庫にリセット）</button>
        </div>
      </div>`;

    const table = c.querySelector('#nkStTable');
    const recalc = () => {
      let bookSum = 0, actSum = 0, diffSum = 0;
      table.querySelectorAll('tr[data-item]').forEach((tr) => {
        const pkg = Number(tr.dataset.pkg) || 0;
        const book = Number(tr.dataset.book) || 0;
        bookSum += book;
        const cnt = tr.querySelector('.nk-st-count').value;
        const frac = tr.querySelector('.nk-st-frac').value;
        const kgEl = tr.querySelector('.nk-st-kg');
        let act = null;
        if (kgEl.value !== '' && kgEl.dataset.manual === '1') act = Number(kgEl.value);
        else if (cnt !== '' || frac !== '') {
          act = r4((Number(cnt) || 0) * pkg + (Number(frac) || 0));
          kgEl.value = act;
          kgEl.dataset.manual = '0';
        } else if (kgEl.value !== '') act = Number(kgEl.value);
        const dEl = tr.querySelector('.nk-st-diff');
        if (act == null) { dEl.textContent = '—'; dEl.className = 'num nk-st-diff'; return; }
        const diff = r4(act - book);
        actSum += act; diffSum += diff;
        dEl.textContent = (diff > 0 ? '+' : '') + fmt(diff);
        dEl.className = 'num nk-st-diff ' + (diff < -EPS ? 'nk-diff-neg' : diff > EPS ? 'nk-diff-pos' : '');
      });
      const ptr = table.querySelector('tr[data-product]');
      const pb = ptr.querySelector('.nk-st-pbags').value;
      if (pb !== '') {
        const d = Number(pb) - Number(ptr.dataset.book);
        ptr.querySelector('.nk-st-pkg').textContent = fmt(Number(pb) * BAG_KG, 0);
        const el = ptr.querySelector('.nk-st-pdiff');
        el.textContent = (d > 0 ? '+' : '') + fmt(d, 0) + ' 袋';
        el.className = 'num nk-st-pdiff ' + (d < 0 ? 'nk-diff-neg' : d > 0 ? 'nk-diff-pos' : '');
      }
      c.querySelector('#nkStBookSum').textContent = fmt(bookSum);
      c.querySelector('#nkStActSum').textContent = fmt(actSum);
      c.querySelector('#nkStDiffSum').textContent = (diffSum > 0 ? '+' : '') + fmt(diffSum);
    };
    table.querySelectorAll('.nk-st-kg').forEach((el) => {
      if (el.value !== '') {
        const tr = el.closest('tr');
        const auto = r4((Number(tr.querySelector('.nk-st-count').value) || 0) * (Number(tr.dataset.pkg) || 0) + (Number(tr.querySelector('.nk-st-frac').value) || 0));
        el.dataset.manual = Math.abs(auto - Number(el.value)) > EPS ? '1' : '0';
      }
      el.addEventListener('input', () => { el.dataset.manual = el.value === '' ? '0' : '1'; recalc(); });
    });
    table.querySelectorAll('.nk-st-count, .nk-st-frac, .nk-st-pbags').forEach((el) => el.addEventListener('input', recalc));
    recalc();

    const collect = () => {
      const out = {};
      table.querySelectorAll('tr[data-item]').forEach((tr) => {
        const cnt = tr.querySelector('.nk-st-count').value;
        const frac = tr.querySelector('.nk-st-frac').value;
        const kg = tr.querySelector('.nk-st-kg').value;
        const note = tr.querySelector('.nk-st-note').value;
        if (cnt === '' && frac === '' && kg === '' && !note) return;
        out[tr.dataset.item] = { count: cnt === '' ? null : Number(cnt), frac: frac === '' ? null : Number(frac), kg: kg === '' ? null : Number(kg), note, book: Number(tr.dataset.book), pkg: Number(tr.dataset.pkg) || null };
      });
      const ptr = table.querySelector('tr[data-product]');
      const pb = ptr.querySelector('.nk-st-pbags').value;
      const wip = c.querySelector('#nkStWip').value;
      out.__product__ = { bags: pb === '' ? null : Number(pb), book: Number(ptr.dataset.book), note: ptr.querySelector('.nk-st-pnote').value, wipKg: wip === '' ? null : Number(wip), wipBook: Number(data.wipKg) || 0 };
      return out;
    };
    const saveDraft = (silent) => {
      const value = { counts: collect(), savedBy: getOperator(), savedAt: new Date().toISOString() };
      const d = loadData();
      saveData(d, { stocktake: { date, value } });
      if (!silent) toast(`💾 ${slashDate(date)} の棚卸入力を保存しました`);
      return value;
    };

    c.querySelector('#nkStDate').addEventListener('change', (e) => { ui.stockDate = e.target.value; rerender(); });
    const sel = c.querySelector('#nkStSaved');
    if (sel) sel.addEventListener('change', (e) => { if (e.target.value) { ui.stockDate = e.target.value; rerender(); } });
    c.querySelector('#nkStPrint').addEventListener('click', () => printCountSheet(date, c.querySelector('#nkStShowBook').checked));
    c.querySelector('#nkStSave').addEventListener('click', () => saveDraft(false));
    c.querySelector('#nkStReport').addEventListener('click', () => {
      const counts2 = collect();
      if (canEdit() && !adjusted) saveDraft(true);
      printStocktakeReport(date, counts2);
    });
    c.querySelector('#nkStAdjust').addEventListener('click', () => {
      const cts = collect();
      const d = loadData();
      if (d.transactions.some((t) => t.stocktakeRef === date)) { toast('この日の棚卸は既に調整済みです'); return; }
      const stock = rawStock(d, master, date);
      const adj = [];
      Object.entries(cts).forEach(([item, v]) => {
        if (item === '__product__') return;
        const act = v.kg != null ? v.kg : (v.count != null || v.frac != null ? r4((v.count || 0) * (v.pkg || 0) + (v.frac || 0)) : null);
        if (act == null) return;
        const book = stock.get(item) ? stock.get(item).kg : 0;
        const diff = r4(act - book);
        if (Math.abs(diff) > EPS) adj.push({ item, diff, pkg: stock.get(item) ? stock.get(item).pkg : v.pkg, book, act });
      });
      const p = cts.__product__ || {};
      const pBook = prodStock(d, date).reduce((s, l) => s + l.bags, 0);
      const pDiff = p.bags != null ? p.bags - pBook : 0;
      if (!adj.length && !pDiff && p.wipKg == null) { toast('調整が必要な差異はありません'); return; }
      const msg = `${slashDate(date)} 付で以下の調整伝票を登録し、帳簿在庫を実棚に合わせます。\n\n` +
        adj.map((a) => `・${a.item}：${a.diff > 0 ? '+' : ''}${fmt(a.diff)} kg（帳簿${fmt(a.book)}→実棚${fmt(a.act)}）`).join('\n') +
        (pDiff ? `\n・製品トロピカル：${pDiff > 0 ? '+' : ''}${pDiff} 袋（ロットは台帳で確認してください）` : '') +
        (p.wipKg != null ? `\n・仕掛品：${fmt(p.wipKg)} kg に更新` : '') + '\n\nよろしいですか？';
      if (!confirm(msg)) return;
      const op = getOperator();
      adj.forEach((a) => d.transactions.push({ id: newId('ADJ'), date, kind: 'raw_adjust', item: a.item, pkg: a.pkg, kg: a.diff, operator: op, note: `棚卸調整（${slashDate(date)} 実棚 ${fmt(a.act)}kg）`, stocktakeRef: date }));
      if (pDiff) {
        const lots = prodStock(d, date).filter((l) => l.bags > 0);
        const lot = pDiff < 0 ? (lots[0] ? lots[0].lot : '') : (lots[lots.length - 1] ? lots[lots.length - 1].lot : '');
        d.transactions.push({ id: newId('ADJ'), date, kind: 'prod_adjust', lot, bags: pDiff, operator: op, note: `棚卸調整（${slashDate(date)} 実棚 ${p.bags}袋）`, stocktakeRef: date });
      }
      const value = { counts: cts, savedBy: op, savedAt: new Date().toISOString(), adjustedAt: new Date().toISOString() };
      saveData(d, Object.assign({ stocktake: { date, value } }, p.wipKg != null ? { wipKg: p.wipKg } : {}));
      toast(`✅ ${adj.length + (pDiff ? 1 : 0)}件の棚卸調整を登録しました`);
    });
  }

  // ===== ダイアログ共通（ネイティブ <dialog>：Escキーで閉じる。誤クリックでの入力消失を防ぐため外側クリックでは閉じない） =====
  function openDialog(title, bodyHtml, footHtml, width) {
    const dlg = document.createElement('dialog');
    dlg.className = 'nk-dialog nk-root';
    if (width) dlg.style.width = width;
    dlg.innerHTML = `
      <div class="nk-dialog-head"><h3>${title}</h3><button type="button" class="nk-btn nk-btn-sm" data-close aria-label="閉じる">✕ 閉じる</button></div>
      <div class="nk-dialog-body">${bodyHtml}</div>
      <div class="nk-dialog-foot">${footHtml || ''}<button type="button" class="nk-btn" data-close>キャンセル</button></div>`;
    document.body.appendChild(dlg);
    dlg.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => dlg.close()));
    dlg.addEventListener('close', () => { dlg.remove(); rerender(); });
    dlg.showModal();
    return dlg;
  }
  function operatorField(id) {
    const m = loadMaster();
    const op = getOperator();
    return `<label class="nk-field">入力担当者<select id="${id}">${m.operators.map((o) => `<option ${o === op ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select></label>`;
  }

  // ----- ⚡ 日次製造（バッチ）一括登録 -----
  function openBatchDialog(prefill) {
    const master = loadMaster();
    const date0 = (prefill && prefill.date) || todayStr();
    const rec0 = recipeForDate(master, date0);
    const dlg = openDialog('⚡ 日次製造（バッチ）一括登録', `
      <div class="nk-info">製造日とバッチ数を選ぶだけで、配合レシピから原料ごとの使用量を自動計算し、<b>古い原料ロットから順に（先入れ先出し）</b>自動で引き当てます。ロットの残量が足りない場合は次のロットへ自動で振り分けます。現場の実績が規定量と異なる場合は「使用量」を直接修正してください。</div>
      <div class="nk-form-grid">
        <label class="nk-field">製造日<input type="date" id="bDate" value="${date0}"></label>
        <label class="nk-field">配合レシピ<select id="bRecipe">${master.recipes.filter((r) => r.status !== 'archived').map((r) => `<option value="${r.id}" ${rec0 && r.id === rec0.id ? 'selected' : ''}>${esc(r.name)}${r.status === 'draft' ? '［下書き］' : ''}</option>`).join('')}</select></label>
        <label class="nk-field">バッチ数（1バッチ＝${fmt(BATCH_KG, 0)}kg）<select id="bBatches">${[1, 2, 3, 4, 5, 6].map((n) => `<option ${n === 3 ? 'selected' : ''}>${n}</option>`).join('')}</select></label>
        <label class="nk-field">包装実績（袋・250kg）<input type="number" id="bBags" min="0" step="1" value="${3 * BAGS_PER_BATCH}"></label>
        <label class="nk-field">製造ロットNo<input type="text" id="bLot" value="${lotFromDate(date0)}"></label>
        <label class="nk-field">終業時点の仕掛品（kg）<input type="number" id="bWip" min="0" step="any" placeholder="変更なしは空欄"></label>
        ${operatorField('bOp')}
        <label class="nk-field">備考<input type="text" id="bNote" placeholder="例：1本特別保管（試験用）"></label>
      </div>
      <div id="bWarn"></div>
      <div class="nk-table-wrap" tabindex="0" role="region" aria-label="原料引当プレビュー">
        <table class="nk-table">
          <thead><tr><th>投入順</th><th>原料</th><th class="num">規定/バッチ</th><th class="num">使用量(kg)</th><th>引当ロット（先入れ先出し）</th><th class="num">引当後の残量</th></tr></thead>
          <tbody id="bRows"></tbody>
          <tfoot><tr><td colspan="3">合計</td><td class="num" id="bTotal">—</td><td colspan="2" id="bTotalNote"></td></tr></tfoot>
        </table>
      </div>`,
      `<label class="nk-note" style="display:flex;gap:6px;align-items:center;margin-right:auto"><input type="checkbox" id="bPrint"> 登録後に製造記録書を印刷</label>
       <button type="button" class="nk-btn nk-btn-primary" id="bSubmit">⚡ 一括登録する</button>`);

    let overrides = {};
    let lastAlloc = [];
    const q = (s) => dlg.querySelector(s);
    const recalc = () => {
      const data = loadData();
      const date = q('#bDate').value || todayStr();
      const recipe = recipeById(master, q('#bRecipe').value);
      const n = Number(q('#bBatches').value) || 0;
      const stock = rawStock(data, master, date);
      const warn = [];
      if (recipe && recipe.status === 'draft') warn.push(`<div class="nk-warn">⚠️ 下書き（未確定）のレシピ「${esc(recipe.name)}」を使用しています。配合内容をご確認ください。</div>`);
      const lot = q('#bLot').value.trim();
      if (lot && data.transactions.some((t) => t.kind === 'prod_in' && t.lot === lot)) warn.push(`<div class="nk-warn">⚠️ ロットNo <b>${esc(lot)}</b> は既に製品入庫が登録されています。同日の追加製造の場合はロットNo末尾（501→502等）を変更してください。</div>`);
      lastAlloc = [];
      let total = 0;
      const rows = (recipe ? recipe.lines : []).map((l, i) => {
        const mat = matById(master, l.mat);
        const key = l.mat + ':' + i;
        const kg = overrides[key] != null ? overrides[key] : r4(Number(l.kg) * n);
        total += kg;
        const { allocations, shortage } = allocateFifo(stock, l.mat, kg, master);
        allocations.forEach((a) => { const s = stock.get(a.item); if (s) s.kg = r4(s.kg - a.kg); });
        lastAlloc.push({ mat: l.mat, kg, allocations });
        const after = allocations.map((a) => { const s = stock.get(a.item); return s ? `${esc(a.item)}：${fmt(s.kg)}kg` : ''; }).join('<br>');
        if (shortage > EPS) warn.push(`<div class="nk-danger">❗ <b>${esc(mat ? mat.name : l.mat)}</b> の在庫が ${fmt(shortage)}kg 不足しています（未登録の入庫がないか確認してください。このまま登録するとマイナス在庫になります）。</div>`);
        return `<tr>
          <td>${esc(mat ? mat.step || '' : '')}</td>
          <td><b>${esc(mat ? mat.name : l.mat)}</b></td>
          <td class="num">${fmt(l.kg)}</td>
          <td style="width:120px"><input class="num" type="number" step="any" min="0" data-key="${key}" value="${kg}"></td>
          <td style="font-size:12.5px">${allocations.map((a) => `${esc(a.item)}：<b>${fmt(a.kg)}</b>kg`).join('<br>') || '—'}</td>
          <td class="num" style="font-size:12px">${after}</td></tr>`;
      });
      q('#bRows').innerHTML = rows.join('') || '<tr><td colspan="6" class="nk-empty">レシピが未設定です</td></tr>';
      q('#bTotal').textContent = fmt(total) + ' kg';
      const bags = Number(q('#bBags').value) || 0;
      q('#bTotalNote').innerHTML = `<span class="nk-note">計画 ${fmt(n * BATCH_KG, 0)}kg／包装 ${bags}袋＝${fmt(bags * BAG_KG, 0)}kg${Math.abs(total - bags * BAG_KG) > 1 ? `（差 ${fmt(total - bags * BAG_KG)}kg は仕掛品・ロス）` : ''}</span>`;
      q('#bWarn').innerHTML = warn.join('');
      q('#bRows').querySelectorAll('input[data-key]').forEach((inp) => inp.addEventListener('change', () => {
        overrides[inp.dataset.key] = inp.value === '' ? null : Number(inp.value);
        recalc();
      }));
    };
    q('#bDate').addEventListener('change', () => {
      const d = q('#bDate').value;
      q('#bLot').value = lotFromDate(d);
      const r = recipeForDate(master, d);
      if (r) q('#bRecipe').value = r.id;
      overrides = {};
      recalc();
    });
    q('#bRecipe').addEventListener('change', () => { overrides = {}; recalc(); });
    q('#bBatches').addEventListener('change', () => { q('#bBags').value = Number(q('#bBatches').value) * BAGS_PER_BATCH; overrides = {}; recalc(); });
    q('#bBags').addEventListener('input', recalc);
    q('#bLot').addEventListener('input', recalc);
    recalc();

    q('#bSubmit').addEventListener('click', () => {
      const date = q('#bDate').value;
      const lot = q('#bLot').value.trim();
      const n = Number(q('#bBatches').value);
      const bags = Number(q('#bBags').value);
      if (!date || !lot) { toast('製造日とロットNoを入力してください'); return; }
      if (!Number.isInteger(bags) || bags < 0) { toast('包装実績（袋）は0以上の整数で入力してください'); return; }
      const data = loadData();
      const op = q('#bOp').value;
      const note = q('#bNote').value.trim();
      const recipe = recipeById(master, q('#bRecipe').value);
      const batchId = `BATCH-${date}-${lot}`;
      lastAlloc.forEach((row) => row.allocations.forEach((a) => {
        if (a.kg <= EPS) return;
        data.transactions.push({ id: newId('RO'), date, kind: 'raw_out', item: a.item, pkg: a.pkg || null, kg: -r4(a.kg), operator: op, note: `トロピカル製造 ${lot}${note ? '／' + note : ''}`, batchId });
      }));
      data.transactions.push({ id: newId('PI'), date, kind: 'prod_in', lot, bags, batches: n, recipeId: recipe ? recipe.id : '', operator: op, note: note || '製造', batchId });
      const wip = q('#bWip').value;
      saveData(data, wip !== '' ? { wipKg: Number(wip) } : null);
      const doPrint = q('#bPrint').checked;
      dlg.close();
      toast(`⚡ ${slashDate(date)} ${n}バッチ（${bags}袋・${lot}）を登録しました`);
      if (doPrint) printBatchRecord(date, n, lot, recipe ? recipe.id : null);
    });
  }

  // ----- 📥 原料入庫 -----
  function openRawInDialog() {
    const master = loadMaster();
    const data = loadData();
    const stock = rawStock(data, master, null);
    const mats = sortedMaterials(master);
    const date0 = todayStr();
    const dlg = openDialog('📥 原料入庫の登録', `
      <div class="nk-info">牧草など入荷ロットごとに荷姿（1個あたり平均重量）が異なる原料は、品名の末尾に入荷日（例：オーツヘイ（1023））を付けて別ロットとして管理します。製造時は古いロットから自動で使用されます。</div>
      <div class="nk-form-grid">
        <label class="nk-field">入庫日<input type="date" id="iDate" value="${date0}"></label>
        <label class="nk-field">原料<select id="iMat">${mats.map((m) => `<option value="${m.id}">${esc(m.name)}</option>`).join('')}</select></label>
        <label class="nk-field">ロット名（品名）<input type="text" id="iItem" list="iItems"><datalist id="iItems"></datalist></label>
        <label class="nk-field">荷姿（1個あたりkg）<input type="number" id="iPkg" step="any" min="0"></label>
        <label class="nk-field">入庫数（個・本・袋）<input type="number" id="iCount" step="any" min="0"></label>
        <label class="nk-field">入庫重量（kg）<input type="number" id="iKg" step="any" min="0" placeholder="自動計算（伝票重量で上書き可）"></label>
        ${operatorField('iOp')}
        <label class="nk-field">入荷元・契約番号・備考<input type="text" id="iNote" placeholder="例：東原→南関、コンテナNo."></label>
      </div>
      <p class="nk-note" id="iHint"></p>`,
      `<button type="button" class="nk-btn nk-btn-primary" id="iSubmit">📥 入庫を登録</button>`, 'min(760px,96vw)');
    const q = (s) => dlg.querySelector(s);
    let kgManual = false;
    const suffix = (d) => `（${d.slice(5, 7)}${d.slice(8, 10)}）`;
    const lotStyle = (m) => ['oats', 'timothy', 'straw', 'corn', 'kinoko', 'apple'].includes(m.id);
    const refreshMat = () => {
      const m = matById(master, q('#iMat').value);
      const lots = lotsOfMaterial(stock, m.id);
      q('#iItems').innerHTML = lots.map((l) => `<option value="${esc(l.item)}">`).join('');
      q('#iItem').value = lotStyle(m) ? m.name.replace('ヘイ', m.id === 'oats' ? 'ヘイ' : '') + suffix(q('#iDate').value) : (lots[lots.length - 1] ? lots[lots.length - 1].item : m.name);
      const last = lots[lots.length - 1];
      q('#iPkg').value = last && last.pkg ? last.pkg : '';
      q('#iHint').textContent = lots.length ? `現在のロット：${lots.map((l) => `${l.item}（${fmt(l.kg)}kg）`).join('、')}` : 'この原料の在庫ロットはまだありません。';
      calc();
    };
    const calc = () => {
      if (kgManual) return;
      const v = (Number(q('#iCount').value) || 0) * (Number(q('#iPkg').value) || 0);
      q('#iKg').value = v ? r4(v) : '';
    };
    q('#iMat').addEventListener('change', refreshMat);
    q('#iDate').addEventListener('change', refreshMat);
    q('#iCount').addEventListener('input', calc);
    q('#iPkg').addEventListener('input', calc);
    q('#iKg').addEventListener('input', () => { kgManual = q('#iKg').value !== ''; });
    refreshMat();
    q('#iSubmit').addEventListener('click', () => {
      const item = q('#iItem').value.trim();
      const kg = Number(q('#iKg').value);
      const pkg = Number(q('#iPkg').value) || null;
      if (!item || !(kg > 0)) { toast('ロット名と入庫重量を入力してください'); return; }
      if (!matOfItem(master, item)) {
        if (!confirm(`「${item}」は原料マスターのどの原料にも一致しません（配合計算の対象外になります）。このまま登録しますか？`)) return;
      }
      const d = loadData();
      const date = q('#iDate').value;
      d.transactions.push({ id: newId('RI'), date, kind: 'raw_in', item, pkg, kg: r4(kg), count: Number(q('#iCount').value) || null, operator: q('#iOp').value, note: q('#iNote').value.trim(), lotOrder: date });
      saveData(d);
      dlg.close();
      toast(`📥 ${item} ${fmt(kg)}kg を入庫登録しました`);
    });
  }

  // ----- 🚚 製品出荷・出庫指図書 -----
  function slipNoStr(n) { return String(n).padStart(10, '0'); }
  function nextSlipNo(data, master) {
    let mx = 0;
    data.transactions.forEach((t) => { const n = parseInt(t.slipNo, 10); if (n > mx) mx = n; });
    return Math.max(Number(master.slipNextNo) || 1, mx + 1);
  }
  function openShipDialog() {
    const data = loadData();
    const master = loadMaster();
    const date0 = todayStr();
    const slipNo = nextSlipNo(data, master);
    const dests = Array.from(new Set([master.company.shipTo, ...data.transactions.filter((t) => t.shipmentId && t.dest).map((t) => t.dest)].filter(Boolean)));
    const carriers = Array.from(new Set(data.transactions.filter((t) => t.carrier).map((t) => t.carrier)));
    const rawItems = Array.from(rawStock(data, master, null).values()).filter((s) => s.kg > EPS)
      .sort((a, b) => ((a.mat ? a.mat.order : 999) - (b.mat ? b.mat.order : 999)) || a.item.localeCompare(b.item, 'ja'));
    const dlg = openDialog('🚚 製品出荷の登録・出庫指図書の発行', `
      <div class="nk-info">出荷袋数を入力すると、<b>古いロットから順に自動で引当て</b>ます（ロット・袋数は変更可。🔒保管中のロットは除外）。登録と同時に山田様の様式どおりの「出庫指図書」を印刷できます。別Excelへの二重入力は不要です。</div>
      <div class="nk-form-grid">
        <label class="nk-field">出庫日<input type="date" id="sDate" value="${date0}"></label>
        <label class="nk-field">伝票No（自動採番）<input type="text" id="sSlip" value="${slipNoStr(slipNo)}" inputmode="numeric"></label>
        <label class="nk-field">出荷先<input type="text" id="sDest" list="sDests" value="${esc(master.company.shipTo || '')}"><datalist id="sDests">${dests.map((d) => `<option value="${esc(d)}">`).join('')}</datalist></label>
        <label class="nk-field">トロピカル 出荷袋数（250kg）<input type="number" id="sBags" min="0" step="1" value="26"></label>
        <label class="nk-field">運送会社（任意・台帳のみ）<input type="text" id="sCarrier" list="sCarriers"><datalist id="sCarriers">${carriers.map((d) => `<option value="${esc(d)}">`).join('')}</datalist></label>
        ${operatorField('sOp')}
      </div>
      <div id="sWarn"></div>
      <h4 style="margin:6px 0">📦 トロピカル（ロット引当）<span class="nk-note">※出庫指図書には合計袋数のみ印字。ロットは台帳に記録されます</span></h4>
      <div class="nk-table-wrap" tabindex="0" role="region" aria-label="出荷ロット引当">
        <table class="nk-table"><thead><tr><th>ロット番号</th><th class="num">現在庫</th><th class="num">出荷袋数</th><th class="num">重量</th><th></th></tr></thead>
        <tbody id="sRows"></tbody><tfoot><tr><td>合計</td><td></td><td class="num" id="sTotal"></td><td class="num" id="sTotalKg"></td><td></td></tr></tfoot></table>
      </div>
      <button type="button" class="nk-btn nk-btn-sm" id="sAddRow" style="margin-top:8px">＋ ロット行を追加</button>
      <h4 style="margin:16px 0 6px">🧪 同送する原料・資材（指図書の明細に印字し、原料在庫から差し引きます）</h4>
      <div class="nk-table-wrap" tabindex="0" role="region" aria-label="同送原料">
        <table class="nk-table"><thead><tr><th>品目（在庫ロット）</th><th>指図書の商品名</th><th class="num">荷姿(kg)</th><th class="num">個数</th><th class="num">数量(kg)</th><th></th></tr></thead>
        <tbody id="sExtra"></tbody></table>
      </div>
      <button type="button" class="nk-btn nk-btn-sm" id="sAddExtra" style="margin-top:8px">＋ 原料・資材を追加（例：サイマスターSP、プロピオン酸カルシウム）</button>
      <label class="nk-field" style="margin-top:16px">備考（指図書に印字・1行ずつ。在庫には影響しません）
        <div class="nk-note" style="font-weight:500;display:flex;gap:6px;align-items:center"><input type="checkbox" id="sCoload" checked> 先頭に「合積み」と印字</div>
        <textarea id="sNote" rows="4" placeholder="例：&#10;ビール粕 600kg×6本 （3,600kg）&#10;きのこ菌床 不定貫×4本 （2,071kg）&#10;日本農産返却用空フレコン 7枚"></textarea>
      </label>
      <p class="nk-note">※ 返却用空フレコンの枚数はここでは備考として印字するのみです（フレコン在庫管理システムへの出庫登録は別途必要です）。</p>`,
      `<label class="nk-note" style="display:flex;gap:6px;align-items:center;margin-right:auto"><input type="checkbox" id="sPrint" checked> 登録後に出庫指図書を印刷</label>
       <button type="button" class="nk-btn nk-btn-primary" id="sSubmit">🚚 出荷を登録</button>`);
    const q = (s) => dlg.querySelector(s);
    let rows = [];
    let extras = [];
    const holds = master.holdLots || [];
    const lotsAt = () => prodStock(loadData(), q('#sDate').value || null).filter((l) => l.bags > 0);
    const auto = () => {
      const { allocations, shortage } = fifoProductLots(loadData(), Number(q('#sBags').value) || 0, q('#sDate').value || null, holds);
      rows = allocations.map((a) => ({ lot: a.lot, bags: a.bags }));
      q('#sWarn').innerHTML = shortage > 0 ? `<div class="nk-danger">❗ トロピカルの在庫が ${shortage}袋 不足しています（製造の登録漏れがないか確認してください）。</div>` : '';
      draw();
    };
    const draw = () => {
      const lots = lotsAt();
      q('#sRows').innerHTML = rows.map((r, i) => `<tr>
        <td><select data-i="${i}" class="sLot">${lots.map((l) => `<option value="${esc(l.lot)}" ${l.lot === r.lot ? 'selected' : ''}>${esc(l.lot)}（${l.bags}袋）${holds.includes(l.lot) ? ' 🔒保管' : ''}</option>`).join('')}${r.lot && !lots.find((l) => l.lot === r.lot) ? `<option selected>${esc(r.lot)}</option>` : ''}</select></td>
        <td class="num">${(lots.find((l) => l.lot === r.lot) || { bags: 0 }).bags} 袋</td>
        <td style="width:110px"><input type="number" class="num sQty" data-i="${i}" min="0" step="1" value="${r.bags}"></td>
        <td class="num">${fmt(r.bags * BAG_KG, 0)} kg</td>
        <td><button type="button" class="nk-btn nk-btn-sm nk-btn-danger" data-rm="${i}" aria-label="行を削除">✕</button></td></tr>`).join('') || '<tr><td colspan="5" class="nk-empty">トロピカルの出荷なし</td></tr>';
      const tot = rows.reduce((s, r) => s + (Number(r.bags) || 0), 0);
      q('#sTotal').textContent = tot + ' 袋';
      q('#sTotalKg').textContent = fmt(tot * BAG_KG, 0) + ' kg';
      q('#sRows').querySelectorAll('.sLot').forEach((el) => el.addEventListener('change', () => { rows[el.dataset.i].lot = el.value; draw(); }));
      q('#sRows').querySelectorAll('.sQty').forEach((el) => el.addEventListener('change', () => { rows[el.dataset.i].bags = Math.max(0, Math.round(Number(el.value) || 0)); draw(); }));
      q('#sRows').querySelectorAll('[data-rm]').forEach((el) => el.addEventListener('click', () => { rows.splice(Number(el.dataset.rm), 1); draw(); }));
    };
    const drawExtra = () => {
      q('#sExtra').innerHTML = extras.map((x, i) => {
        const st = rawItems.find((s) => s.item === x.item);
        return `<tr>
          <td><select class="xItem" data-i="${i}">${rawItems.map((s) => `<option value="${esc(s.item)}" ${s.item === x.item ? 'selected' : ''}>${esc(s.item)}（在庫${fmt(s.kg)}kg）</option>`).join('')}</select></td>
          <td><input class="xName" data-i="${i}" value="${esc(x.name)}"></td>
          <td style="width:100px"><input class="num xPkg" data-i="${i}" type="number" step="any" min="0" value="${x.pkg ?? ''}"></td>
          <td style="width:90px"><input class="num xCnt" data-i="${i}" type="number" step="any" min="0" value="${x.count ?? ''}"></td>
          <td style="width:120px"><input class="num xKg" data-i="${i}" type="number" step="any" min="0" value="${x.kg ?? ''}"></td>
          <td><button type="button" class="nk-btn nk-btn-sm nk-btn-danger" data-xrm="${i}" aria-label="行を削除">✕</button>${st && x.kg > st.kg + EPS ? '<div class="nk-note" style="color:#b91c1c">在庫不足</div>' : ''}</td></tr>`;
      }).join('') || '<tr><td colspan="6" class="nk-empty">同送する原料・資材なし</td></tr>';
      const setDefaults = (x) => {
        const st = rawItems.find((s) => s.item === x.item);
        x.pkg = st && st.pkg ? st.pkg : x.pkg;
        x.name = st && st.mat ? st.mat.name : x.item;
        x.kg = x.count != null && x.pkg ? r4(x.count * x.pkg) : x.kg;
      };
      q('#sExtra').querySelectorAll('.xItem').forEach((el) => el.addEventListener('change', () => { const x = extras[el.dataset.i]; x.item = el.value; setDefaults(x); drawExtra(); }));
      q('#sExtra').querySelectorAll('.xName').forEach((el) => el.addEventListener('input', () => { extras[el.dataset.i].name = el.value; }));
      q('#sExtra').querySelectorAll('.xPkg, .xCnt').forEach((el) => el.addEventListener('change', () => {
        const x = extras[el.dataset.i];
        x.pkg = Number(q(`.xPkg[data-i="${el.dataset.i}"]`).value) || null;
        x.count = q(`.xCnt[data-i="${el.dataset.i}"]`).value === '' ? null : Number(q(`.xCnt[data-i="${el.dataset.i}"]`).value);
        if (x.pkg && x.count != null) x.kg = r4(x.pkg * x.count);
        drawExtra();
      }));
      q('#sExtra').querySelectorAll('.xKg').forEach((el) => el.addEventListener('change', () => { extras[el.dataset.i].kg = Number(el.value) || 0; drawExtra(); }));
      q('#sExtra').querySelectorAll('[data-xrm]').forEach((el) => el.addEventListener('click', () => { extras.splice(Number(el.dataset.xrm), 1); drawExtra(); }));
      extras.__setDefaults = setDefaults;
    };
    q('#sBags').addEventListener('change', auto);
    q('#sDate').addEventListener('change', auto);
    q('#sAddRow').addEventListener('click', () => { const l = lotsAt()[0]; rows.push({ lot: l ? l.lot : '', bags: 0 }); draw(); });
    q('#sAddExtra').addEventListener('click', () => {
      if (!rawItems.length) { toast('在庫のある原料がありません'); return; }
      const pref = rawItems.find((s) => s.mat && s.mat.id === 'cymaster') || rawItems[0];
      const x = { item: pref.item, count: 1 };
      drawExtra(); extras.__setDefaults(x); extras.push(x); drawExtra();
    });
    auto();
    drawExtra();

    q('#sSubmit').addEventListener('click', () => {
      const valid = rows.filter((r) => r.lot && r.bags > 0);
      const xs = extras.filter((x) => x.item && x.kg > 0);
      if (!valid.length && !xs.length) { toast('出荷するトロピカルまたは原料・資材を入力してください'); return; }
      const dest = q('#sDest').value.trim();
      if (!dest) { toast('出荷先を入力してください'); return; }
      const n = parseInt(q('#sSlip').value, 10);
      if (!(n > 0)) { toast('伝票Noを数字で入力してください'); return; }
      const d = loadData();
      if (d.transactions.some((t) => parseInt(t.slipNo, 10) === n) && !confirm(`伝票No ${slipNoStr(n)} は既に使用されています。重複して登録しますか？`)) return;
      const date = q('#sDate').value;
      const shipmentId = newId('SHIP');
      const remarks = q('#sNote').value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      const common = { date, dest, carrier: q('#sCarrier').value.trim(), operator: q('#sOp').value, shipmentId, slipNo: slipNoStr(n), coload: q('#sCoload').checked, remarks, note: remarks.join('／') };
      valid.forEach((r) => d.transactions.push(Object.assign({ id: newId('PO'), kind: 'prod_out', lot: r.lot, bags: r.bags }, common)));
      xs.forEach((x) => d.transactions.push(Object.assign({ id: newId('RS'), kind: 'raw_ship', item: x.item, slipName: x.name || x.item, pkg: x.pkg || null, count: x.count, kg: -r4(x.kg) }, common)));
      saveData(d);
      const m = loadMaster();
      if ((Number(m.slipNextNo) || 0) <= n) { m.slipNextNo = n + 1; saveMaster(m); }
      const doPrint = q('#sPrint').checked;
      dlg.close();
      toast(`🚚 伝票No ${slipNoStr(n)} の出荷を登録しました`);
      if (doPrint) setTimeout(() => printShippingInstruction(shipmentId), 200);
    });
  }

  // ----- ✏️ 個別調整 -----
  function openAdjustDialog() {
    const master = loadMaster();
    const data = loadData();
    const items = Array.from(rawStock(data, master, null).values()).map((s) => s.item);
    const lots = prodStock(data, null).map((l) => l.lot);
    const dlg = openDialog('✏️ 個別調整（原料の移動・ロス・製品の振替など）', `
      <div class="nk-warn">通常の製造・入庫・出荷は専用ボタンから登録してください。ここでは破損ロス、倉庫間移動、特別保管、登録漏れの補正など例外的な増減を登録します。</div>
      <div class="nk-form-grid">
        <label class="nk-field">日付<input type="date" id="aDate" value="${todayStr()}"></label>
        <label class="nk-field">対象<select id="aType"><option value="raw">原料（kg）</option><option value="prod">製品トロピカル（袋）</option></select></label>
        <label class="nk-field">品目／ロット<input type="text" id="aItem" list="aList"><datalist id="aList"></datalist></label>
        <label class="nk-field">増減（マイナスは減少）<input type="number" id="aQty" step="any" placeholder="例：-20"></label>
        ${operatorField('aOp')}
        <label class="nk-field">理由・備考（必須）<input type="text" id="aNote"></label>
      </div>`,
      `<button type="button" class="nk-btn nk-btn-primary" id="aSubmit">登録</button>`, 'min(720px,96vw)');
    const q = (s) => dlg.querySelector(s);
    const fill = () => { q('#aList').innerHTML = (q('#aType').value === 'raw' ? items : lots).map((v) => `<option value="${esc(v)}">`).join(''); q('#aItem').value = ''; };
    q('#aType').addEventListener('change', fill);
    fill();
    q('#aSubmit').addEventListener('click', () => {
      const item = q('#aItem').value.trim();
      const qty = Number(q('#aQty').value);
      const note = q('#aNote').value.trim();
      if (!item || !qty || !note) { toast('品目・増減・理由を入力してください'); return; }
      const d = loadData();
      const base = { id: newId('ADJ'), date: q('#aDate').value, operator: q('#aOp').value, note };
      if (q('#aType').value === 'raw') {
        const st = rawStock(d, master, null).get(item);
        d.transactions.push(Object.assign(base, { kind: 'raw_adjust', item, pkg: st ? st.pkg : null, kg: r4(qty) }));
      } else {
        if (!Number.isInteger(qty)) { toast('製品は袋数（整数）で入力してください'); return; }
        d.transactions.push(Object.assign(base, { kind: 'prod_adjust', lot: item, bags: qty }));
      }
      saveData(d);
      dlg.close();
      toast('✏️ 調整を登録しました');
    });
  }

  // ----- 伝票の編集 -----
  function openEditDialog(id) {
    const data = loadData();
    const t = data.transactions.find((x) => x.id === id);
    if (!t) return;
    const isRaw = t.kind.startsWith('raw');
    const meta = KIND_META[t.kind] || { label: t.kind };
    const dlg = openDialog(`✏️ 伝票の修正（${meta.label}）`, `
      <div class="nk-form-grid">
        <label class="nk-field">日付<input type="date" id="eDate" value="${esc(t.date)}"></label>
        <label class="nk-field">${isRaw ? '品目（ロット名）' : 'ロット番号'}<input type="text" id="eItem" value="${esc(isRaw ? t.item : t.lot)}"></label>
        ${isRaw ? `<label class="nk-field">数量（kg・出庫はマイナス）<input type="number" step="any" id="eQty" value="${t.kg}"></label>
                   <label class="nk-field">荷姿（kg）<input type="number" step="any" id="ePkg" value="${t.pkg || ''}"></label>`
                : `<label class="nk-field">袋数${t.kind === 'prod_adjust' ? '（増減）' : ''}<input type="number" step="1" id="eQty" value="${t.bags}"></label>`}
        ${t.kind === 'prod_out' ? `<label class="nk-field">出荷先<input type="text" id="eDest" value="${esc(t.dest || '')}"></label><label class="nk-field">運送会社<input type="text" id="eCarrier" value="${esc(t.carrier || '')}"></label>` : ''}
        ${operatorField('eOp')}
        <label class="nk-field" style="grid-column:1/-1">備考<input type="text" id="eNote" value="${esc(t.note || '')}"></label>
      </div>
      <p class="nk-note">登録者：${esc(t.operator || '—')}／伝票ID：${esc(t.id)}${t.batchId ? `／製造ID：${esc(t.batchId)}` : ''}</p>`,
      `<button type="button" class="nk-btn nk-btn-primary" id="eSubmit">保存</button>`, 'min(760px,96vw)');
    const q = (s) => dlg.querySelector(s);
    q('#eSubmit').addEventListener('click', () => {
      const d = loadData();
      const x = d.transactions.find((y) => y.id === id);
      if (!x) { toast('伝票が見つかりません（他端末で削除された可能性があります）'); dlg.close(); return; }
      x.date = q('#eDate').value;
      if (isRaw) { x.item = q('#eItem').value.trim(); x.kg = r4(q('#eQty').value); x.pkg = Number(q('#ePkg').value) || null; }
      else { x.lot = q('#eItem').value.trim(); x.bags = Math.round(Number(q('#eQty').value) || 0); }
      if (q('#eDest')) x.dest = q('#eDest').value.trim();
      if (q('#eCarrier')) x.carrier = q('#eCarrier').value.trim();
      x.note = q('#eNote').value.trim();
      x.editedBy = q('#eOp').value;
      x.editedAt = new Date().toISOString();
      saveData(d);
      dlg.close();
      toast('✏️ 伝票を修正しました');
    });
  }

  // ===== タブ④：報告書・指示書 =====
  function renderReports(c, data, master) {
    const months = Array.from(new Set(data.transactions.map((t) => (t.date || '').slice(0, 7)).filter(Boolean))).sort().reverse();
    const stDates = Object.keys(data.stocktakes || {}).sort().reverse();
    const ships = {};
    data.transactions.filter((t) => (t.kind === 'prod_out' || t.kind === 'raw_ship') && t.shipmentId).forEach((t) => {
      const s = ships[t.shipmentId] = ships[t.shipmentId] || { id: t.shipmentId, date: t.date, dest: t.dest || '', bags: 0, slipNo: t.slipNo || '', extra: 0 };
      if (t.kind === 'prod_out') s.bags += Number(t.bags) || 0; else s.extra += 1;
    });
    const shipList = Object.values(ships).sort((a, b) => b.date.localeCompare(a.date));
    const recs = master.recipes.filter((r) => r.status !== 'archived');
    c.innerHTML = `
      <div class="nk-report-grid">
        <div class="nk-report-card">
          <h3>📑 在庫報告（月末在庫証明書）</h3>
          <p>KuKuRu様へ提出する月末時点の原料・製品・仕掛品の在庫報告書です（Excel「8月末」「9月末」シート相当）。棚卸調整後の帳簿在庫で作成します。</p>
          <label class="nk-field">対象月<select id="rpMonth">${months.map((m) => `<option value="${m}">${m.replace('-', '年')}月末</option>`).join('')}</select></label>
          <label class="nk-field">発行日<input type="date" id="rpIssue" value="${todayStr()}"></label>
          <button type="button" class="nk-btn nk-btn-primary" id="rpMonthly">🖨 プレビュー・印刷</button>
        </div>
        <div class="nk-report-card">
          <h3>⚖️ 在庫集計（帳簿重量 vs 棚卸重量・差異）</h3>
          <p>隔週棚卸しの結果報告書です（Excel「週末)0930※報告用」相当）。棚卸しタブで保存した入力内容から作成します。</p>
          <label class="nk-field">棚卸日<select id="rpSt">${stDates.map((d) => `<option value="${d}">${slashDate(d)}</option>`).join('') || '<option value="">（保存済みの棚卸がありません）</option>'}</select></label>
          <button type="button" class="nk-btn nk-btn-primary" id="rpStBtn" ${stDates.length ? '' : 'disabled'}>🖨 プレビュー・印刷</button>
        </div>
        <div class="nk-report-card">
          <h3>🏷️ 倉庫料計算（製品ロット別在庫）</h3>
          <p>指定日時点のトロピカルのロット別在庫数・重量一覧です（Excel「倉庫料計算」相当）。</p>
          <label class="nk-field">基準日<input type="date" id="rpWhDate" value="${todayStr()}"></label>
          <button type="button" class="nk-btn nk-btn-primary" id="rpWh">🖨 プレビュー・印刷</button>
        </div>
        <div class="nk-report-card">
          <h3>📝 製造記録書（現場配布用）</h3>
          <p>製造日前日に印刷して現場へ渡す記録書です（Excel「③製造記録書」相当）。レシピから計画数量を自動印字し、投入実績・時刻は現場で記入します。</p>
          <div class="nk-form-grid" style="margin:0">
            <label class="nk-field">製造日<input type="date" id="rpBDate" value="${todayStr()}"></label>
            <label class="nk-field">バッチ数<select id="rpBN">${[1, 2, 3, 4].map((n) => `<option ${n === 3 ? 'selected' : ''}>${n}</option>`).join('')}</select></label>
          </div>
          <label class="nk-field">レシピ<select id="rpBRec">${recs.map((r) => `<option value="${r.id}" ${recipeForDate(master, todayStr()) && recipeForDate(master, todayStr()).id === r.id ? 'selected' : ''}>${esc(r.name)}</option>`).join('')}</select></label>
          <button type="button" class="nk-btn nk-btn-primary" id="rpBatch">🖨 プレビュー・印刷</button>
        </div>
        <div class="nk-report-card">
          <h3>🚚 出庫指図書</h3>
          <p>登録済みの出荷から出庫指図書を再発行します（山田様ご提供の様式：ロゴ・伝票No・出荷先・明細7行・合積み備考）。新規の出荷は上部「🚚 製品出荷・出庫指図書」から登録してください。</p>
          <label class="nk-field">出荷<select id="rpShip">${shipList.map((s) => `<option value="${esc(s.id)}">${s.slipNo ? 'No.' + esc(String(parseInt(s.slipNo, 10))) + '　' : ''}${slashDate(s.date)} ${esc(s.dest || '出荷先未入力')}（${s.bags}袋${s.extra ? `＋原料${s.extra}品目` : ''}）</option>`).join('') || '<option value="">（出荷登録がありません）</option>'}</select></label>
          <button type="button" class="nk-btn nk-btn-primary" id="rpShipBtn" ${shipList.length ? '' : 'disabled'}>🖨 プレビュー・印刷</button>
        </div>
      </div>`;
    c.querySelector('#rpMonthly').addEventListener('click', () => { const m = c.querySelector('#rpMonth').value; if (m) printMonthlyReport(monthEnd(m), c.querySelector('#rpIssue').value); });
    c.querySelector('#rpStBtn').addEventListener('click', () => {
      const d = c.querySelector('#rpSt').value;
      const st = (loadData().stocktakes || {})[d];
      if (st) printStocktakeReport(d, st.counts || {});
    });
    c.querySelector('#rpWh').addEventListener('click', () => printWarehouseReport(c.querySelector('#rpWhDate').value));
    c.querySelector('#rpBatch').addEventListener('click', () => {
      const d = c.querySelector('#rpBDate').value;
      printBatchRecord(d, Number(c.querySelector('#rpBN').value), lotFromDate(d), c.querySelector('#rpBRec').value);
    });
    c.querySelector('#rpShipBtn').addEventListener('click', () => { const s = c.querySelector('#rpShip').value; if (s) printShippingInstruction(s); });
  }

  // ===== 印刷（A4・新規ウィンドウ） =====
  const PRINT_CSS = `
    @page{size:A4;margin:14mm 12mm}
    *{box-sizing:border-box}
    body{font-family:"Noto Sans JP","Hiragino Kaku Gothic ProN","Yu Gothic",sans-serif;color:#111;font-size:11pt;margin:0;padding:16px}
    h1{text-align:center;font-size:20pt;letter-spacing:.5em;margin:4px 0 14px}
    table{border-collapse:collapse;width:100%;margin:6px 0 12px}
    th,td{border:1px solid #333;padding:4px 6px;font-size:10pt}
    th{background:#eef2f7}
    .num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
    .right{text-align:right}.center{text-align:center}
    .meta{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px}
    .issuer{text-align:right;line-height:1.6}
    .seal{display:inline-block;width:22mm;height:22mm;border:1px dashed #999;text-align:center;line-height:22mm;color:#999;font-size:9pt;margin-left:6px;vertical-align:top}
    .sec{font-weight:700;margin:12px 0 2px}
    .small{font-size:9pt;color:#444}
    .neg{color:#b00}.blank{height:24px}
    .noprint{margin-bottom:12px;padding:10px;background:#f1f5f9;border-radius:8px;font-size:10pt}
    .noprint button{padding:6px 14px;font-weight:700;cursor:pointer}
    .signs{display:flex;justify-content:flex-end;gap:0;margin-top:10px}
    .signs div{border:1px solid #333;width:24mm;text-align:center;font-size:9pt}
    .signs div span{display:block;height:18mm;border-top:1px solid #333}
    @media print{.noprint{display:none}body{padding:0}}`;
  function openPrint(title, body) {
    const w = window.open('', '_blank');
    if (!w) { toast('⚠️ ポップアップがブロックされました。ブラウザの設定でこのサイトのポップアップを許可してください。', 6000); return; }
    w.document.open();
    w.document.write(`<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8"><title>${esc(title)}</title><style>${PRINT_CSS}</style></head><body>
      <div class="noprint">🖨 内容を確認のうえ印刷してください（PDF保存はプリンタ選択で「PDFに保存」）。 <button onclick="window.print()">印刷する</button></div>${body}</body></html>`);
    w.document.close();
  }
  function headerBlock(master, issueDate, withSeal = true) {
    const co = master.company;
    return `<div class="meta"><div>${issueDate ? jpDate(issueDate) : ''}<br><br><b style="font-size:13pt">${esc(co.client)}</b></div>
      <div class="issuer">${esc(co.issuer)}<br>${esc(co.factory)}<br><span class="small">${esc(co.tel)}</span>${withSeal ? '<br><span class="seal">印</span>' : ''}</div></div>`;
  }
  function rawRowsForReport(data, master, date) {
    const stock = rawStock(data, master, date);
    const rows = [];
    sortedMaterials(master).forEach((mat) => lotsOfMaterial(stock, mat.id).forEach((l) => { if (Math.abs(l.kg) > EPS) rows.push(l); }));
    Array.from(stock.values()).filter((s) => !s.mat && Math.abs(s.kg) > EPS).forEach((s) => rows.push(s));
    return rows;
  }

  function printMonthlyReport(date, issueDate) {
    const data = loadData(); const master = loadMaster();
    const rows = rawRowsForReport(data, master, date);
    const prod = prodStock(data, date).filter((l) => l.bags !== 0);
    const bags = prod.reduce((s, l) => s + l.bags, 0);
    const st = (data.stocktakes || {})[date];
    const wip = st && st.counts && st.counts.__product__ && st.counts.__product__.wipKg != null ? st.counts.__product__.wipKg : data.wipKg;
    const adjusted = data.transactions.some((t) => t.stocktakeRef === date);
    openPrint(`在庫報告_${date}`, `
      <h1>在 庫 報 告</h1>${headerBlock(master, issueDate)}
      <p>${jpDate(date)}　時点で、以下の通りに在庫を保管していることを証明いたします。</p>
      ${adjusted ? '' : '<p class="small neg">※ この日付の棚卸調整が未登録です（帳簿在庫で作成しています）。</p>'}
      <div class="sec">○ 原料在庫一覧</div>
      <table><thead><tr><th>原料名</th><th>荷姿(kg)</th><th>実在庫重量(kg)</th></tr></thead>
      <tbody>${rows.map((r) => `<tr><td>${esc(r.item)}</td><td class="num">${r.pkg ? fmt(r.pkg, 6) : ''}</td><td class="num">${fmt(r.kg)}</td></tr>`).join('')}</tbody></table>
      <div class="sec">○ 商品在庫一覧</div>
      <table><thead><tr><th>商品名</th><th>荷姿(kg)</th><th>在庫数(袋)</th><th>在庫重量(kg)</th></tr></thead>
      <tbody><tr><td>トロピカル</td><td class="num">250</td><td class="num">${fmt(bags, 0)}</td><td class="num">${fmt(bags * BAG_KG, 0)}</td></tr>
      <tr><th colspan="2">総計</th><th class="num">${fmt(bags, 0)}</th><th class="num">${fmt(bags * BAG_KG, 0)}</th></tr></tbody></table>
      <p>トロピカル（仕掛品）　${fmt(wip || 0)} kg</p>`);
  }

  function printStocktakeReport(date, counts) {
    const data = loadData(); const master = loadMaster();
    const stock = rawStock(data, master, date);
    // 調整済みの場合は「調整前の帳簿」（調整伝票を除く）で比較
    const adjIds = new Set(data.transactions.filter((t) => t.stocktakeRef === date).map((t) => t.id));
    const before = adjIds.size ? rawStock(data, master, date, adjIds) : stock;
    const items = new Set([...rawRowsForReport(data, master, date).map((r) => r.item), ...Object.keys(counts).filter((k) => k !== '__product__')]);
    if (adjIds.size) before.forEach((s, k) => { if (Math.abs(s.kg) > EPS) items.add(k); });
    const ordered = Array.from(items).sort((a, b) => {
      const ma = matOfItem(master, a), mb = matOfItem(master, b);
      return ((ma ? ma.order : 999) - (mb ? mb.order : 999)) || a.localeCompare(b, 'ja');
    });
    let sb = 0, sa = 0, sbc = 0;
    const body = ordered.map((item) => {
      const s = before.get(item);
      const book = s ? s.kg : 0;
      const v = counts[item];
      const act = v ? (v.kg != null ? v.kg : (v.count != null || v.frac != null ? r4((v.count || 0) * (v.pkg || (s && s.pkg) || 0) + (v.frac || 0)) : null)) : null;
      sb += book; if (act != null) { sa += act; sbc += book; }
      const diff = act != null ? r4(act - book) : null;
      return `<tr><td>${esc(item)}</td><td class="num">${s && s.pkg ? fmt(s.pkg, 6) : ''}</td><td class="num">${fmt(book)}</td><td class="num">${act != null ? fmt(act) : '未計数'}</td><td class="num ${diff < 0 ? 'neg' : ''}">${diff != null ? fmt(diff) : ''}</td><td class="small">${esc(v && v.note || '')}</td></tr>`;
    }).join('');
    const p = counts.__product__ || {};
    const pAdj = data.transactions.filter((t) => t.stocktakeRef === date && t.kind === 'prod_adjust').reduce((s, t) => s + t.bags, 0);
    const pBook = prodStock(data, date).reduce((s, l) => s + l.bags, 0) - pAdj;
    openPrint(`在庫集計_${date}`, `
      <h1>在 庫 集 計</h1>${headerBlock(master, todayStr(), false)}
      <p>${jpDate(date)}　時点での在庫重量と棚卸重量となります。</p>
      <table><thead><tr><th>原料名</th><th>荷姿(kg)</th><th>帳簿 在庫重量(kg)</th><th>棚卸 在庫重量(kg)</th><th>差異(kg)</th><th>備考</th></tr></thead>
      <tbody>${body}</tbody>
      <tfoot><tr><th colspan="2">原料合計</th><th class="num">${fmt(sb)}</th><th class="num">${fmt(sa)}</th><th class="num">${fmt(sa - sbc)}</th><th class="small">差異は計数済み品目のみ</th></tr></tfoot></table>
      <table><thead><tr><th>商品名</th><th>荷姿(kg)</th><th>帳簿 在庫数(袋)</th><th>棚卸 在庫数(袋)</th><th>差異(袋)</th><th>在庫重量(kg)</th></tr></thead>
      <tbody><tr><td>トロピカル</td><td class="num">250</td><td class="num">${fmt(pBook, 0)}</td><td class="num">${p.bags != null ? fmt(p.bags, 0) : '未計数'}</td><td class="num">${p.bags != null ? fmt(p.bags - pBook, 0) : ''}</td><td class="num">${fmt((p.bags != null ? p.bags : pBook) * BAG_KG, 0)}</td></tr></tbody></table>
      <p>トロピカル（仕掛品）　${fmt(p.wipKg != null ? p.wipKg : (data.wipKg || 0))} kg</p>
      <p class="small">差異 ＝ 棚卸重量 − 帳簿重量（プラス：帳簿より多い／マイナス：帳簿より少ない）</p>`);
  }

  function printWarehouseReport(date) {
    const data = loadData();
    const prod = prodStock(data, date).filter((l) => l.bags > 0);
    const bags = prod.reduce((s, l) => s + l.bags, 0);
    openPrint(`倉庫料計算_${date}`, `
      <h1 style="letter-spacing:.2em">倉庫料計算（製品在庫）</h1>
      <p class="right">基準日：${jpDate(date)}</p>
      <table><thead><tr><th>商品名</th><th>荷姿(kg)</th><th>ロット番号</th><th>製造日</th><th>在庫数(袋)</th><th>在庫重量(kg)</th></tr></thead>
      <tbody>${prod.map((l, i) => `<tr><td>${i === 0 ? 'トロピカル' : ''}</td><td class="num">${i === 0 ? 250 : ''}</td><td>${esc(l.lot)}</td><td>${slashDate(l.date)}</td><td class="num">${l.bags}</td><td class="num">${fmt(l.bags * BAG_KG, 0)}</td></tr>`).join('')}
      <tr><th colspan="4">総計</th><th class="num">${bags}</th><th class="num">${fmt(bags * BAG_KG, 0)}</th></tr></tbody></table>`);
  }

  function printCountSheet(date, showBook) {
    const data = loadData(); const master = loadMaster();
    const rows = stocktakeRows(data, master, date);
    const bags = prodStock(data, date).reduce((s, l) => s + l.bags, 0);
    openPrint(`棚卸表_${date}`, `
      <h1 style="letter-spacing:.2em">TMR原料　棚卸表</h1>
      <table style="width:60%"><tr><th style="width:30%">実施日</th><td>${jpDate(date)}</td></tr><tr><th>担当者名</th><td class="blank"></td></tr></table>
      <table><thead>
        <tr class="small"><th>しょうひんめい</th><th>にすがた</th>${showBook ? '<th>ちょうぼ</th>' : ''}<th>ざいこすう</th><th>はんぱ</th><th>ごうけい</th><th>メモ</th></tr>
        <tr><th>商品名</th><th>荷姿(kg)</th>${showBook ? '<th>帳簿(kg)</th>' : ''}<th>在庫数</th><th>端数(kg)</th><th>合計重量(kg)</th><th>備考</th></tr></thead>
      <tbody>${rows.map((r) => `<tr style="height:30px"><td>${esc(r.item)}<div class="small">${esc(r.mat ? r.mat.kana : '')}</div></td><td class="num">${r.pkg ? fmt(r.pkg, 3) : ''}</td>${showBook ? `<td class="num">${fmt(r.book)}</td>` : ''}<td class="right small">${esc(r.mat ? r.mat.unit : '')}</td><td class="right small">kg</td><td class="right small">kg</td><td></td></tr>`).join('')}
      <tr style="height:30px"><td>トロピカル<div class="small">とろぴかる</div></td><td class="num">250</td>${showBook ? `<td class="num">${bags}袋</td>` : ''}<td class="right small">袋</td><td class="right small">kg</td><td class="right small">kg</td><td></td></tr>
      <tr style="height:30px"><td>仕掛品<div class="small">しかかりひん</div></td><td></td>${showBook ? '<td></td>' : ''}<td></td><td></td><td class="right small">kg</td><td></td></tr></tbody></table>`);
  }

  function printBatchRecord(date, n, lot, recipeId) {
    const master = loadMaster();
    const recipe = (recipeId && recipeById(master, recipeId)) || recipeForDate(master, date);
    if (!recipe) { toast('レシピが未設定です'); return; }
    const cols = Array.from({ length: n });
    const lines = recipe.lines.map((l, i) => ({ l, i, mat: matById(master, l.mat) }));
    const steps = [];
    lines.forEach((x) => { const s = (x.mat && x.mat.step) || '—'; let g = steps.find((y) => y.s === s); if (!g) { g = { s, rows: [] }; steps.push(g); } g.rows.push(x); });
    const total = recipeTotal(recipe);
    const body = steps.map((g) => g.rows.map((x, j) => `<tr>${j === 0 ? `<td rowspan="${g.rows.length + 1}" class="center"><b>${esc(g.s)}</b></td>` : ''}<td class="center">${x.i + 1}</td><td>${esc(x.mat ? x.mat.name : x.l.mat)}</td>${cols.map(() => `<td class="num">${fmt(x.l.kg)}</td><td class="right small">㎏</td><td></td>`).join('')}</tr>`).join('') +
      `<tr><td colspan="2" class="small">投入完了時刻</td>${cols.map(() => '<td colspan="3" class="center small">：</td>').join('')}</tr>`).join('');
    openPrint(`製造記録書_${date}`, `
      <h1 style="letter-spacing:.3em">製造記録書</h1>
      <table><tr><th>製品名称</th><td>${esc(master.company.productName)}</td><th>計画出力日</th><td>${jpDate(todayStr())}</td><th>レシピ</th><td class="small">${esc(recipe.name)}</td></tr></table>
      <table>
        <tr><th colspan="3">製造ロットNo</th>${cols.map(() => `<td colspan="3" class="center"><b>${esc(lot)}</b></td>`).join('')}</tr>
        <tr><th colspan="3">製造日</th>${cols.map(() => `<td colspan="3" class="center">${slashDate(date)}</td>`).join('')}</tr>
        <tr><th colspan="3">計画数量</th>${cols.map(() => `<td colspan="3" class="center">${fmt(total)} kg</td>`).join('')}</tr>
        <tr><th colspan="3">記録者名</th>${cols.map(() => '<td colspan="3" class="blank"></td>').join('')}</tr>
        <tr><th colspan="3">ミキサー開始時刻</th>${cols.map(() => '<td colspan="3" class="center">：</td>').join('')}</tr>
        <tr><th>投入順</th><th>No</th><th>原料名称</th>${cols.map((_, k) => `<th>計画数量</th><th>投入実績</th><th>確認</th>`).join('')}</tr>
        ${body}
        <tr><th colspan="3">計</th>${cols.map(() => `<td class="num"><b>${fmt(total)}</b></td><td class="right small">㎏</td><td></td>`).join('')}</tr>
        <tr><th colspan="3">ミキサー終了時刻</th>${cols.map(() => '<td colspan="3" class="center">：</td>').join('')}</tr>
        <tr><th colspan="3">包装実績</th>${cols.map(() => '<td class="right small">袋</td><td colspan="2" class="right small">端数　　　㎏</td>').join('')}</tr>
      </table>
      <div class="signs"><div>工場長<span></span></div><div>飼料製造<br>管理者<span></span></div></div>`);
  }

  function printShippingInstruction(shipmentId) {
    const data = loadData(); const master = loadMaster();
    const list = data.transactions.filter((t) => t.shipmentId === shipmentId && (t.kind === 'prod_out' || t.kind === 'raw_ship'));
    if (!list.length) { toast('出荷データが見つかりません'); return; }
    const h = list.find((t) => t.kind === 'prod_out') || list[0];
    const co = master.company;
    const prodBags = list.filter((t) => t.kind === 'prod_out').reduce((s, t) => s + (Number(t.bags) || 0), 0);
    const lines = [];
    if (prodBags) lines.push({ name: 'トロピカル', pkg: BAG_KG, count: prodBags, kg: prodBags * BAG_KG });
    list.filter((t) => t.kind === 'raw_ship').forEach((t) => lines.push({ name: t.slipName || t.item, pkg: t.pkg, count: t.count, kg: Math.abs(Number(t.kg) || 0) }));
    const lots = list.filter((t) => t.kind === 'prod_out').map((t) => `${t.lot}×${t.bags}`).join('、');
    const remarks = Array.isArray(h.remarks) ? h.remarks : (h.note ? String(h.note).split('／') : []);
    const logo = new URL('src/cascadia-logo-wide.png', window.location.href).href;
    const md = (s) => { if (!s) return ''; const [, m, d] = s.split('-').map(Number); return `${m}月${d}日`; };
    const ROWS = 7;
    const blank = Math.max(0, ROWS - lines.length);
    const css = `
      .slip{width:180mm;margin:0 auto;font-family:"Yu Gothic","游ゴシック","Noto Sans JP",sans-serif}
      .slip-head{position:relative;height:30mm}
      .slip-logo{position:absolute;left:0;top:0;height:9mm}
      .slip-title{text-align:center;font-size:22pt;letter-spacing:.6em;padding-top:10mm;margin:0;border:0}
      .slip-title span{border-bottom:1px solid #000;padding:0 4mm 1mm}
      .slip-meta{width:70mm;margin-left:auto;border:0}
      .slip-meta td{border:0;padding:1mm 2mm;font-size:11pt}
      .slip-meta .no{border-bottom:3px double #000;text-align:center}
      .slip-to{display:flex;justify-content:space-between;align-items:flex-end;margin:6mm 0 4mm}
      .slip-to .dest{width:85mm}
      .slip-to .dest .lbl{font-size:13pt;text-align:center;border-bottom:1px dotted #555;width:40mm}
      .slip-to .dest .name{font-size:15pt;text-align:center;border-bottom:2px solid #000;padding:2mm 0;margin-top:2mm}
      .slip-to .iss{font-size:10pt;line-height:1.6;text-align:left;width:80mm}
      table.lines{border-collapse:collapse;width:100%}
      table.lines th{border:1px solid #000;background:#fff;font-weight:700;text-align:center;padding:2mm}
      table.lines td{border-left:1px solid #000;border-right:1px solid #000;border-bottom:1px dotted #555;height:9mm;padding:1mm 2mm;text-align:center;font-size:11.5pt}
      table.lines tr:last-child td{border-bottom:1px solid #000}
      .remarks{margin-top:6mm;font-size:11pt;line-height:1.9;min-height:40mm}
      .remarks .r{padding-left:22mm}
      .lotnote{margin-top:4mm;font-size:8.5pt;color:#555}`;
    openPrint(`出庫指図書_${h.slipNo || h.date}`, `<style>${css}</style>
      <div class="slip">
        <div class="slip-head"><img class="slip-logo" src="${esc(logo)}" alt="CASCADIA TRADING, INC."><h1 class="slip-title"><span>出庫指図書</span></h1></div>
        <table class="slip-meta"><tr><td class="right">日付：</td><td class="center">${jpDate(h.date)}</td></tr>
          <tr><td class="right">伝票No:</td><td class="no">${esc(h.slipNo || '')}</td></tr></table>
        <div class="slip-to">
          <div class="dest"><div class="lbl">出荷先</div><div class="name">${esc(h.dest || '')}</div></div>
          <div class="iss">${esc(co.hqPostal || '')}<br>${esc(co.hqAddress1 || '')}<br>${esc(co.hqAddress2 || '')}<br>${esc(co.hqTel || '')}<br>担当：${esc(h.operator || '')}</div>
        </div>
        <table class="lines">
          <thead><tr><th style="width:17%">出庫日</th><th style="width:30%">商品名</th><th style="width:14%">荷姿</th><th style="width:15%">個数</th><th style="width:24%">数量</th></tr></thead>
          <tbody>${lines.map((l) => `<tr><td>${md(h.date)}</td><td>${esc(l.name)}</td><td>${l.pkg ? fmt(l.pkg, 3) : ''}</td><td>${l.count != null ? fmt(l.count, 2) : ''}</td><td>${fmt(l.kg, 2)}kg</td></tr>`).join('')}
            ${Array.from({ length: blank }).map(() => '<tr><td></td><td></td><td></td><td></td><td></td></tr>').join('')}</tbody>
        </table>
        <div class="remarks">備考　　${h.coload === false ? '' : '合積み'}${remarks.map((r) => `<div class="r">${esc(r)}</div>`).join('')}</div>
        ${lots ? `<div class="lotnote noprint">（社内控え・印刷されません）ロット内訳：${esc(lots)}</div>` : ''}
      </div>`);
  }

  // ===== タブ⑤：配合レシピ・マスター =====
  function renderMaster(c, data, master) {
    const sub = ui.masterSub;
    c.innerHTML = `
      <div class="nk-subtabs">
        ${[['recipes', '🧪 配合レシピ'], ['materials', '🌾 原料マスター'], ['settings', '👤 担当者・帳票設定'], ['backup', '💾 バックアップ']]
          .map(([k, l]) => `<button type="button" class="nk-tab ${sub === k ? 'active' : ''}" data-sub="${k}" style="background:${sub === k ? '#fff' : '#f1f5f9'}">${l}</button>`).join('')}
      </div><div id="nkMasterBody"></div>`;
    c.querySelectorAll('[data-sub]').forEach((b) => b.addEventListener('click', () => { ui.masterSub = b.dataset.sub; rerender(); }));
    const body = c.querySelector('#nkMasterBody');
    if (sub === 'materials') renderMaterialMaster(body, master);
    else if (sub === 'settings') renderSettings(body, master);
    else if (sub === 'backup') renderBackup(body, data, master);
    else renderRecipeMaster(body, master);
  }

  function renderRecipeMaster(body, master) {
    const editable = canEdit();
    const cur = recipeById(master, ui.editRecipeId) || recipeForDate(master, todayStr()) || master.recipes[0];
    const statusBadge = (s) => s === 'active' ? '<span class="nk-badge nk-alert-ok">有効</span>' : s === 'draft' ? '<span class="nk-badge nk-alert-amber">下書き</span>' : '<span class="nk-badge nk-alert-gray">廃止</span>';
    body.innerHTML = `
      <div class="nk-grid2" style="grid-template-columns:minmax(260px,340px) 1fr">
        <div class="nk-card">
          <h2>レシピ一覧</h2><p class="nk-card-desc">製造登録時は「有効」かつ適用開始日が製造日以前のうち最新のレシピが自動選択されます。</p>
          ${master.recipes.slice().sort((a, b) => (b.validFrom || '').localeCompare(a.validFrom || '')).map((r) => `
            <button type="button" class="nk-btn" data-rid="${esc(r.id)}" style="width:100%;justify-content:space-between;margin-bottom:6px;${cur && cur.id === r.id ? 'border-color:#047857;background:#ecfdf5' : ''}">
              <span style="text-align:left">${esc(r.name)}<br><span class="nk-note">${slashDate(r.validFrom)}〜／${fmt(recipeTotal(r))}kg</span></span>${statusBadge(r.status)}</button>`).join('')}
          <button type="button" class="nk-btn nk-btn-sm" id="rcNew" ${editable ? '' : 'disabled'} style="margin-top:6px">＋ 選択中のレシピを複製して新規作成</button>
        </div>
        <div class="nk-card">
          ${cur ? `
          <h2>🧪 レシピ編集</h2>
          <div class="nk-form-grid">
            <label class="nk-field" style="grid-column:span 2">レシピ名<input type="text" id="rcName" value="${esc(cur.name)}" ${editable ? '' : 'disabled'}></label>
            <label class="nk-field">適用開始日<input type="date" id="rcFrom" value="${esc(cur.validFrom || '')}" ${editable ? '' : 'disabled'}></label>
            <label class="nk-field">状態<select id="rcStatus" ${editable ? '' : 'disabled'}><option value="active" ${cur.status === 'active' ? 'selected' : ''}>有効</option><option value="draft" ${cur.status === 'draft' ? 'selected' : ''}>下書き（未確定）</option><option value="archived" ${cur.status === 'archived' ? 'selected' : ''}>廃止</option></select></label>
            <label class="nk-field" style="grid-column:1/-1">メモ<input type="text" id="rcNote" value="${esc(cur.note || '')}" ${editable ? '' : 'disabled'}></label>
          </div>
          <div class="nk-table-wrap"><table class="nk-table"><thead><tr><th>No</th><th>原料</th><th class="num">1バッチ使用量(kg)</th><th class="num">配合割合</th><th></th></tr></thead>
            <tbody id="rcLines">${cur.lines.map((l, i) => `<tr><td>${i + 1}</td>
              <td><select class="rcMat" ${editable ? '' : 'disabled'}>${sortedMaterials(master).map((m) => `<option value="${m.id}" ${m.id === l.mat ? 'selected' : ''}>${esc(m.step || '')} ${esc(m.name)}</option>`).join('')}</select></td>
              <td style="width:150px"><input class="num rcKg" type="number" step="any" min="0" value="${l.kg}" ${editable ? '' : 'disabled'}></td>
              <td class="num rcPct"></td>
              <td><button type="button" class="nk-btn nk-btn-sm nk-btn-danger rcDel" ${editable ? '' : 'disabled'} aria-label="行を削除">✕</button></td></tr>`).join('')}</tbody>
            <tfoot><tr><td colspan="2">合計（1バッチ）</td><td class="num" id="rcTotal"></td><td class="num">100%</td><td></td></tr></tfoot></table></div>
          <div id="rcWarn"></div>
          <div class="nk-actions" style="justify-content:space-between;margin-top:10px">
            <button type="button" class="nk-btn nk-btn-sm" id="rcAdd" ${editable ? '' : 'disabled'}>＋ 原料を追加</button>
            <div class="nk-actions">
              <button type="button" class="nk-btn nk-btn-danger nk-btn-sm" id="rcRemove" ${editable ? '' : 'disabled'}>このレシピを削除</button>
              <button type="button" class="nk-btn nk-btn-primary" id="rcSave" ${editable ? '' : 'disabled'}>💾 レシピを保存</button>
            </div>
          </div>` : '<div class="nk-empty">レシピがありません</div>'}
        </div>
      </div>`;
    body.querySelectorAll('[data-rid]').forEach((b) => b.addEventListener('click', () => { ui.editRecipeId = b.dataset.rid; rerender(); }));
    if (!cur) return;
    const tb = body.querySelector('#rcLines');
    const recalc = () => {
      const kgs = Array.from(tb.querySelectorAll('.rcKg')).map((i) => Number(i.value) || 0);
      const tot = kgs.reduce((a, b) => a + b, 0);
      tb.querySelectorAll('.rcPct').forEach((td, i) => { td.textContent = tot ? fmt(kgs[i] / tot * 100, 3) + '%' : '—'; });
      body.querySelector('#rcTotal').textContent = fmt(tot) + ' kg';
      body.querySelector('#rcWarn').innerHTML = Math.abs(tot - BATCH_KG) > 0.5 ? `<div class="nk-warn">⚠️ 1バッチ合計が ${fmt(tot)}kg です（標準 ${fmt(BATCH_KG, 0)}kg・7袋）。差分は包装時の端数（仕掛品）になります。</div>` : '';
    };
    tb.addEventListener('input', recalc);
    tb.querySelectorAll('.rcDel').forEach((b) => b.addEventListener('click', () => { b.closest('tr').remove(); recalc(); }));
    recalc();
    const collectLines = () => Array.from(tb.querySelectorAll('tr')).map((tr) => ({ mat: tr.querySelector('.rcMat').value, kg: r4(tr.querySelector('.rcKg').value) })).filter((l) => l.kg > 0);
    body.querySelector('#rcAdd').addEventListener('click', () => {
      const m = loadMaster(); const r = recipeById(m, cur.id);
      r.lines = collectLines(); r.lines.push({ mat: sortedMaterials(m)[0].id, kg: 0.0001 });
      ui.editRecipeId = cur.id; saveMaster(m); rerender();
    });
    body.querySelector('#rcSave').addEventListener('click', () => {
      const m = loadMaster(); const r = recipeById(m, cur.id);
      r.name = body.querySelector('#rcName').value.trim() || r.name;
      r.validFrom = body.querySelector('#rcFrom').value;
      r.status = body.querySelector('#rcStatus').value;
      r.note = body.querySelector('#rcNote').value.trim();
      r.lines = collectLines();
      r.updatedBy = getOperator(); r.updatedAt = new Date().toISOString();
      saveMaster(m); toast('💾 レシピを保存しました（全端末に共有されます）'); rerender();
    });
    body.querySelector('#rcRemove').addEventListener('click', () => {
      const used = loadData().transactions.some((t) => t.recipeId === cur.id);
      if (used) { toast('製造実績で使用済みのレシピは削除できません。状態を「廃止」にしてください。', 5000); return; }
      if (!confirm(`レシピ「${cur.name}」を削除しますか？`)) return;
      const m = loadMaster(); m.recipes = m.recipes.filter((r) => r.id !== cur.id);
      ui.editRecipeId = null; saveMaster(m); rerender();
    });
    body.querySelector('#rcNew').addEventListener('click', () => {
      const m = loadMaster(); const src = recipeById(m, cur.id);
      const nr = clone(src);
      nr.id = 'R' + Date.now().toString(36); nr.name = src.name.replace(/（.*$/, '') + '（新規）'; nr.status = 'draft'; nr.validFrom = todayStr(); nr.note = '';
      m.recipes.push(nr); ui.editRecipeId = nr.id; saveMaster(m); rerender();
      toast('下書きレシピを作成しました。内容を編集して「有効」にしてください。');
    });
  }

  function renderMaterialMaster(body, master) {
    const editable = canEdit();
    const data = loadData();
    const stock = rawStock(data, master, null);
    body.innerHTML = `
      <div class="nk-card">
        <h2>🌾 原料マスター</h2>
        <p class="nk-card-desc">「ロット名の先頭文字」で台帳の品名（例：オーツヘイ（0910））と原料を紐づけます。表示順は棚卸表・報告書・ダッシュボードの並び順、投入順は製造記録書のグループに使用します。</p>
        <div class="nk-table-wrap"><table class="nk-table"><thead><tr><th>表示順</th><th>原料名</th><th>ロット名の先頭文字</th><th>ふりがな（棚卸表）</th><th>単位</th><th>投入順</th><th class="num">現在の在庫</th></tr></thead>
        <tbody id="mmRows">${sortedMaterials(master).map((m) => `<tr data-id="${esc(m.id)}">
          <td style="width:80px"><input class="num mmOrder" type="number" value="${m.order || 0}" ${editable ? '' : 'disabled'}></td>
          <td><input class="mmName" value="${esc(m.name)}" ${editable ? '' : 'disabled'}></td>
          <td><input class="mmPrefix" value="${esc(m.prefix)}" ${editable ? '' : 'disabled'}></td>
          <td><input class="mmKana" value="${esc(m.kana || '')}" ${editable ? '' : 'disabled'}></td>
          <td style="width:90px"><input class="mmUnit" value="${esc(m.unit || '')}" ${editable ? '' : 'disabled'}></td>
          <td style="width:80px"><input class="mmStep" value="${esc(m.step || '')}" ${editable ? '' : 'disabled'}></td>
          <td class="num">${fmt(lotsOfMaterial(stock, m.id).reduce((s, l) => s + l.kg, 0))} kg</td></tr>`).join('')}</tbody></table></div>
        <div class="nk-actions" style="justify-content:space-between;margin-top:10px">
          <button type="button" class="nk-btn nk-btn-sm" id="mmAdd" ${editable ? '' : 'disabled'}>＋ 原料を追加</button>
          <button type="button" class="nk-btn nk-btn-primary" id="mmSave" ${editable ? '' : 'disabled'}>💾 原料マスターを保存</button>
        </div>
      </div>`;
    const collect = (m) => {
      body.querySelectorAll('#mmRows tr').forEach((tr) => {
        const x = m.materials.find((y) => y.id === tr.dataset.id);
        if (!x) return;
        x.order = Number(tr.querySelector('.mmOrder').value) || 0;
        x.name = tr.querySelector('.mmName').value.trim() || x.name;
        x.prefix = tr.querySelector('.mmPrefix').value.trim() || x.prefix;
        x.kana = tr.querySelector('.mmKana').value.trim();
        x.unit = tr.querySelector('.mmUnit').value.trim();
        x.step = tr.querySelector('.mmStep').value.trim();
      });
    };
    body.querySelector('#mmSave').addEventListener('click', () => { const m = loadMaster(); collect(m); saveMaster(m); toast('💾 原料マスターを保存しました'); rerender(); });
    body.querySelector('#mmAdd').addEventListener('click', () => {
      const name = prompt('追加する原料名を入力してください（例：ビートパルプ）');
      if (!name) return;
      const m = loadMaster(); collect(m);
      m.materials.push({ id: 'm' + Date.now().toString(36), name: name.trim(), prefix: name.trim(), unit: '本', kana: '', step: '②', order: Math.max(0, ...m.materials.map((x) => x.order || 0)) + 10 });
      saveMaster(m); rerender();
    });
  }

  function renderSettings(body, master) {
    const editable = canEdit();
    const co = master.company;
    body.innerHTML = `
      <div class="nk-card">
        <h2>👤 担当者・帳票設定</h2>
        <div class="nk-form-grid">
          <label class="nk-field" style="grid-column:1/-1">入力担当者（カンマ区切り・先頭が既定）<input id="stOps" value="${esc(master.operators.join(', '))}" ${editable ? '' : 'disabled'}></label>
          <label class="nk-field">報告書の宛先<input id="stClient" value="${esc(co.client)}" ${editable ? '' : 'disabled'}></label>
          <label class="nk-field">発行者（会社名）<input id="stIssuer" value="${esc(co.issuer)}" ${editable ? '' : 'disabled'}></label>
          <label class="nk-field">事業所名<input id="stFactory" value="${esc(co.factory)}" ${editable ? '' : 'disabled'}></label>
          <label class="nk-field">TEL/FAX<input id="stTel" value="${esc(co.tel)}" ${editable ? '' : 'disabled'}></label>
          <label class="nk-field">保管倉庫名<input id="stWh" value="${esc(co.warehouse)}" ${editable ? '' : 'disabled'}></label>
          <label class="nk-field">製品名称（製造記録書）<input id="stProd" value="${esc(co.productName)}" ${editable ? '' : 'disabled'}></label>
        </div>
        <h3 style="font-size:14px;margin:8px 0">🚚 出庫指図書</h3>
        <div class="nk-form-grid">
          <label class="nk-field">出荷先（初期値）<input id="stShipTo" value="${esc(co.shipTo || '')}" ${editable ? '' : 'disabled'}></label>
          <label class="nk-field">次の伝票No<input id="stSlip" type="number" min="1" step="1" value="${Number(master.slipNextNo) || 1}" ${editable ? '' : 'disabled'}></label>
          <label class="nk-field">〒<input id="stHqPostal" value="${esc(co.hqPostal || '')}" ${editable ? '' : 'disabled'}></label>
          <label class="nk-field">住所1<input id="stHqA1" value="${esc(co.hqAddress1 || '')}" ${editable ? '' : 'disabled'}></label>
          <label class="nk-field">住所2<input id="stHqA2" value="${esc(co.hqAddress2 || '')}" ${editable ? '' : 'disabled'}></label>
          <label class="nk-field">TEL/FAX<input id="stHqTel" value="${esc(co.hqTel || '')}" ${editable ? '' : 'disabled'}></label>
        </div>
        <div class="nk-actions" style="justify-content:flex-end"><button type="button" class="nk-btn nk-btn-primary" id="stSave" ${editable ? '' : 'disabled'}>💾 保存</button></div>
      </div>`;
    body.querySelector('#stSave').addEventListener('click', () => {
      const m = loadMaster();
      const ops = body.querySelector('#stOps').value.split(/[,、，]/).map((s) => s.trim()).filter(Boolean);
      if (!ops.length) { toast('担当者を1名以上入力してください'); return; }
      m.operators = ops;
      Object.assign(m.company, {
        client: body.querySelector('#stClient').value, issuer: body.querySelector('#stIssuer').value, factory: body.querySelector('#stFactory').value,
        tel: body.querySelector('#stTel').value, warehouse: body.querySelector('#stWh').value, productName: body.querySelector('#stProd').value,
        shipTo: body.querySelector('#stShipTo').value, hqPostal: body.querySelector('#stHqPostal').value, hqAddress1: body.querySelector('#stHqA1').value,
        hqAddress2: body.querySelector('#stHqA2').value, hqTel: body.querySelector('#stHqTel').value
      });
      const sn = parseInt(body.querySelector('#stSlip').value, 10);
      if (sn > 0) m.slipNextNo = sn;
      saveMaster(m); toast('💾 設定を保存しました'); rerender();
    });
  }

  function renderBackup(body, data, master) {
    const editable = canEdit();
    body.innerHTML = `
      <div class="nk-card">
        <h2>💾 バックアップ・復元</h2>
        <p class="nk-card-desc">現在 ${fmt(data.transactions.length, 0)} 件の伝票が登録されています（初期データ：${esc(data.source || '—')}）。</p>
        <div class="nk-actions">
          <button type="button" class="nk-btn" id="bkExport">⬇ 全データをJSONで保存</button>
          <button type="button" class="nk-btn" id="bkCsv">⬇ 全伝票をCSVで保存</button>
          <label class="nk-btn ${editable ? '' : 'nk-disabled'}" style="cursor:pointer">⬆ JSONから復元<input type="file" id="bkImport" accept="application/json" hidden ${editable ? '' : 'disabled'}></label>
        </div>
        ${data.skippedResiduals && data.skippedResiduals.length ? `<div class="nk-info">ℹ️ Excelからの移行時、9月末時点で端数のみ残っていた旧ロット（${data.skippedResiduals.map((s) => `${esc(s.item)} ${s.kg}kg`).join('、')}）は在庫ゼロとして扱いました。</div>` : ''}
        <div class="nk-danger" style="margin-top:16px">🔄 <b>初期データへリセット</b>：全端末の共有データを、Excelから移行した初期状態（2026年9月末確定在庫＋10月実績）に戻します。登録済みの伝票はすべて失われます。
          <div style="margin-top:8px"><button type="button" class="nk-btn nk-btn-danger" id="bkReset" ${editable ? '' : 'disabled'}>初期データへリセット</button></div></div>
      </div>`;
    body.querySelector('#bkExport').addEventListener('click', () => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), data: loadData(), master: loadMaster() }, null, 1)], { type: 'application/json' }));
      a.download = `南関トロピカル_バックアップ_${todayStr()}.json`;
      a.click();
    });
    body.querySelector('#bkCsv').addEventListener('click', () => exportLedgerCsv(loadData().transactions.slice().sort((a, b) => a.date.localeCompare(b.date))));
    body.querySelector('#bkImport').addEventListener('change', (e) => {
      const f = e.target.files[0];
      if (!f) return;
      f.text().then((txt) => {
        const j = JSON.parse(txt);
        if (!j.data || !Array.isArray(j.data.transactions)) throw new Error('形式が不正です');
        if (!confirm(`${j.exportedAt ? slashDate(j.exportedAt.slice(0, 10)) + ' 時点の' : ''}バックアップ（伝票${j.data.transactions.length}件）で共有データを上書きします。よろしいですか？`)) return;
        if (j.master) saveMaster(j.master);
        saveData(j.data, null, { fullOverwrite: true });
        toast('⬆ バックアップから復元しました');
      }).catch((err) => toast('復元に失敗しました：' + err.message, 6000));
    });
    body.querySelector('#bkReset').addEventListener('click', () => {
      if (!confirm('全端末の共有データを初期状態に戻します。登録済みの伝票はすべて失われます。よろしいですか？')) return;
      if (prompt('確認のため「リセット」と入力してください') !== 'リセット') return;
      saveData(freshData(), null, { fullOverwrite: true });
      toast('🔄 初期データにリセットしました');
    });
  }

  // ===== 公開API =====
  window.renderNankanSystem = renderNankanSystem;
  window.NankanSystem = {
    render: renderNankanSystem,
    // テスト・検証用（在庫計算ロジック）
    _internal: { rawStock, prodStock, allocateFifo, fifoProductLots, loadMaster, freshData, recipeForDate, lotFromDate, DEFAULT_MASTER }
  };
})();
