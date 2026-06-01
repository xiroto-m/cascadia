// app.js - Main Application Logic

const sidebarToggle = document.getElementById('sidebarToggle');
const sidebar = document.getElementById('sidebar');
const contentArea = document.getElementById('contentArea');
const breadcrumbPage = document.getElementById('breadcrumbPage');

// Setup sidebar toggle
sidebarToggle.addEventListener('click', () => {
  sidebar.classList.toggle('open');
});

// Setup accordion
document.querySelectorAll('.nav-section-title').forEach(title => {
  title.addEventListener('click', () => {
    title.classList.toggle('open');
    const items = title.nextElementSibling;
    items.classList.toggle('show');
  });
});

// Helper functions that might be used inside app.js for dom-buy
function tbl(hd,rows){
  if(hd[0] === 'Step') {
    let stepsHtml = rows.map(row => {
      let stepNum = row[0];
      let assignee = row[1];
      let action = row[2];
      let sys = row[3] || '—';
      let output = row[4] || '—';
      
      let sysHtml = sys !== '—' ? `<span class="step-sys">${sys}</span>` : '';
      let outHtml = output !== '—' ? `<div class="step-output">📄 出力: ${output}</div>` : '';
      
      return `<div class="step-item">
        <div class="step-marker">${stepNum}</div>
        <div class="step-content">
          <div class="step-header">
            <span class="step-assignee">${assignee}</span>
            ${sysHtml}
          </div>
          <div class="step-action">${action}</div>
          ${outHtml}
        </div>
      </div>`;
    }).join('');
    return `<div class="step-list">${stepsHtml}</div>`;
  }
  let h=hd.map(c=>`<th>${c}</th>`).join('');
  let r=rows.map(row=>`<tr>${row.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('');
  return `<div class="table-wrapper"><table><thead><tr>${h}</tr></thead><tbody>${r}</tbody></table></div>`;
}
function sec(n,t){return `<div class="section-header"><div class="section-number">${n}</div><div class="section-title">${t}</div></div>`;}
function sub(t){return `<h4 class="subsection-title">${t}</h4>`;}
function note(t,cls='note',icon='📘 NOTE'){return `<div class="alert alert-${cls}"><div class="alert-title">${icon}</div>${t}</div>`;}
function cl(items){return `<ul class="checklist">${items.map(i=>`<li><div class="check-box"></div><span>${i}</span></li>`).join('')}</ul>`;}
function caution(items){return `<div class="alert alert-caution"><div class="alert-title">🔴 有識者確認必須</div><ul style="margin:0;padding-left:18px;line-height:1.8">${items.map(i=>`<li>${i}</li>`).join('')}</ul></div>`;}
function meta(id, sys, pages, status) {
  return `<div class="meta-card"><div class="meta-grid">
    <div><div class="meta-item-label">文書ID</div><div class="meta-item-value">${id}</div></div>
    <div><div class="meta-item-label">対象システム</div><div class="meta-item-value"><span class="tag tag-system">${sys}</span></div></div>
    <div><div class="meta-item-label">対象ページ</div><div class="meta-item-value">${pages}</div></div>
    <div><div class="meta-item-label">ステータス</div><div class="meta-item-value"><span class="tag tag-manual">${status||'有識者確認待ち'}</span></div></div>
  </div></div>`;
}

PAGES_DATA['home'] = {
  breadcrumb: 'はじめに',
  html: `
    <h1 class="page-title">業務部マニュアル</h1>
    <p class="page-subtitle">株式会社カスケディア・トレーディング 業務部 — プロセスフロー・操作手順・チェックリスト統合マニュアル</p>
    <div class="stats-row">
      <div class="stat-card"><div class="stat-value">10</div><div class="stat-label">プロセス文書</div></div>
      <div class="stat-card"><div class="stat-value">20</div><div class="stat-label">対象ページ</div></div>
      <div class="stat-card"><div class="stat-value">8</div><div class="stat-label">カテゴリ</div></div>
      <div class="stat-card"><div class="stat-value">35</div><div class="stat-label">有識者確認項目</div></div>
    </div>
    ${note('本マニュアルは「ご提案フロー」（全20ページ）を骨組みとし、4部構成テンプレート（トリガー/手順/例外/チェックリスト）で統一しています。')}
    ${sec(0, '目次構成')}
    ${tbl(['#','カテゴリ','文書','対象ページ'], [
      ['01','国内取引','買継取引（3パターン）','P2-4'],
      ['02','国内取引','在庫取引（4パターン）','P5-8'],
      ['03','輸入取引','買継取引+前払（3パターン）','P9-12'],
      ['04','諸掛・倉庫','諸掛処理','P13'],
      ['05','諸掛・倉庫','倉庫移動','P14'],
      ['06','返品処理','返品処理（3パターン）','P15-16'],
      ['07','請求・回収','請求〜回収','P17'],
      ['08','支払・出金','支払〜出金（国内）','P18'],
      ['09','支払・出金','支払〜出金（海外）','P19'],
      ['10','会計連携','会計システム連携','P20']
    ])}
    ${note('各文書末尾に <strong>[!CAUTION]</strong> タグで有識者確認必須項目を記載しています。山田様・澤田様へのヒアリング完了後に更新予定です。', 'important', '⚡ IMPORTANT')}
  `
};

PAGES_DATA['dom-buy'] = {
  breadcrumb: '国内取引 ＞ 買継取引',
  html: `
    <h1 class="page-title">国内取引：買継取引フロー</h1>
    <p class="page-subtitle">得意先からの注文を受け、仕入先（国内・海外）から得意先へ商品を直送するフロー</p>
    ${meta('OP-DOM-BUY-001','アラジンオフィス / Shippio', 'P2〜P4')}
    
    ${sec(1, 'トリガーとインプット')}
    ${sub('業務開始トリガー')}
    ${tbl(['#','トリガー','発信元','受信先','頻度'], [
      ['T-1','得意先からの引合','得意先','営業','都度'],
      ['T-2','営業からの見積依頼','営業','営業事務','都度'],
      ['T-3','得意先からの注文書受領','得意先','営業','都度']
    ])}
    
    ${sec(2, '操作手順')}
    <div class="pattern-tabs">
      <button class="pattern-tab active" data-pattern="a">A：通常（直送）</button>
      <button class="pattern-tab" data-pattern="b">B：仕入先が輸入</button>
      <button class="pattern-tab" data-pattern="c">C：前払金あり</button>
    </div>
    
    ${sub('パターンA：通常（仕入先が国内・運送会社経由）')}
    ${tbl(['Step','担当','操作内容','システム','出力'], [
      ['1','営業','得意先からの引合を受け、メール又は口頭で回答','—','—'],
      ['2','営業','見積書をExcelで作成し、得意先へ提出','Excel','見積書'],
      ['3','営業事務','仕入先へメールで発注処理を実施','メール','—'],
      ['4','営業','得意先から注文書を受領','—','注文書'],
      ['5','営業','「受発注同時計上入力」を実行','<span class="tag tag-system">アラジン</span>','受注発注書'],
      ['6','営業事務','受注発注書を受領し「発注計上入力」を実行','<span class="tag tag-system">アラジン</span>','—'],
      ['7','営業事務','仕入先へ配送先を連絡','—','—'],
      ['8','営業事務','「売仕入同時計上入力」を実行','<span class="tag tag-system">アラジン</span>','荷渡指図書'],
      ['9','営業事務','荷渡指図書を仕入先へ送付','—','荷渡指図書'],
      ['10','仕入先','商品を出荷（運送会社経由）','—','—'],
      ['11','得意先','商品を受領','—','—']
    ])}
    
    ${sec(3, '例外処理と判断基準')}
    ${note('以下の例外処理はフロー図から読み取れた内容です。<strong>有識者へのヒアリングにて追加・修正が必要です。</strong>', 'warning', '⚠️ WARNING')}
    ${tbl(['#','例外事象','判断基準','対応手順','エスカレーション先'], [
      ['E-1','仕入先からの納期遅延','希望納期に間に合わない場合','①営業が得意先へ遅延連絡 ②代替品の提案','営業マネージャー'],
      ['E-2','船積遅延（パターンB）','ETAが当初予定より遅延','①入船予定表を更新 ②スケジュール表を再送','営業事務リーダー'],
      ['E-3','注文内容と見積の不一致','品名・数量・単価に差異','①営業が得意先へ確認 ②修正注文書の再取得','営業']
    ])}

    ${sec(4, 'ミス防止チェックリスト')}
    ${sub('受注時チェック')}
    ${cl([
      '注文書と見積書の内容（品名・数量・単価・納期）が一致しているか',
      'アラジンオフィスの得意先コード・商品コードが正しいか',
      '受発注同時計上入力が正常に完了したか'
    ])}
    ${sub('出荷・納品時チェック')}
    ${cl([
      '「売仕入同時計上入力」が正常に完了したか',
      '荷渡指図書が正しく発行・得意先へ送付されたか',
      '商品が正しい納品先へ配送されたか'
    ])}
    
    ${caution([
      'パターンBにおける入荷予定表の管理ルールの詳細',
      '「基本は都度都度依頼」の例外ケース',
      '動静確認の具体的な確認頻度・担当分担ルール'
    ])}
  `
};

// Route handling
function navigateTo(pageId) {
  if (!PAGES_DATA[pageId]) return;
  const page = PAGES_DATA[pageId];
  
  // Update UI
  document.querySelectorAll('.nav-item').forEach(item => {
    if (item.dataset.page === pageId) item.classList.add('active');
    else item.classList.remove('active');
  });
  
  breadcrumbPage.textContent = page.breadcrumb;
  contentArea.innerHTML = page.html;
  
  // Re-bind interactive elements
  bindInteractiveElements();
  
  // Close sidebar on mobile
  if (window.innerWidth <= 768) {
    sidebar.classList.remove('open');
  }
}

function bindInteractiveElements() {
  document.querySelectorAll('.check-box').forEach(box => {
    box.addEventListener('click', (e) => {
      e.target.classList.toggle('checked');
      e.target.closest('li').classList.toggle('checked-item');
    });
  });
  
  document.querySelectorAll('.pattern-tab').forEach(tab => {
    tab.addEventListener('click', (e) => {
      document.querySelectorAll('.pattern-tab').forEach(t => t.classList.remove('active'));
      e.target.classList.add('active');
    });
  });
}

// Navigation Listeners
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    navigateTo(item.dataset.page);
  });
});

// Search functionality
document.getElementById('searchInput').addEventListener('input', (e) => {
  const query = e.target.value.toLowerCase();
  document.querySelectorAll('.nav-item').forEach(item => {
    const text = item.textContent.toLowerCase();
    if (text.includes(query) || query === '') {
      item.style.display = 'flex';
      if(query !== '') {
        const section = item.closest('.nav-section');
        section.querySelector('.nav-section-title').classList.add('open');
        section.querySelector('.nav-section-items').classList.add('show');
      }
    } else {
      item.style.display = 'none';
    }
  });
});

// Init
navigateTo('home');
