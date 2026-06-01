(function() {
  const PASS_HASH = '1639943cb52312351a24a8ab510d14032f3b1b314c5b138a475d13efa868fe76';
  const SESSION_KEY = 'cascadia_auth_token';
  const SESSION_EXPIRY_DAYS = 30;

  // Pure JS SHA-256 Fallback (for non-secure contexts like file://)
  function sha256_fallback(s) {
    const chrsz = 8;
    const hexcase = 0;
    function safe_add(x, y) {
      const lsw = (x & 0xFFFF) + (y & 0xFFFF);
      const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
      return (msw << 16) | (lsw & 0xFFFF);
    }
    function S(X, n) { return (X >>> n) | (X << (32 - n)); }
    function R(X, n) { return (X >>> n); }
    function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }
    function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
    function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
    function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
    function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
    function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }
    function core_sha256(m, l) {
      const K = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2];
      const HASH = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
      const W = Array(64);
      let a, b, c, d, e, f, g, h, i, j, T1, T2;
      m[l >> 5] |= 0x80 << (24 - l % 32);
      m[((l + 64 >> 9) << 4) + 15] = l;
      for (i = 0; i < m.length; i += 16) {
        a = HASH[0]; b = HASH[1]; c = HASH[2]; d = HASH[3]; e = HASH[4]; f = HASH[5]; g = HASH[6]; h = HASH[7];
        for (j = 0; j < 64; j++) {
          if (j < 16) W[j] = m[j + i];
          else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
          T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
          T2 = safe_add(Sigma0256(a), Maj(a, b, c));
          h = g; g = f; f = e; e = safe_add(d, T1); d = c; c = b; b = a; a = safe_add(T1, T2);
        }
        HASH[0] = safe_add(a, HASH[0]); HASH[1] = safe_add(b, HASH[1]); HASH[2] = safe_add(c, HASH[2]); HASH[3] = safe_add(d, HASH[3]); HASH[4] = safe_add(e, HASH[4]); HASH[5] = safe_add(f, HASH[5]); HASH[6] = safe_add(g, HASH[6]); HASH[7] = safe_add(h, HASH[7]);
      }
      return HASH;
    }
    function str2binb(str) {
      const bin = Array();
      const mask = (1 << chrsz) - 1;
      for (let i = 0; i < str.length * chrsz; i += chrsz) bin[i >> 5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i % 32);
      return bin;
    }
    function binb2hex(binarray) {
      const hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
      let str = "";
      for (let i = 0; i < binarray.length * 4; i++) str += hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8 + 4)) & 0xF) + hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8)) & 0xF);
      return str;
    }
    return binb2hex(core_sha256(str2binb(s), s.length * chrsz));
  }

  async function getHash(message) {
    try {
      if (window.isSecureContext && crypto.subtle) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      }
    } catch(e) {}
    return sha256_fallback(message);
  }

  function checkSession() {
    const session = localStorage.getItem(SESSION_KEY);
    if (!session) return false;
    try {
      const data = JSON.parse(session);
      if (data.hash === PASS_HASH && new Date().getTime() < data.expiry) {
        return true;
      }
    } catch (e) {}
    localStorage.removeItem(SESSION_KEY);
    return false;
  }

  function showLogin() {
    // Ensure body exists
    if (!document.body) {
      window.addEventListener('DOMContentLoaded', showLogin);
      return;
    }

    const overlay = document.createElement('div');
    overlay.id = 'auth-overlay';
    overlay.innerHTML = `
      <div class="auth-card">
        <div class="auth-logo">🐄</div>
        <h1>Cascadia Trading</h1>
        <p>営業マニュアル 認証</p>
        <form id="auth-form">
          <input type="password" id="auth-pass" placeholder="パスワードを入力" required autofocus autocomplete="current-password">
          <label class="auth-remember">
            <input type="checkbox" id="auth-remember" checked> ログイン状態を保持する
          </label>
          <button type="submit">ログイン</button>
          <div id="auth-error" class="hidden">パスワードが正しくありません</div>
        </form>
      </div>
      <style>
        #auth-overlay {
          position: fixed; top: 0; left: 0; width: 100%; height: 100%;
          background: #0f1117; display: flex; align-items: center; justify-content: center;
          z-index: 2147483647; font-family: 'Inter', 'Noto Sans JP', sans-serif; color: #e8eaed;
          visibility: visible !important; opacity: 1 !important;
        }
        .auth-card {
          background: #1e2132; padding: 40px; border-radius: 24px; width: 100%; max-width: 360px;
          text-align: center; box-shadow: 0 20px 50px rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.08);
          animation: authFadeIn 0.4s ease-out;
        }
        @keyframes authFadeIn { 
          from { opacity: 0; transform: translateY(20px); } 
          to { opacity: 1; transform: translateY(0); } 
        }
        .auth-logo { font-size: 56px; margin-bottom: 20px; filter: drop-shadow(0 0 10px rgba(52, 211, 153, 0.3)); }
        .auth-card h1 { font-size: 26px; font-weight: 800; margin: 0 0 8px; color: #34d399; letter-spacing: -0.5px; }
        .auth-card p { color: #9ca3af; font-size: 14px; margin-bottom: 30px; font-weight: 500; }
        #auth-pass {
          width: 100%; padding: 16px; border-radius: 12px; border: 2px solid #374151;
          background: #0f1117; color: white; font-size: 16px; margin-bottom: 16px; box-sizing: border-box;
          outline: none; transition: all 0.2s;
        }
        #auth-pass:focus { border-color: #34d399; background: #111827; box-shadow: 0 0 15px rgba(52, 211, 153, 0.2); }
        .auth-remember {
          display: flex; align-items: center; justify-content: center; cursor: pointer;
          font-size: 13px; color: #9ca3af; margin-bottom: 24px; gap: 10px; user-select: none;
        }
        .auth-remember input { width: 16px; height: 16px; accent-color: #34d399; cursor: pointer; }
        .auth-card button {
          width: 100%; padding: 16px; border-radius: 12px; border: none;
          background: linear-gradient(135deg, #34d399, #10b981); color: #0f1117; font-weight: 800; font-size: 16px;
          cursor: pointer; transition: all 0.3s; box-shadow: 0 4px 12px rgba(52, 211, 153, 0.3);
        }
        .auth-card button:hover { opacity: 0.95; transform: translateY(-1px); box-shadow: 0 6px 16px rgba(52, 211, 153, 0.4); }
        .auth-card button:active { transform: translateY(1px); }
        #auth-error { color: #fb7185; font-size: 13px; margin-top: 16px; font-weight: 600; }
        .hidden { display: none; }
      </style>
    `;
    document.body.appendChild(overlay);

    document.getElementById('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = e.target.querySelector('button');
      btn.textContent = '認証中...';
      btn.disabled = true;

      const pass = document.getElementById('auth-pass').value;
      const remember = document.getElementById('auth-remember').checked;
      const hash = await getHash(pass);
      
      if (hash === PASS_HASH) {
        if (remember) {
          const expiry = new Date().getTime() + (SESSION_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
          localStorage.setItem(SESSION_KEY, JSON.stringify({ hash, expiry }));
        }
        unlock();
      } else {
        document.getElementById('auth-error').classList.remove('hidden');
        document.getElementById('auth-pass').value = '';
        btn.textContent = 'ログイン';
        btn.disabled = false;
        const card = document.querySelector('.auth-card');
        card.style.animation = 'none';
        card.offsetHeight;
        card.style.animation = 'authShake 0.4s';
      }
    });

    const style = document.createElement('style');
    style.innerHTML = `
      @keyframes authShake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-10px); }
        50% { transform: translateX(10px); }
        75% { transform: translateX(-10px); }
      }
    `;
    document.head.appendChild(style);
  }

  function unlock() {
    const guard = document.getElementById('auth-guard');
    if (guard) guard.remove();
    const overlay = document.getElementById('auth-overlay');
    if (overlay) overlay.remove();
    // Final safety - ensure html/body are visible
    document.documentElement.style.visibility = 'visible';
    document.body.style.visibility = 'visible';
  }

  // Startup
  if (checkSession()) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', unlock);
    } else {
      unlock();
    }
  } else {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', showLogin);
    } else {
      showLogin();
    }
  }
})();
