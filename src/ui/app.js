// sopedu-dns UI. No framework, no inline script (CSP). The server renders every
// row and table as escaped HTML; this file only swaps it in, tails the log over
// Server-Sent Events and copies rule text (every page).
(() => {
  'use strict';
  const MAX_ROWS = 300;
  const $ = (id) => document.getElementById(id);

  // Server rows carry UTC text; show them in the viewer's time zone.
  const localize = (root) => {
    root.querySelectorAll('time[data-ms]').forEach((t) => {
      t.textContent = new Date(Number(t.dataset.ms)).toLocaleTimeString([], { hour12: false });
    });
  };

  // Clipboard needs a secure context (localhost or https); fall back to a
  // temporary textarea so port-forwarded and LAN http still work.
  const copy = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      const area = document.createElement('textarea');
      area.value = text;
      document.body.appendChild(area);
      area.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (_) { /* fall through */ }
      area.remove();
      return ok;
    }
  };

  document.addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-copy]');
    if (!button) return;
    const label = button.textContent;
    button.textContent = (await copy(button.dataset.copy)) ? 'Copied' : 'Copy failed';
    setTimeout(() => { button.textContent = label; }, 1200);
  });

  // Dashboard and clients: re-fetch the page every few seconds and swap <main>.
  const refreshing = () => {
    const main = $('main');
    const refresh = async () => {
      if (document.hidden) return;
      try {
        const response = await fetch(location.pathname, { cache: 'no-store' });
        if (!response.ok) return;
        const doc = new DOMParser().parseFromString(await response.text(), 'text/html');
        const next = doc.getElementById('main');
        if (next) main.replaceChildren(...next.childNodes);
      } catch (_) { /* server restarting; try again next tick */ }
    };
    setInterval(refresh, 5000);
    document.addEventListener('visibilitychange', refresh);
  };

  // Query log: live tail. Pause closes the stream, so a long pause costs the
  // server nothing; resume opens a new one (rows in between are not replayed,
  // use the filter form to reload the ring).
  const tail = () => {
    const rows = $('rows');
    const state = $('state');
    const pause = $('pause');
    const form = document.querySelector('.filters');
    let source = null;
    let paused = false;

    const url = () => '/api/log/stream?' + new URLSearchParams(new FormData(form)).toString();
    const trim = () => { while (rows.rows.length > MAX_ROWS) rows.deleteRow(-1); };

    const open = () => {
      source = new EventSource(url());
      source.onopen = () => { state.textContent = 'Live'; };
      source.onerror = () => { state.textContent = paused ? 'Paused' : 'Reconnecting'; };
      source.onmessage = (event) => {
        // The server sends one HTML-escaped <tr> per event (tested), and the
        // CSP blocks inline handlers and scripts even if that ever slipped.
        const before = rows.firstElementChild;
        rows.insertAdjacentHTML('afterbegin', event.data);
        const added = [];
        for (let row = rows.firstElementChild; row && row !== before; row = row.nextElementSibling) added.push(row);
        added.forEach(localize);
        trim();
      };
    };
    const close = () => { if (source) source.close(); source = null; };

    pause.addEventListener('click', () => {
      paused = !paused;
      pause.textContent = paused ? 'Resume' : 'Pause';
      pause.setAttribute('aria-pressed', String(paused));
      if (paused) { close(); state.textContent = 'Paused'; } else { state.textContent = 'Connecting'; open(); }
    });
    window.addEventListener('pagehide', close);
    localize(rows);
    open();
  };

  // The rules page has forms, so it never refreshes itself.
  const page = document.body.dataset.page;
  if (page === 'log') tail(); else if (page === 'dash' || page === 'clients') refreshing();
})();
