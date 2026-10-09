/* Immune landing page — vanilla JS, no dependencies.
   1. copy-to-clipboard buttons   2. scroll reveal   3. simulated remediation loop (hero)   4. receipt tamper toggle */
(function () {
  'use strict';

  document.documentElement.classList.add('js');

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  /* ------------------------------------------------------------------ copy buttons */
  function legacyCopy(text) {
    return new Promise(function (resolve, reject) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.top = '0';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try {
        if (document.execCommand('copy')) resolve(); else reject(new Error('copy failed'));
      } catch (e) {
        reject(e);
      } finally {
        ta.remove();
      }
    });
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      // The async API rejects when the document is not focused; fall back to the legacy command.
      return navigator.clipboard.writeText(text).catch(function () { return legacyCopy(text); });
    }
    return legacyCopy(text);
  }

  $$('[data-copy]').forEach(function (btn) {
    var label = btn.querySelector('.btn-text') || btn;
    var original = btn.getAttribute('data-label') || label.textContent;
    var timer = 0;
    btn.addEventListener('click', function () {
      copyText(btn.getAttribute('data-copy')).then(function () {
        label.textContent = 'Copied to clipboard';
        btn.classList.add('copied');
      }, function () {
        label.textContent = 'Copy failed';
      }).then(function () {
        clearTimeout(timer);
        timer = setTimeout(function () {
          label.textContent = original;
          btn.classList.remove('copied');
        }, 2000);
      });
    });
  });

  /* ------------------------------------------------------------------ scroll reveal */
  var revealEls = $$('.reveal');
  if (!reduceMotion.matches && 'IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('in');
          io.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -6% 0px', threshold: 0.05 });
    revealEls.forEach(function (el) { io.observe(el); });
  } else {
    revealEls.forEach(function (el) { el.classList.add('in'); });
  }

  /* ------------------------------------------------------------------ remediation theatre (simulated) */
  var theatre = $('#theatre');
  if (theatre) {
    var STEPS = ['trace_captured', 'antibody_drafted', 'replay_proven', 'semgrep_rescan', 'receipt_signed', 'ruling_published', 'immunity_verified'];

    // Real-time step durations in ms, [min, max]. The whole loop lands around 6–9 s so it reads as "seconds, not days".
    var DUR = {
      trace_captured: [220, 420],
      antibody_drafted: [650, 1100],
      replay_proven: [1100, 1900],
      semgrep_rescan: [1500, 2600],
      receipt_signed: [90, 260],
      ruling_published: [450, 950],
      immunity_verified: [700, 1300]
    };

    var RUNNING = {
      trace_captured: 'writing the antigen to ClickHouse…',
      antibody_drafted: 'deriving distinguishing tokens, destination and capability signature…',
      replay_proven: 'replaying the whole corpus (attacks + benign) in ClickHouse…',
      semgrep_rescan: 'semgrep --config antibody.yaml integrations/semgrep/targets…',
      receipt_signed: 'canonicalizing proof · HMAC-SHA256…',
      ruling_published: 'publishing the precedent to the verified-context layer…',
      immunity_verified: 'replaying the identical attack against a fresh session…'
    };

    // All hosts are under .example (reserved, never resolve). Numbers are illustrative.
    var SCENARIOS = [
      { family: 'result_injection', variant: 'mutated-3a', path: 'acme/read_shared_doc → send_webhook https://evil-cdn.example/collect',
        rule: '3 patterns · host evil-cdn.example · network after tainted', semgrep: '1 finding · tool-result → fetch() · acme_server.ts:88', rows: 12400, before: 94.2, after: 99.1 },
      { family: 'secret_exfil', variant: 'mutated-5c', path: 'acme/get_api_credentials → fetch_url https://telemetry.evil-cdn.example/k',
        rule: 'secret-shaped arg · destination not in allowlist', semgrep: '1 finding · credential echoed into outbound body · acme_server.ts:142', rows: 12401, before: 95.0, after: 99.4 },
      { family: 'poisoned_description', variant: 'mutated-7c', path: 'acme/lookup_customer (description) → get_api_credentials',
        rule: 'hidden-block marker · cross-tool directive · secret capability', semgrep: 'skipped · no server-side sink for a description payload', skipSemgrep: true, rows: 12402, before: 96.1, after: 99.6 },
      { family: 'rug_pull', variant: 'v2', path: 'acme/run_report redefined after pin · sha256 a41c…9e02 ≠ 0f9e…b7d1',
        rule: 'pinned-hash mismatch · exec capability', semgrep: '1 finding · tool-result → child_process.exec · acme_server.ts:201', rows: 12403, before: 96.9, after: 99.7 },
      { family: 'homoglyph_spoof', variant: 'v1', path: 'acme/lookup_customеr (U+0435) shadows lookup_customer',
        rule: 'confusable skeleton · zero-width chars · shadowed name', semgrep: 'skipped · no server-side sink for a name collision', skipSemgrep: true, rows: 12404, before: 97.3, after: 99.8 },
      { family: 'indirect_fetch', variant: 'mutated-2b', path: 'acme/fetch_url (page content) → run_report "curl … | sh"',
        rule: '2 patterns · exec after tainted result', semgrep: '1 finding · tool-result → child_process.exec · acme_server.ts:201', rows: 12405, before: 97.8, after: 99.9 }
    ];

    var els = {
      family: $('#breach-family'),
      path: $('#breach-path'),
      num: $('#tti-num'),
      state: $('#tti-state'),
      steps: {}
    };
    $$('.step', theatre).forEach(function (li) {
      els.steps[li.getAttribute('data-step')] = { li: li, ms: li.querySelector('.ms'), detail: li.querySelector('.detail') };
    });

    var rand = function (a, b) { return a + Math.random() * (b - a); };
    var hex = function (n) { var s = ''; for (var i = 0; i < n; i++) s += (Math.random() * 16 | 0).toString(16); return s; };
    var fmtMs = function (ms) { return ms < 1000 ? Math.round(ms) + ' ms' : (ms / 1000).toFixed(1) + ' s'; };
    var fmtInt = function (n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ','); };

    function build(sc) {
      var ids = { tr: 'tr_' + hex(6), rl: 'rl_' + hex(6), rc: 'rc_' + hex(6), ru: 'ru_' + hex(6) };
      var t = 0;
      var steps = STEPS.map(function (name) {
        var range = DUR[name];
        var skipped = false;
        if (name === 'semgrep_rescan' && sc.skipSemgrep) { range = [120, 240]; skipped = true; }
        var dur = rand(range[0], range[1]);
        var s = { name: name, start: t, end: t + dur, dur: dur, skipped: skipped };
        t += dur;
        return s;
      });
      var detail = {
        trace_captured: ids.tr + '… · ' + sc.family + ' · ' + sc.variant + ' · decision allow → breach',
        antibody_drafted: ids.rl + '… · ' + sc.rule,
        replay_proven: fmtInt(sc.rows) + ' traces · catch ' + sc.before.toFixed(1) + '% → ' + sc.after.toFixed(1) + '% · fp 0 → 0 · promoted',
        semgrep_rescan: sc.semgrep,
        receipt_signed: ids.rc + '… · HMAC-SHA256 over sha256(canonicalJson({ ruleId, proof }))',
        ruling_published: ids.ru + '… → senso · evidence ' + ids.tr + '…',
        immunity_verified: 'identical attack · fresh session · blocked · cites ' + ids.ru + '…'
      };
      return { sc: sc, steps: steps, detail: detail, total: t, hold: 3600 };
    }

    function applyScenario(run) {
      els.family.textContent = run.sc.family + ' · ' + run.sc.variant;
      els.path.textContent = run.sc.path;
    }

    function render(run, v) {
      run.steps.forEach(function (s) {
        var el = els.steps[s.name];
        if (!el) return;
        var state = v >= s.end ? (s.skipped ? 'skipped' : 'done') : v >= s.start ? 'running' : 'pending';
        if (el.li.getAttribute('data-state') !== state) {
          el.li.setAttribute('data-state', state);
          el.detail.textContent = state === 'pending' ? '' : state === 'running' ? RUNNING[s.name] : run.detail[s.name];
          el.ms.textContent = state === 'pending' ? '' : fmtMs(state === 'running' ? v - s.start : s.dur);
        } else if (state === 'running') {
          el.ms.textContent = fmtMs(v - s.start);
        }
      });
      var done = v >= run.total;
      els.num.textContent = (Math.min(v, run.total) / 1000).toFixed(2);
      if (els.state.textContent !== (done ? 'Immune' : 'Remediating')) {
        els.state.textContent = done ? 'Immune' : 'Remediating';
        els.state.className = 'badge ' + (done ? 'badge-immune' : 'badge-neutral');
      }
    }

    var idx = 0;
    var run = build(SCENARIOS[idx]);
    applyScenario(run);

    if (reduceMotion.matches) {
      // Static end state: the loop completed, no ticking, no cycling.
      render(run, run.total);
    } else {
      var v = 0;            // virtual clock (ms) — only advances while visible
      var last = null;
      var rafId = 0;
      var paused = false;
      var swapping = false;
      var inView = true;

      var frame = function (now) {
        if (paused) { rafId = 0; last = null; return; }
        if (last === null) last = now;
        var dt = Math.min(now - last, 100); // clamp so a throttled tab never jumps
        last = now;
        if (!swapping) {
          v += dt;
          render(run, v);
          if (v >= run.total + run.hold) nextScenario();
        }
        rafId = requestAnimationFrame(frame);
      };
      var start = function () { if (!rafId) { last = null; rafId = requestAnimationFrame(frame); } };
      var setPaused = function () {
        var shouldPause = document.hidden || !inView;
        if (shouldPause === paused) return;
        paused = shouldPause;
        if (!paused) start();
      };

      var nextScenario = function () {
        swapping = true;
        theatre.classList.add('swap');
        setTimeout(function () {
          idx = (idx + 1) % SCENARIOS.length;
          run = build(SCENARIOS[idx]);
          v = 0;
          applyScenario(run);
          render(run, 0);
          theatre.classList.remove('swap');
          swapping = false;
        }, 450);
      };

      render(run, 0);
      if ('IntersectionObserver' in window) {
        new IntersectionObserver(function (entries) {
          inView = entries.some(function (e) { return e.isIntersecting; });
          setPaused();
        }, { threshold: 0.05 }).observe(theatre);
      }
      document.addEventListener('visibilitychange', setPaused);
      start();
    }
  }

  /* ------------------------------------------------------------------ receipt tamper toggle */
  var tamperBtn = $('#tamper');
  if (tamperBtn) {
    var field = $('#tamper-field');
    var verdict = $('#verify-verdict');
    var out = $('#verify-out code');
    var okHtml = out.innerHTML;
    var badHtml =
      '<span class="prompt">$</span> immune verify receipt.json\n' +
      '<span class="bad">✖</span> payloadHash  = sha256(canonicalJson({ ruleId, proof }))   <span class="bad">mismatch</span>\n' +
      '<span class="bad">✖</span> signature    = HMAC-SHA256(secret, payloadHash)           <span class="bad">mismatch</span>\n' +
      '<span class="bad">✖</span> rc_7f3a9c21be04 rejected · proof modified after signing · rl_2d8e41c0a7f3 stays candidate · “done” refused';
    var tampered = false;
    tamperBtn.addEventListener('click', function () {
      tampered = !tampered;
      field.textContent = tampered ? '0.9999' : '0.9913';
      field.classList.toggle('tampered', tampered);
      verdict.setAttribute('data-state', tampered ? 'fail' : 'ok');
      verdict.textContent = tampered ? 'Rejected · signature mismatch' : 'Verified · signature matches';
      out.innerHTML = tampered ? badHtml : okHtml;
      tamperBtn.textContent = tampered ? 'Restore the field' : 'Tamper with one field';
    });
  }
})();
