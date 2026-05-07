/*
File:    script.js
Version: 1.20.0
Description:
  Extracted static JavaScript for the sdproxy admin web UI.
  Compiled directly into the Go binary via //go:embed.

Changes:
  1.20.0 - [UI] Implemented "invert" checkbox handlers to support inverse (NOT) 
           grepping natively within the Query Log and Cache Inspector modals.
  1.19.3 - [UI] Implemented live filter/grep input capabilities for the Cache Inspector.
           Aligned column styling constraints with the layout updates.
  1.19.2 - [UI] Implemented a client-side sorting engine natively inside the Cache 
           Inspector modal. Clickable headers now alternate sort direction organically,
           respecting alphanumeric and TTL time-bound metrics automatically.
  1.19.1 - [UI] Appended `word-break` and `white-space` inline styles to the Cache 
           Inspector payload cells to guarantee strict column wrapping.
  1.19.0 - [UI] Supported the new Cache Inspector modal logic natively. 
           Incorporated formatting helpers and seamless cross-modal transitions 
           to query-logs and rules-editor.
*/

(function(){
// ── Section 0: Theme & Scroll Management ────────────────────────────────────

// Seamless scroll preservation across reloads triggered by Mode changes.
window.addEventListener('DOMContentLoaded', function() {
    var sp = sessionStorage.getItem('sdp_scroll');
    if(sp) { 
        window.scrollTo(0, parseInt(sp, 10)); 
        sessionStorage.removeItem('sdp_scroll'); 
    }
});

function reloadPage() {
    sessionStorage.setItem('sdp_scroll', window.scrollY);
    window.location.reload();
}

(function(){
  var btns = {
    light: document.getElementById('theme-light'),
    auto:  document.getElementById('theme-auto'),
    dark:  document.getElementById('theme-dark')
  };
  if(!btns.light) return;

  function setTheme(t){
    localStorage.setItem('sdp_theme', t);
    if(t==='auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);

    Object.keys(btns).forEach(function(k){
      if(btns[k]) btns[k].className = (k===t) ? 'active' : '';
    });
  }

  var cur = localStorage.getItem('sdp_theme') || 'auto';
  setTheme(cur);

  Object.keys(btns).forEach(function(k){
    if(btns[k]) btns[k].addEventListener('click', function(){ setTheme(k); });
  });
})();

// ── Section 1: radio instant-apply & temporary timers ─────────────────────
var bm={
  DEFAULT:{c:'st-ok',   l:'Default (normal)'},
  LOG:    {c:'st-log',  l:'Override: LOG \u2014 log-only bypass'},
  ALLOW:  {c:'st-allow',l:'Override: ALLOW \u2014 bypass all restrictions'},
  FREE:   {c:'st-free', l:'Override: FREE \u2014 suspend time/sched limits'},
  BLOCK:  {c:'st-block',l:'Override: BLOCK \u2014 internet cut'}
};
var toast=document.getElementById('sdp-toast'),toastT;
function show(msg,ok){
  clearTimeout(toastT);
  toast.textContent=msg;
  toast.className='toast '+(ok?'toast-ok':'toast-err')+' toast-show';
  toastT=setTimeout(function(){toast.className='toast';},2800);
}

// Sync duration selectors (desktop <-> mobile)
document.addEventListener('change', function(e){
  if(e.target.classList.contains('dur-sel')) {
    var g = e.target.dataset.group;
    var val = e.target.value;
    document.querySelectorAll('.dur-sel[data-group="'+g+'"]').forEach(function(s){
      s.value = val;
    });
  }
});

document.addEventListener('change',function(e){
  var el=e.target;
  if(el.type!=='radio')return;
  var g=el.name.replace(/^m_/,''),m=el.value,fd=new URLSearchParams();
  
  // Find associated duration from closest container
  var container = el.closest('tr') || el.closest('.card');
  var durEl = container ? container.querySelector('.dur-sel') : null;
  var dur = durEl ? durEl.value : "0";

  fd.append('group',g);
  fd.append('mode',m);
  fd.append('duration',dur);

  fetch('/api/set',{method:'POST',body:fd})
    .then(function(r){return r.json();})
    .then(function(d){
      if(d.ok){
        var msg = '\u2713 '+d.group+' \u2192 '+d.mode;
        if(d.duration > 0) msg += ' (' + d.duration + 'm)';
        show(msg,true);
        
        // Instant Reload syncs all Server-Side complex HTML logic
        setTimeout(reloadPage, 400); 
      }else{show('\u2717 '+(d.error||'failed'),false);}
    })
    .catch(function(){show('\u2717 Request failed',false);});
});

// Cancel timer click handler
document.addEventListener('click', function(e){
  var tb = e.target.closest('.timer-badge');
  if (tb && tb.id && tb.id.startsWith("timer_")) {
     e.preventDefault();
     e.stopPropagation();

     var g = tb.dataset.group;
     var fd = new URLSearchParams();
     fd.append('group', g);
     fd.append('mode', 'CANCEL_TIMER');
     fetch('/api/set', {method:'POST', body:fd})
      .then(function(r){return r.json();})
      .then(function(d){
         if(d.ok) {
           show('\u2713 Timer canceled for ' + d.group + '. Reverted to ' + d.mode, true);
           setTimeout(reloadPage, 400);
         }
     });
  }
}, true);

var activeTimers = {};
var expiredNotified = {}; 

setInterval(function(){
  var now = Math.floor(Date.now()/1000);
  
  Object.keys(activeTimers).forEach(function(g) {
      var t = activeTimers[g];
      if (t && t.expires_at > 0 && t.expires_at <= now) {
          if (!expiredNotified[g]) {
              expiredNotified[g] = true;
              var revertMode = t.revert_mode || 'DEFAULT';
              show('\u23F2\uFE0F Timer expired for ' + g + '. Reverted to ' + revertMode, true);
              setTimeout(reloadPage, 1500); 
          }
      }
  });

  document.querySelectorAll('.timer-badge').forEach(function(el) {
     if(el.id === "timer_m_") return;
     var g = el.dataset.group;
     var t = activeTimers[g];
     if (t && t.expires_at > 0 && t.expires_at > now) {
        var left = t.expires_at - now;
        var h = Math.floor(left / 3600);
        var m = Math.floor((left % 3600) / 60);
        var s = left % 60;
        var str = (h > 0 ? h + ':' : '') + (h > 0 && m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;
        
        var revertTo = t.revert_mode || 'DEFAULT';
        el.innerHTML = t.mode + ' (' + str + ' until ' + revertTo + ')';
        el.classList.remove('hidden');
     } else {
        el.classList.add('hidden');
     }
  });
}, 1000);


// ── Section 2: stats auto-refresh ─────────────────────────────────────────
(function(){
  var panel=document.getElementById('sdp-stats');
  if(!panel)return;
  var ms=(parseInt(panel.dataset.refresh,10)||30)*1000;
  var topN=parseInt(panel.dataset.topn,10)||10;
  var timerId;

  var fields={
    'st-uptime':'uptime', 'st-total':'total_queries',
    'st-hits':'cache_hits', 'st-hits-sub':'cache_hits_pct',
    'st-hitrate':'cache_hit_rate',
    'st-fwd':'forwarded', 'st-fwd-sub':'forwarded_pct',
    'st-blocked':'blocked', 'st-blocked-sub':'blocked_pct',
    'st-dropped':'dropped', 'st-dropped-sub':'dropped_pct',
    'st-dropped-up':'dropped_upstream', 'st-dropped-up-sub':'dropped_upstream_pct',
    'st-cache':null,'st-since':null,
    'st-qps-cur':null, 'st-qps-sub':null
  };

  var months=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  function formatSince(unix){
    if(!unix)return'';
    var d=new Date(unix*1000);
    var day=('0'+d.getDate()).slice(-2);
    var mon=months[d.getMonth()];
    var yr=d.getFullYear();
    var hh=('0'+d.getHours()).slice(-2);
    var mm=('0'+d.getMinutes()).slice(-2);
    var ss=('0'+d.getSeconds()).slice(-2);
    return day+'-'+mon+'-'+yr+'<br>'+hh+':'+mm+':'+ss;
  }

  function top10(id,rows){
    var el=document.getElementById(id);
    if(!el)return;
    var wrap=el.closest('.top10-tbl-wrap');
    if(wrap){
      if(topN>10){wrap.style.maxHeight='300px';wrap.style.overflowY='auto';}
      else{wrap.style.maxHeight='';wrap.style.overflowY='';}
    }
    if(!rows||!rows.length){
      el.innerHTML='<tr><td colspan="3"><span class="top10-none">No data yet\u2026</span></td></tr>';
      return;
    }
    el.innerHTML=rows.map(function(r,i){
      var rawName = String(r.name);
      var filterStr = rawName;
      if (id === 'top-domains' || id === 'top-blocked' || id === 'top-nxdomain') {
          filterStr = '-> ' + rawName + '.';
      } else if (id === 'top-tlds') {
          if (!filterStr.startsWith('.')) {
              filterStr = '.' + filterStr;
          }
          filterStr = filterStr + '.';
      } else if (id === 'top-groups') {
          filterStr = '(' + rawName + ')';
      } else if (id === 'top-upstreams') {
          filterStr = 'ROUTE: ' + rawName + ' (';
      } else if (id === 'top-upstream-hosts') {
          filterStr = 'UPSTREAM: ' + rawName;
      }
      
      var fTerm = filterStr.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g, '&quot;');
      var n = rawName.replace(/&/g,'&amp;').replace(/</g,'&lt;');
      var rawEsc = rawName.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g, '&quot;');
      
      if(id==='top-categories' && r.name==='unknown'){
        n='<span class="muted" style="font-style:italic">unknown</span>';
      }
      var hintHtml='';
      if(r.hint){
        var h=String(r.hint).replace(/&/g,'&amp;').replace(/</g,'&lt;');
        if(id==='top-talkers'){
          n=h+' ('+n+')';
        }else if(id==='top-blocked' || id==='top-tlds' || id==='top-block-reasons' || id==='top-filtered-ips'){
          hintHtml='<span class="reason-badge">'+h+'</span>';
        }
      }
      n='<a href="#" class="qlog-link" data-filter="'+fTerm+'" title="View in Query Log">'+n+'</a>';

      var addBtn = '';
      if (id === 'top-domains' || id === 'top-blocked' || id === 'top-nxdomain') {
          addBtn = '<button class="top10-add-rule" data-domain="' + rawEsc + '" title="Add to Custom Rules">+</button>';
      }

      return '<tr><td class="top10-rank">'+(i+1)+'</td><td class="top10-name">'+n+hintHtml+'</td><td class="top10-cnt">'+r.count+addBtn+'</td></tr>';
    }).join('');
  }

  function drawGraph(pts){
    var el=document.getElementById('hourly-chart');
    if(!el||!pts||!pts.length)return;
    var rawMax=0,i,p;
    for(i=0;i<pts.length;i++){p=pts[i];if((p.total||0)>rawMax)rawMax=p.total||0;}
    var max=10;
    if(rawMax>0){
      if(rawMax<=10) max=10;
      else{
        var pow=Math.pow(10,Math.floor(Math.log10(rawMax)));
        var frac=rawMax/pow;
        if(frac<=1.5) max=1.5*pow;
        else if(frac<=2) max=2*pow;
        else if(frac<=5) max=5*pow;
        else max=10*pow;
      }
    }
    var yEl=document.getElementById('hchart-y');
    if(yEl){
      function fmt(n){return n>=1e6?+(n/1e6).toFixed(1)+'M':n>=1e3?+(n/1e3).toFixed(1)+'k':n;}
      yEl.innerHTML='<span>0</span><span>'+fmt(Math.round(max/2))+'</span><span>'+fmt(max)+'</span>';
    }
    var html='';
    var skip = Math.max(1, Math.floor(pts.length / 8)); 
    for(i=0;i<pts.length;i++){
      p=pts[i];
      var tot=p.total||0,blk=p.blocked||0,fwd=p.fwd||0;
      if(blk>tot)blk=tot;
      if(fwd>tot-blk)fwd=tot-blk;
      var fwdPx=Math.round(fwd/max*100);
      var blkPx=Math.round(blk/max*100);
      var lbl=(i%skip===0||i===pts.length-1)?p.label:'';
      var tip=p.label+': '+tot+' total, '+blk+' blocked';
      html+='<div class="hbar-wrap" title="'+tip+'">'
        +'<div class="hbar">'
        +'<div class="hbar-fwd" style="height:'+fwdPx+'px"></div>'
        +'<div class="hbar-blk" style="height:'+blkPx+'px"></div>'
        +'</div>'
        +'<div class="hbar-lbl">'+lbl+'</div>'
        +'</div>';
    }
    el.innerHTML=html;
  }

  function refresh(){
    fetch('/api/stats')
      .then(function(r){return r.json();})
      .then(function(d){
        activeTimers = d.group_overrides || {};
        
        Object.keys(expiredNotified).forEach(function(g) {
            if (!activeTimers[g] || activeTimers[g].expires_at === 0) {
                delete expiredNotified[g];
            }
        });

        Object.keys(fields).forEach(function(id){
          var el=document.getElementById(id);
          if(!el)return;
          var key=fields[id];
          if(id==='st-cache'){
            el.textContent=d.cache_capacity>0
              ?(d.cache_entries+' / '+d.cache_capacity)
              :d.cache_entries;
          } else if(id==='st-since'){
            if(d.since_unix){el.innerHTML=formatSince(d.since_unix);}
          } else if(id==='st-qps-cur'){
            el.textContent = (d.qps_current || 0).toFixed(1);
          } else if(id==='st-qps-sub'){
            el.textContent = 'L: '+(d.qps_low || 0).toFixed(1)+' | A: '+(d.qps_average || 0).toFixed(1)+' | H: '+(d.qps_high || 0).toFixed(1);
          } else if(key){
            el.textContent=d[key];
          }
        });
        top10('top-domains',    d.top_domains);
        top10('top-blocked',    d.top_blocked);
        top10('top-nxdomain',   d.top_nxdomain);
        top10('top-talkers',    d.top_talkers);
        top10('top-filtered-ips', d.top_filtered_ips);
        top10('top-categories', d.top_categories);
        top10('top-tlds',       d.top_tlds);
        top10('top-vendors',    d.top_vendors);
        top10('top-groups',     d.top_groups);
        top10('top-block-reasons', d.top_block_reasons);
        top10('top-upstreams',  d.top_upstreams);
        top10('top-upstream-hosts', d.top_upstream_hosts);
        top10('top-return-codes', d.top_return_codes);
        if(panel.dataset.graphs==='true'){drawGraph(d.hourly_stats);}
      })
      .catch(function(){});
  }

  window.forceRefreshStats = refresh;
  refresh();
  timerId = setInterval(refresh, ms);

  var refMinus = document.getElementById('st-ref-minus'),
      refPlus  = document.getElementById('st-ref-plus'),
      refVal   = document.getElementById('st-ref-val'),
      refNow   = document.getElementById('st-ref-now');

  if(refVal && refMinus && refPlus) {
    function updateRef(val) {
      var n = parseInt(val, 10);
      if(isNaN(n)) n = 30;
      if(n < 5) n = 5;
      if(n > 300) n = 300;
      refVal.value = n;
      var newMs = n * 1000;
      if(newMs !== ms) {
        ms = newMs;
        clearInterval(timerId);
        timerId = setInterval(refresh, ms);
      }
    }
    refMinus.addEventListener('click', function() { updateRef(parseInt(refVal.value, 10) - 5); });
    refPlus.addEventListener('click',  function() { updateRef(parseInt(refVal.value, 10) + 5); });
    refVal.addEventListener('change',  function() { updateRef(this.value); });
    refVal.addEventListener('keydown', function(e) {
      if(e.key === 'Enter') { updateRef(this.value); this.blur(); }
    });
    if(refNow) {
      refNow.addEventListener('click', function() {
        refresh();
        clearInterval(timerId);
        timerId = setInterval(refresh, ms);
      });
    }
  }
})();

// ── Section 3: live query log modal ───────────────────────────────────────
(function(){
  var btn=document.getElementById('btn-qlog'),
      mod=document.getElementById('qlog-modal'),
      cls=document.getElementById('qlog-close'),
      lines=document.getElementById('qlog-lines'),
      filt=document.getElementById('qlog-filter'),
      invQlog=document.getElementById('qlog-invert'),
      clr=document.getElementById('qlog-clear'),
      tail=document.getElementById('qlog-tail'),
      zOut=document.getElementById('qlog-zoom-out'),
      zIn=document.getElementById('qlog-zoom-in'),
      zRes=document.getElementById('qlog-zoom-reset'),
      es=null,
      autoScroll=true,
      maxLines=500, 
      baseZoom=0.72,
      curZoom=0.72;
      
  if(!btn)return;

  var limitInput = document.getElementById('qlog-limit'),
      limitMinus = document.getElementById('qlog-limit-minus'),
      limitPlus  = document.getElementById('qlog-limit-plus');

  if(limitInput) {
      function applyLimit(val) {
          if (isNaN(val) || val < 10) val = 10;
          if (val > 5000) val = 5000;
          limitInput.value = val;
          if (val !== maxLines) {
              maxLines = val;
              if (mod.classList.contains('modal-show')) {
                  window.openQueryLog(filt.value);
              }
          }
      }
      limitInput.addEventListener('change', function() {
          applyLimit(parseInt(this.value, 10));
      });
      limitInput.addEventListener('keydown', function(e) {
          if (e.key === 'Enter') { this.blur(); }
      });
      if(limitMinus) limitMinus.addEventListener('click', function() {
          applyLimit(parseInt(limitInput.value, 10) - 50);
      });
      if(limitPlus) limitPlus.addEventListener('click', function() {
          applyLimit(parseInt(limitInput.value, 10) + 50);
      });
  }

  function updateLogRange() {
      var children = lines.children;
      var rangeEl = document.getElementById('qlog-time-range');
      if (!rangeEl) return;
      if (children.length === 0) {
          rangeEl.textContent = '';
          return;
      }
      var first = children[0].dataset.raw;
      var last = children[children.length - 1].dataset.raw;
      
      var start = first && first.length >= 19 ? first.substring(5, 19) : '';
      var end = last && last.length >= 19 ? last.substring(5, 19) : '';
      
      if (start && end) {
          rangeEl.textContent = '(' + start + ' \u2192 ' + end + ')';
      }
  }

  var modalContent = document.getElementById('qlog-modal-content');
  var modalHeader  = document.getElementById('qlog-modal-header');
  var isDragging = false, isResizing = false, curResizer = null;
  var startX, startY, startW, startH, startL, startT;
  var isMaximized = false;
  var preMaxState = { top: '', left: '', width: '', height: '' };

  if (modalHeader) {
    modalHeader.addEventListener('dblclick', function(e) {
      var tag = e.target.tagName.toLowerCase();
      if (tag === 'button' || tag === 'input' || tag === 'label' || e.target.closest('.zoom-controls') || e.target.closest('.filter-box') || e.target.closest('.log-meta') || e.target.closest('.filter-invert')) return;
      
      isMaximized = !isMaximized;
      if (isMaximized) {
        preMaxState.top = modalContent.style.top;
        preMaxState.left = modalContent.style.left;
        preMaxState.width = modalContent.style.width;
        preMaxState.height = modalContent.style.height;
        modalContent.classList.add('modal-maximized');
      } else {
        modalContent.classList.remove('modal-maximized');
        modalContent.style.top = preMaxState.top;
        modalContent.style.left = preMaxState.left;
        modalContent.style.width = preMaxState.width;
        modalContent.style.height = preMaxState.height;
      }
      if (autoScroll) lines.scrollTop = lines.scrollHeight;
    });

    modalHeader.addEventListener('mousedown', function(e) {
      if (isMaximized) return;
      var tag = e.target.tagName.toLowerCase();
      if (tag === 'button' || tag === 'input' || tag === 'label' || e.target.closest('.zoom-controls') || e.target.closest('.filter-box') || e.target.closest('.log-meta') || e.target.closest('.filter-invert')) return;
      isDragging = true;
      startX = e.clientX; startY = e.clientY;
      startL = modalContent.offsetLeft; startT = modalContent.offsetTop;
      document.body.style.userSelect = 'none';
    });
  }

  document.querySelectorAll('.resizer').forEach(function(res) {
    res.addEventListener('mousedown', function(e) {
      if (isMaximized) return;
      isResizing = true;
      curResizer = e.target;
      startX = e.clientX; startY = e.clientY;
      startW = modalContent.offsetWidth; startH = modalContent.offsetHeight;
      startL = modalContent.offsetLeft; startT = modalContent.offsetTop;
      document.body.style.userSelect = 'none';
      e.preventDefault();
    });
  });

  document.addEventListener('mousemove', function(e) {
    if (isDragging) {
      var dx = e.clientX - startX;
      var dy = e.clientY - startY;
      var newT = Math.max(0, startT + dy); 
      modalContent.style.left = (startL + dx) + 'px';
      modalContent.style.top  = newT + 'px';
    } else if (isResizing) {
      var dx = e.clientX - startX;
      var dy = e.clientY - startY;
      if (curResizer.classList.contains('e') || curResizer.classList.contains('ne') || curResizer.classList.contains('se')) {
        modalContent.style.width = Math.max(320, startW + dx) + 'px';
      }
      if (curResizer.classList.contains('s') || curResizer.classList.contains('sw') || curResizer.classList.contains('se')) {
        modalContent.style.height = Math.max(300, startH + dy) + 'px';
      }
      if (curResizer.classList.contains('w') || curResizer.classList.contains('nw') || curResizer.classList.contains('sw')) {
        if (startW - dx >= 320) {
          modalContent.style.left = (startL + dx) + 'px';
          modalContent.style.width = (startW - dx) + 'px';
        }
      }
      if (curResizer.classList.contains('n') || curResizer.classList.contains('nw') || curResizer.classList.contains('ne')) {
        if (startH - dy >= 300) {
          modalContent.style.top = (startT + dy) + 'px';
          modalContent.style.height = (startH - dy) + 'px';
        }
      }
    }
  });

  document.addEventListener('mouseup', function() {
    if (isDragging || isResizing) {
      isDragging = false;
      isResizing = false;
      curResizer = null;
      document.body.style.userSelect = '';
    }
  });

  function updateZoom(newZoom) {
      curZoom = Math.max(0.4, Math.min(2.0, newZoom)); 
      lines.style.fontSize = curZoom.toFixed(2) + 'em';
      if (autoScroll) {
          lines.scrollTop = lines.scrollHeight;
      }
  }

  zOut.addEventListener('click', function() { updateZoom(curZoom - 0.08); });
  zIn.addEventListener('click',  function() { updateZoom(curZoom + 0.08); });
  zRes.addEventListener('click', function() { updateZoom(baseZoom); });

  function escHtml(s){ 
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); 
  }

  function colorizeLog(txt) {
    txt = txt.replace(/(\([^)]+\))(?=\s+->)/g, '\x10$1\x11');
    txt = txt.replace(/(->\s+[^\s]+)/g, '\x12$1\x13');
    txt = txt.replace(/\|\s+(ROUTE:[^|]+?)(?=\s*\|)/g, '| \x14$1\x15');
    txt = txt.replace(/\|\s+(UPSTREAM:[^|]+?)(?=\s*\|)/g, '| \x16$1\x17');
    txt = txt.replace(/\b(CACHE HIT|NOERROR|NXDOMAIN|SERVFAIL|REFUSED|NOTIMP|COALESCED|LOCAL|NULL-IP)\b/g, '\x18$1\x19');
    txt = txt.replace(/\b(POLICY BLOCK|PARENTAL BLOCK(?:\s\([^)]+\))?|BLOCKED|Blocked: [^|]*[^|\s]|FAILED|CUSTOM RULE BLOCK|CUSTOM RULE DROP)(?=\b|\s*\||$)/g, '\x1A$1\x1B');
    txt = txt.replace(/\b(STALE|DDR DISCOVERY|PARENTAL FREE[^)]*|PARENTAL LOG[^)]*|PARENTAL ALLOW[^)]*|CUSTOM RULE ALLOW|Manual Override[^|]*)\b/g, '\x1C$1\x1D');
    return txt;
  }

  function renderLine(txt, f){
    txt = colorizeLog(txt);
    var chunks = [];
    if(f){
      var escaped = f.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      var rx = new RegExp('(' + escaped + ')', 'gi');
      var p = txt.split(rx);
      for(var i=0; i<p.length; i++){
        if(i%2===1) chunks.push('<mark>'+escHtml(p[i])+'</mark>');
        else chunks.push(escHtml(p[i]));
      }
    } else {
      chunks.push(escHtml(txt));
    }
    var html = chunks.join('');
    html = html.replace(/\x10/g, '<span class="log-client">').replace(/\x11/g, '</span>');
    html = html.replace(/\x12/g, '<span class="log-domain">').replace(/\x13/g, '</span>');
    html = html.replace(/\x14/g, '<span class="log-route">').replace(/\x15/g, '</span>');
    html = html.replace(/\x16/g, '<span class="log-upstream">').replace(/\x17/g, '</span>');
    html = html.replace(/\x18/g, '<span class="log-ok">').replace(/\x19/g, '</span>');
    html = html.replace(/\x1A/g, '<span class="log-err">').replace(/\x1B/g, '</span>');
    html = html.replace(/\x1C/g, '<span class="log-warn">').replace(/\x1D/g, '</span>');
    return html;
  }

  function closeLog(){
    mod.classList.remove('modal-show');
    if(es){es.close();es=null;}
  }

  function applyQlogFilter() {
    var f = filt.value.toLowerCase();
    var invert = invQlog ? invQlog.checked : false;

    if(f.length > 0) {
      clr.classList.remove('hidden');
    } else {
      clr.classList.add('hidden');
    }

    var ch = lines.children;
    for(var i=0; i<ch.length; i++){
      var raw = ch[i].dataset.raw;
      var hasMatch = raw.toLowerCase().indexOf(f) !== -1;
      var showLine = f ? (invert ? !hasMatch : hasMatch) : true;

      if(showLine) {
        ch[i].style.display = '';
        ch[i].innerHTML = renderLine(raw, invert ? '' : f);
      } else {
        ch[i].style.display = 'none';
        ch[i].innerHTML = renderLine(raw, '');
      }
    }
    if(autoScroll) lines.scrollTop = lines.scrollHeight;
  }

  window.openQueryLog = function(filterTerm) {
    mod.classList.add('modal-show');
    lines.innerHTML='';
    filt.value = filterTerm || '';
    
    if(filt.value.length > 0) clr.classList.remove('hidden');
    else clr.classList.add('hidden');
    
    autoScroll=true;
    tail.classList.add('hidden');
    if(es){es.close();es=null;}
    es=new EventSource('/api/logs?limit=' + maxLines);
    es.onmessage=function(ev){
      var d=document.createElement('div');
      d.className='log-line';
      d.dataset.raw = ev.data;
      var f=filt.value.toLowerCase();
      var invert = invQlog ? invQlog.checked : false;
      var hasMatch = ev.data.toLowerCase().indexOf(f) !== -1;
      var showLine = f ? (invert ? !hasMatch : hasMatch) : true;
      
      if(!showLine) {
        d.style.display = 'none';
        d.innerHTML = renderLine(ev.data, '');
      } else {
        d.style.display = '';
        d.innerHTML = renderLine(ev.data, invert ? '' : f);
      }
      
      lines.appendChild(d);
      
      while(lines.children.length > maxLines){
        lines.removeChild(lines.firstElementChild);
      }
      updateLogRange();
      if(autoScroll) lines.scrollTop=lines.scrollHeight;
    };
  };

  btn.addEventListener('click',function(e){
    e.preventDefault();
    window.openQueryLog('');
  });

  lines.addEventListener('scroll',function(){
    var atBot=(lines.scrollHeight-lines.clientHeight)<=lines.scrollTop+20;
    if(atBot){
      autoScroll=true;
      tail.classList.add('hidden');
    }else{
      autoScroll=false;
      tail.classList.remove('hidden');
    }
  });

  tail.addEventListener('click',function(){
    autoScroll=true;
    lines.scrollTop=lines.scrollHeight;
    tail.classList.add('hidden');
  });

  clr.addEventListener('click',function(){
    filt.value='';
    filt.dispatchEvent(new Event('input'));
    filt.focus();
  });

  cls.addEventListener('click',closeLog);
  mod.addEventListener('click',function(e){if(e.target===mod)closeLog();});
  
  filt.addEventListener('input', applyQlogFilter);
  if(invQlog) {
      invQlog.addEventListener('change', applyQlogFilter);
  }
})();

// ── Custom Rules Editor Modal ──────────────────────────────────────
(function(){
  var btnRules = document.getElementById('btn-custom-rules');
  var modRules = document.getElementById('rules-modal');
  if(!btnRules || !modRules) return;

  var clsRules = document.getElementById('rules-close');
  var cancelRules = document.getElementById('rules-cancel');
  var saveRules = document.getElementById('rules-save');
  var btnAdd = document.getElementById('btn-add-rule');
  var tbody = document.getElementById('rules-tbody');

  var currentGroups = [];
  var currentRules = [];

  function closeRules() {
    modRules.classList.remove('modal-show');
  }

  function escHtml(s){ 
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); 
  }

  function renderRules() {
    tbody.innerHTML = '';
    currentRules.forEach(function(r, i) {
      var tr = document.createElement('tr');
      
      var tdDom = document.createElement('td');
      var inpDom = document.createElement('input');
      inpDom.type = 'text';
      inpDom.value = r.domain;
      inpDom.className = 'rules-input';
      inpDom.placeholder = 'example.com';
      inpDom.onchange = function() { currentRules[i].domain = this.value; };
      tdDom.appendChild(inpDom);

      var tdGrp = document.createElement('td');
      var selGrp = document.createElement('select');
      selGrp.className = 'rules-select';
      currentGroups.forEach(function(g) {
        var opt = document.createElement('option');
        opt.value = g;
        opt.textContent = g;
        if(r.group === g) opt.selected = true;
        selGrp.appendChild(opt);
      });
      selGrp.onchange = function() { currentRules[i].group = this.value; };
      tdGrp.appendChild(selGrp);

      var tdAct = document.createElement('td');
      var selAct = document.createElement('select');
      selAct.className = 'rules-select';
      ['ALLOW', 'BLOCK'].forEach(function(a) {
        var opt = document.createElement('option');
        opt.value = a;
        opt.textContent = a;
        if(r.action === a) opt.selected = true;
        selAct.appendChild(opt);
      });
      selAct.onchange = function() { currentRules[i].action = this.value; };
      tdAct.appendChild(selAct);

      var tdEn = document.createElement('td');
      tdEn.style.textAlign = 'center';
      var chk = document.createElement('input');
      chk.type = 'checkbox';
      chk.checked = r.enabled;
      chk.onchange = function() { currentRules[i].enabled = this.checked; };
      tdEn.appendChild(chk);

      var tdActns = document.createElement('td');
      tdActns.className = 'rules-actions';

      var btnClone = document.createElement('button');
      btnClone.textContent = 'Copy';
      btnClone.className = 'rules-clone';
      btnClone.title = 'Clone Rule';
      btnClone.onclick = function() {
        var cloned = JSON.parse(JSON.stringify(currentRules[i]));
        currentRules.splice(i + 1, 0, cloned);
        renderRules();
      };

      var btnDel = document.createElement('button');
      btnDel.textContent = '✕';
      btnDel.className = 'rules-del';
      btnDel.title = 'Delete Rule';
      btnDel.onclick = function() {
        currentRules.splice(i, 1);
        renderRules();
      };

      tdActns.appendChild(btnClone);
      tdActns.appendChild(btnDel);

      tr.appendChild(tdDom);
      tr.appendChild(tdGrp);
      tr.appendChild(tdAct);
      tr.appendChild(tdEn);
      tr.appendChild(tdActns);

      tbody.appendChild(tr);
    });
  }

  function loadAndShowRules(domainToAdd) {
    fetch('/api/rules/get')
      .then(function(res) { return res.json(); })
      .then(function(data) {
        currentGroups = data.groups || ['global'];
        currentRules = data.rules || [];
        if (domainToAdd) {
          currentRules.push({ domain: domainToAdd, group: 'global', action: 'ALLOW', enabled: true });
        }
        renderRules();
        modRules.classList.add('modal-show');
        if (domainToAdd) {
          setTimeout(function() { var wrap = tbody.closest('.table-wrap'); if(wrap) wrap.scrollTop = wrap.scrollHeight; }, 10);
        }
      })
      .catch(function(err) { show('Failed to fetch rules', false); });
  }

  btnRules.addEventListener('click', function(e){
    e.preventDefault();
    loadAndShowRules();
  });

  window.addCustomRuleForDomain = function(domain) {
    if (!modRules.classList.contains('modal-show')) {
      loadAndShowRules(domain);
    } else {
      currentRules.push({ domain: domain, group: 'global', action: 'ALLOW', enabled: true });
      renderRules();
      setTimeout(function() { var wrap = tbody.closest('.table-wrap'); if(wrap) wrap.scrollTop = wrap.scrollHeight; }, 10);
    }
  };

  btnAdd.addEventListener('click', function() {
    currentRules.push({
      domain: '',
      group: 'global',
      action: 'ALLOW',
      enabled: true
    });
    renderRules();
    // Scroll to bottom
    var wrap = tbody.closest('.table-wrap');
    if(wrap) wrap.scrollTop = wrap.scrollHeight;
  });

  saveRules.addEventListener('click', function() {
    var valid = currentRules.filter(function(r) { return r.domain.trim() !== ''; });
    fetch('/api/rules/set', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(valid)
    })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if(data.ok) {
        show('Custom rules saved successfully', true);
        closeRules();
      } else {
        show('Failed to save rules', false);
      }
    })
    .catch(function() { show('Network error', false); });
  });

  clsRules.addEventListener('click', closeRules);
  cancelRules.addEventListener('click', closeRules);
  modRules.addEventListener('click', function(e){ if(e.target===modRules) closeRules(); });
})();

// ── Cache Inspector Modal ──────────────────────────────────────────
(function(){
  function escHtml(s){ 
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); 
  }

  var cachedData = [];
  var currentSortCol = '';
  var currentSortAsc = true;
  var cacheFilter = document.getElementById('cache-filter');
  var invCache = document.getElementById('cache-invert');
  var cacheClear = document.getElementById('cache-clear');

  function getFilteredCacheData() {
      if (!cacheFilter || !cacheFilter.value) return cachedData;
      var f = cacheFilter.value.toLowerCase();
      var invert = invCache ? invCache.checked : false;
      
      return cachedData.filter(function(e) {
          var match = (e.qname && e.qname.toLowerCase().indexOf(f) !== -1) ||
                 (e.qtype && e.qtype.toLowerCase().indexOf(f) !== -1) ||
                 (e.upstream_group && e.upstream_group.toLowerCase().indexOf(f) !== -1) ||
                 (e.response && e.response.toLowerCase().indexOf(f) !== -1);
          return invert ? !match : match;
      });
  }

  function renderCache(entries) {
      var tbody = document.getElementById('cache-tbody');
      if(!entries || !entries.length) {
          tbody.innerHTML = '<tr><td colspan="8" class="empty">Cache is empty or matches no filters</td></tr>';
          return;
      }
      var html = '';
      entries.forEach(function(e) {
          var fTerm = '-> ' + e.qname + '.';
          var qnameLink = '<a href="#" class="qlog-link" data-filter="'+escHtml(fTerm)+'" title="View in Query Log">'+escHtml(e.qname)+'</a>';
          var addBtn = '<button class="top10-add-rule" data-domain="'+escHtml(e.qname)+'" title="Add to Custom Rules">+</button>';
          
          var respFormatted = escHtml(e.response).replace(/\n/g, '<br>');

          html += '<tr>' +
              '<td style="word-break:break-all; text-align:left;">' + qnameLink + '</td>' +
              '<td style="text-align:center;">' + escHtml(e.qtype) + '</td>' +
              '<td style="text-align:center; word-break:break-word;">' + escHtml(e.upstream_group) + '</td>' +
              '<td style="font-family:monospace; font-size:0.9em; word-break:break-all; white-space:normal; text-align:left;">' + respFormatted + '</td>' +
              '<td style="text-align:center;">' + e.hits + '</td>' +
              '<td style="text-align:center; white-space:nowrap;">' + escHtml(e.timestamp) + '</td>' +
              '<td style="text-align:center; white-space:nowrap;">' + escHtml(e.time_left) + '</td>' +
              '<td style="text-align:center;">' + addBtn + '</td>' +
          '</tr>';
      });
      tbody.innerHTML = html;
  }

  function applySort() {
      var dataToProcess = getFilteredCacheData();

      if (!currentSortCol) {
          renderCache(dataToProcess);
          return;
      }

      document.querySelectorAll('#cache-modal .sortable-th').forEach(function(th) {
          th.classList.remove('sort-asc', 'sort-desc');
          if (th.dataset.sort === currentSortCol) {
              th.classList.add(currentSortAsc ? 'sort-asc' : 'sort-desc');
          }
      });

      var sorted = dataToProcess.slice();
      sorted.sort(function(a, b) {
          var valA, valB;
          switch(currentSortCol) {
              case 'qname': valA = a.qname.toLowerCase(); valB = b.qname.toLowerCase(); break;
              case 'qtype': valA = a.qtype; valB = b.qtype; break;
              case 'route': valA = a.upstream_group; valB = b.upstream_group; break;
              case 'response': valA = a.response; valB = b.response; break;
              case 'hits': valA = a.hits; valB = b.hits; break;
              case 'cachedat': valA = a.timestamp; valB = b.timestamp; break;
              case 'ttl': 
                  valA = parseInt(a.time_left.replace(/[^0-9-]/g, ''), 10) || 0;
                  if(a.time_left.indexOf("Expired") !== -1 && valA > 0) valA = -valA;
                  valB = parseInt(b.time_left.replace(/[^0-9-]/g, ''), 10) || 0;
                  if(b.time_left.indexOf("Expired") !== -1 && valB > 0) valB = -valB;
                  break;
              default: return 0;
          }
          if (valA < valB) return currentSortAsc ? -1 : 1;
          if (valA > valB) return currentSortAsc ? 1 : -1;
          return 0;
      });
      renderCache(sorted);
  }

  function sortCache(col) {
      if (currentSortCol === col) {
          currentSortAsc = !currentSortAsc;
      } else {
          currentSortCol = col;
          currentSortAsc = true;
      }
      applySort();
  }

  var btnCache = document.getElementById('btn-cache');
  var modCache = document.getElementById('cache-modal');
  var clsCache = document.getElementById('cache-close');
  var refCache = document.getElementById('btn-cache-refresh');

  function loadAndShowCache() {
      fetch('/api/cache/get')
          .then(function(r){ return r.json(); })
          .then(function(d){
              cachedData = d || [];
              applySort();
              modCache.classList.add('modal-show');
          })
          .catch(function(){ 
              var toast = document.getElementById('sdp-toast');
              if (toast) {
                  clearTimeout(window.toastT);
                  toast.textContent = 'Failed to fetch cache';
                  toast.className = 'toast toast-err toast-show';
                  window.toastT = setTimeout(function(){ toast.className='toast'; }, 2800);
              }
          });
  }

  if(btnCache && modCache) {
      btnCache.addEventListener('click', function(e){
          e.preventDefault();
          loadAndShowCache();
      });
      clsCache.addEventListener('click', function(){
          modCache.classList.remove('modal-show');
      });
      refCache.addEventListener('click', function(){
          loadAndShowCache();
      });
      modCache.addEventListener('click', function(e){
          if(e.target === modCache) modCache.classList.remove('modal-show');
      });

      // Add sorting click listener
      var cacheThead = document.querySelector('#cache-modal thead');
      if (cacheThead) {
          cacheThead.addEventListener('click', function(e) {
              var th = e.target.closest('.sortable-th');
              if (th) {
                  sortCache(th.dataset.sort);
              }
          });
      }
      
      if (cacheFilter && cacheClear) {
          cacheFilter.addEventListener('input', function() {
              if (this.value.length > 0) {
                  cacheClear.classList.remove('hidden');
              } else {
                  cacheClear.classList.add('hidden');
              }
              applySort();
          });
          cacheClear.addEventListener('click', function() {
              cacheFilter.value = '';
              cacheFilter.dispatchEvent(new Event('input'));
              cacheFilter.focus();
          });
      }
      
      if (invCache) {
          invCache.addEventListener('change', applySort);
      }
  }
})();

// Global Delegated Listener for qlog-link and add-rule clicks outside specific modules
document.addEventListener('click', function(e){
  var link = e.target.closest('.qlog-link');
  if(link) {
    e.preventDefault();
    var cMod = document.getElementById('cache-modal');
    if(cMod) cMod.classList.remove('modal-show'); 
    
    if(window.openQueryLog) {
      window.openQueryLog(link.getAttribute('data-filter'));
    }
    return;
  }
  var addRuleBtn = e.target.closest('.top10-add-rule');
  if(addRuleBtn) {
    e.preventDefault();
    var caMod = document.getElementById('cache-modal');
    if(caMod) caMod.classList.remove('modal-show'); 
    
    if(window.addCustomRuleForDomain) {
      window.addCustomRuleForDomain(addRuleBtn.getAttribute('data-domain'));
    }
  }
});

// ── Section 4: Reset Statistics ──────────────────────────────────────
(function(){
  var resetBtn = document.getElementById('st-reset-now');
  var resetModal = document.getElementById('reset-modal');
  var resetCancel = document.getElementById('reset-cancel');
  var resetConfirm = document.getElementById('reset-confirm');

  if(resetBtn && resetModal) {
    resetBtn.addEventListener('click', function() {
      resetModal.classList.add('modal-show');
    });
    resetCancel.addEventListener('click', function() {
      resetModal.classList.remove('modal-show');
    });
    resetConfirm.addEventListener('click', function() {
      resetConfirm.disabled = true;
      resetConfirm.style.opacity = '0.5';

      fetch('/api/reset', {method:'POST'})
        .then(function(r){ return r.json(); })
        .then(function(d){
          resetModal.classList.remove('modal-show');
          resetConfirm.disabled = false;
          resetConfirm.style.opacity = '1';
          if(d.ok) {
            if (typeof window.forceRefreshStats === 'function') {
                window.forceRefreshStats();
            }
          } else {
            console.error('Reset failed');
          }
        })
        .catch(function(){
            resetConfirm.disabled = false;
            resetConfirm.style.opacity = '1';
            console.error('Reset request failed');
        });
    });
    resetModal.addEventListener('click', function(e) {
      if(e.target === resetModal) resetModal.classList.remove('modal-show');
    });
  }
})();
})();

