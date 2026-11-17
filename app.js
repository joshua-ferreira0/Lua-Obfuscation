const PRESET_MAP = {
  low:        { dup: false, mask: true,  shuf: false, opq: false, mba: false, split: false, bit32: false, scrK: true, decH: false, anti: false, paranoid: false, id: 'luaobf' },
  medium:     { dup: true,  mask: true,  shuf: true,  opq: true,  mba: false, split: true,  bit32: true,  scrK: true, decH: true,  anti: true,  paranoid: false, id: 'luaobf' },
  high:       { dup: true,  mask: true,  shuf: true,  opq: true,  mba: true,  split: true,  bit32: true,  scrK: true, decH: true,  anti: true,  paranoid: false, id: 'luaobf' },
  extra_high: { dup: true,  mask: true,  shuf: true,  opq: true,  mba: true,  split: true,  bit32: true,  scrK: true, decH: true,  anti: true,  paranoid: true,  id: 'il1' }
};

let activePreset = 'high';

const inputArea = document.getElementById('lua-input');
const outputArea = document.getElementById('lua-output');
const inputStats = document.getElementById('input-stats');
const outMeta = document.getElementById('outMeta');
const inputCard = document.getElementById('input-card');
const outputCard = document.getElementById('output-card');
const outputDot = document.getElementById('output-dot');
const scanBeam = document.getElementById('scan-beam');
const errorBanner = document.getElementById('errorBanner');

const obfuscateBtn = document.getElementById('obfuscate-btn');
const obfuscateBtnText = document.getElementById('obfuscateBtnText');
const clearBtn = document.getElementById('clear-btn');
const copyBtn = document.getElementById('copy-btn');
const copyLabel = document.getElementById('copy-label');
const downloadBtn = document.getElementById('downloadBtn');
const toggleIsaBtn = document.getElementById('toggleIsaBtn');
const fileUpload = document.getElementById('fileUpload');

const isaDrawer = document.getElementById('isaDrawer');
const closeIsaBtn = document.getElementById('closeIsaBtn');
const toastEl = document.getElementById('toast');

let toastTimer = null;

function showToast(message) {
  toastEl.textContent = message;
  toastEl.classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toastEl.classList.remove('visible');
  }, 2300);
}

function updateInputMeta() {
  const bytes = new TextEncoder().encode(inputArea.value).length;
  inputStats.textContent = `${bytes.toLocaleString()} B`;
}

inputArea.addEventListener('input', updateInputMeta);

// Tab indentation + Ctrl/Cmd+Enter shortcut
inputArea.addEventListener('keydown', (e) => {
  if (e.key === 'Tab') {
    e.preventDefault();
    const start = inputArea.selectionStart;
    const end = inputArea.selectionEnd;
    inputArea.value =
      inputArea.value.substring(0, start) + '  ' + inputArea.value.substring(end);
    inputArea.selectionStart = inputArea.selectionEnd = start + 2;
    updateInputMeta();
  }

  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    runObfuscate();
  }
});

// Upload .lua / .luau File
fileUpload.addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  inputArea.value = await file.text();
  updateInputMeta();
  showToast(`Loaded ${file.name}`);
  e.target.value = '';
});

// Protection Presets (Low, Medium, High, Extra High)
document.querySelectorAll('.preset-pill').forEach((pill) => {
  pill.addEventListener('click', () => {
    document.querySelectorAll('.preset-pill').forEach((p) => p.classList.remove('active'));
    pill.classList.add('active');
    activePreset = pill.dataset.preset;
    const cfg = PRESET_MAP[activePreset];
    if (!cfg) return;

    document.getElementById('optDuplicateOps').checked = cfg.dup;
    document.getElementById('optMaskOperands').checked = cfg.mask;
    document.getElementById('optShuffleBlocks').checked = cfg.shuf;
    document.getElementById('optOpaque').checked = cfg.opq;
    document.getElementById('optMBA').checked = cfg.mba;
    document.getElementById('optSplitConstants').checked = cfg.split;
    document.getElementById('optVirtualizeBit32').checked = cfg.bit32;
    document.getElementById('optScrambleK').checked = cfg.scrK;
    document.getElementById('optDecoyHandlers').checked = cfg.decH;
    document.getElementById('optAntiTamper').checked = cfg.anti;
    document.getElementById('optIdStyle').value = cfg.id;
  });
});

// Clear Button
clearBtn.addEventListener('click', () => {
  if (!inputArea.value && !outputArea.value) return;
  inputArea.value = '';
  outputArea.value = '';
  errorBanner.classList.remove('visible');
  outputDot.classList.remove('is-ready');
  outMeta.textContent = 'Ready';
  updateInputMeta();
  inputArea.focus();
});

// Copy Button
copyBtn.addEventListener('click', async () => {
  if (!outputArea.value) {
    showToast('Nothing in Output to copy yet');
    return;
  }
  try {
    await navigator.clipboard.writeText(outputArea.value);
    copyLabel.textContent = 'Copied!';
    showToast('Copied obfuscated script to clipboard');
    setTimeout(() => {
      copyLabel.textContent = 'Copy';
    }, 1500);
  } catch {
    outputArea.select();
    document.execCommand('copy');
    showToast('Copied to clipboard');
  }
});

// Download Button
downloadBtn.addEventListener('click', () => {
  if (!outputArea.value) {
    showToast('Obfuscate a script before downloading');
    return;
  }
  const blob = new Blob([outputArea.value], { type: 'text/plain;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'luaobf_obfuscated.lua';
  a.click();
  URL.revokeObjectURL(a.href);
  showToast('Downloaded luaobf_obfuscated.lua');
});

// ISA Map Drawer
toggleIsaBtn.addEventListener('click', () => {
  isaDrawer.classList.toggle('visible');
  if (isaDrawer.classList.contains('visible')) {
    isaDrawer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
});

closeIsaBtn.addEventListener('click', () => {
  isaDrawer.classList.remove('visible');
});

function setStatValue(id, text) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.classList.remove('pop');
  void el.offsetWidth;
  el.classList.add('pop');
}

function gatherOptions() {
  return {
    preset: activePreset,
    paranoid: activePreset === 'extra_high',
    duplicateOps: document.getElementById('optDuplicateOps').checked,
    maskOperands: document.getElementById('optMaskOperands').checked,
    shuffleBlocks: document.getElementById('optShuffleBlocks').checked,
    opaquePredicates: document.getElementById('optOpaque').checked,
    bogusBlocks: document.getElementById('optOpaque').checked,
    mbaConstants: document.getElementById('optMBA').checked,
    splitConstants: document.getElementById('optSplitConstants').checked,
    virtualizeBit32: document.getElementById('optVirtualizeBit32').checked,
    scrambleConstants: document.getElementById('optScrambleK').checked,
    decoyHandlers: document.getElementById('optDecoyHandlers').checked,
    antiTamper: document.getElementById('optAntiTamper').checked,
    idStyle: document.getElementById('optIdStyle').value,
    payloadPrefix: 'joshua',
    watermark: false,
    seed: document.getElementById('optSeed').value.trim()
  };
}

async function runObfuscate() {
  const source = inputArea.value.trim();

  if (!source) {
    inputCard.classList.remove('shake');
    void inputCard.offsetWidth;
    inputCard.classList.add('shake');
    inputArea.focus();
    showToast('Paste a Lua script in Input first');
    return false;
  }

  errorBanner.classList.remove('visible');
  obfuscateBtn.classList.add('is-loading');
  obfuscateBtnText.textContent = 'Obfuscating...';

  scanBeam.classList.remove('active');
  void scanBeam.offsetWidth;
  scanBeam.classList.add('active');

  try {
    const res = await fetch('/api/obfuscate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: inputArea.value, options: gatherOptions() })
    });

    const data = await res.json();
    if (!data.ok) {
      errorBanner.textContent = data.error || 'Obfuscation failed.';
      errorBanner.classList.add('visible');
      return false;
    }

    outputArea.value = data.code;
    outputArea.scrollTop = 0;

    const s = data.stats;
    setStatValue('stTime', `${s.compileTimeMs} ms`);
    setStatValue('stSize', `${(s.outputBytes / 1024).toFixed(1)} KB`);
    setStatValue('stProtos', String(s.prototypesCompiled));
    setStatValue('stInsts', `${s.totalInstructions} (+${s.bogusInstructions})`);
    setStatValue('stOps', `${s.uniquePhysicalOpcodes} ops`);
    setStatValue('stSchema', s.sectionOrder.map((x) => x[0]).join(' → '));

    outMeta.textContent = `${s.outputBytes.toLocaleString()} B · seed ${s.seed.slice(0, 8)}`;
    outputDot.classList.add('is-ready');

    document.getElementById('isaSeedLabel').textContent = `Seed: ${s.seed.slice(0, 16)}…`;
    const tbody = document.getElementById('isaTableBody');
    tbody.innerHTML = data.isaPreview
      .map(
        (row) =>
          `<tr><td>${row.opCode}</td><td>${row.semOp}</td><td>[${row.perm}]</td><td>${row.masks.join(' / ')}</td></tr>`
      )
      .join('');

    outputCard.classList.remove('pulse-complete');
    void outputCard.offsetWidth;
    outputCard.classList.add('pulse-complete');
    showToast('Script virtualized & encrypted');
    return true;
  } catch (err) {
    errorBanner.textContent = err.message || 'Network error contacting obfuscator server.';
    errorBanner.classList.add('visible');
    return false;
  } finally {
    obfuscateBtn.classList.remove('is-loading');
    obfuscateBtnText.textContent = 'Obfuscate';
  }
}

obfuscateBtn.addEventListener('click', runObfuscate);
updateInputMeta();
