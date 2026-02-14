let isActive = false;
let language = 'en'; // Default to English

const toggleBtn = document.getElementById('toggleBtn');
const statusDiv = document.getElementById('status');
const infoDiv = document.getElementById('info');
const scanSummaryDiv = document.getElementById('scanSummary');
const threatListDiv = document.getElementById('threatList');
const langSelector = document.getElementById('langSelector');
const criticalLineDiv = document.getElementById('criticalLine');
const criticalLineText = document.getElementById('criticalLineText');

// Translations
const translations = {
  en: {
    protectionOn: 'Protection: ON ✓',
    protectionOff: 'Protection: OFF',
    activate: 'Activate Protection',
    deactivate: 'Deactivate Protection',
    scanning: 'Scanning webpage for phishing threats...',
    threatsDetected: 'Threats detected ⚠️',
    noThreats: 'No threats detected ✅',
    scanResult: 'Scan result:',
    riskScore: 'Risk Score:',
    noSuspicious: 'No suspicious message found in scanned blocks.',
    suspicious: 'Suspicious content found in page text',
    modelDetected: 'Model detected phishing risk. Avoid sharing OTP/CVV/KYC details.',
    riskLabel: 'Risk',
    criticalLine: '🚨 Critical Line:',
  },
  hi: {
    protectionOn: 'सुरक्षा: ON ✓',
    protectionOff: 'सुरक्षा: OFF',
    activate: 'सुरक्षा सक्रिय करें',
    deactivate: 'सुरक्षा बंद करें',
    scanning: 'वेबपेज को फिशिंग के लिए स्कैन कर रहे हैं...',
    threatsDetected: 'खतरे का पता चला ⚠️',
    noThreats: 'कोई खतरा नहीं ✅',
    scanResult: 'स्कैन परिणाम:',
    riskScore: 'जोखिम स्कोर:',
    noSuspicious: 'कोई संदिग्ध संदेश नहीं मिला।',
    suspicious: 'पाठ में संदिग्ध सामग्री मिली',
    modelDetected: 'फिशिंग जोखिम का पता चला। OTP/CVV/KYC शेयर न करें।',
    riskLabel: 'जोखिम',
    criticalLine: '🚨 महत्वपूर्ण लाइन:',
  },
};

function t(key) {
  return translations[language][key] || translations.en[key];
}

function renderResult(result) {
  const risk = result?.overall_risk ?? 0;
  const severity = (result?.severity || 'low').toUpperCase();
  const threats = result?.threats || [];
  const criticalLine = result?.critical_line || null;
  const threatDetected = threats.length > 0 || risk >= 45;

  scanSummaryDiv.style.display = 'block';
  scanSummaryDiv.innerHTML = `<strong>${t('scanResult')}</strong> ${threatDetected ? t('threatsDetected') : t('noThreats')}<br>
    ${t('riskScore')} <strong>${risk}</strong> (${severity})`;

  // Show critical line if available
  if (criticalLine) {
    criticalLineDiv.style.display = 'block';
    criticalLineText.textContent = criticalLine;
  } else {
    criticalLineDiv.style.display = 'none';
  }

  if (!threats.length) {
    if (risk >= 45) {
      threatListDiv.innerHTML = `<div class="threat-item red">
        <div class="threat-head">
          ${t('riskLabel')} ${risk}% · model_detected
          <span class="severity-badge severity-red">HIGH</span>
        </div>
        <div class="threat-phrase">${t('suspicious')}</div>
        <div class="threat-explain">${t('modelDetected')}</div>
      </div>`;
      return;
    }

    threatListDiv.innerHTML = `<div class="threat-item safe">${t('noSuspicious')}</div>`;
    return;
  }

  const topThreats = threats
    .slice()
    .sort((a, b) => (b.risk || 0) - (a.risk || 0))
    .slice(0, 6);

  threatListDiv.innerHTML = topThreats
    .map((threat) => {
      const color = threat.severity_color || 'orange';
      const severityDisplay = color === 'red' ? 'HIGH' : color === 'yellow' ? 'MEDIUM' : 'LOW';
      const severityClass = `severity-${color}`;

      return `
        <div class="threat-item ${color}">
          <div class="threat-head">
            ${t('riskLabel')} ${threat.risk || 0}% · ${threat.category || 'suspicious'}
            <span class="severity-badge ${severityClass}">${severityDisplay}</span>
          </div>
          <div class="threat-phrase">${threat.phrase || 'Suspicious message segment'}</div>
          <div class="threat-explain">${threat.explanation || 'Potential phishing pattern detected.'}</div>
        </div>`;
    })
    .join('');
}

// Language selector
langSelector.addEventListener('change', (e) => {
  language = e.target.value;
  chrome.storage.local.set({ language: language });
  updateUILanguage();
});

function updateUILanguage() {
  statusDiv.textContent = isActive ? t('protectionOn') : t('protectionOff');
  toggleBtn.textContent = isActive ? t('deactivate') : t('activate');
  infoDiv.textContent = t('scanning');

  if (criticalLineDiv.querySelector('.critical-line-label')) {
    criticalLineDiv.querySelector('.critical-line-label').textContent = t('criticalLine');
  }
}

toggleBtn.addEventListener('click', async () => {
  isActive = !isActive;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  chrome.tabs.sendMessage(tab.id, {
    action: isActive ? 'START_SCAN' : 'STOP_SCAN'
  });

  chrome.runtime.sendMessage({ action: 'SAVE_STATE', isActive });

  if (isActive) {
    statusDiv.textContent = t('protectionOn');
    statusDiv.className = 'status active';
    toggleBtn.textContent = t('deactivate');
    infoDiv.style.display = 'block';
  } else {
    statusDiv.textContent = t('protectionOff');
    statusDiv.className = 'status inactive';
    toggleBtn.textContent = t('activate');
    infoDiv.style.display = 'none';
    scanSummaryDiv.style.display = 'none';
    criticalLineDiv.style.display = 'none';
    threatListDiv.innerHTML = '';
  }
});

chrome.runtime.onMessage.addListener((message) => {
  if (message.action === 'SCAN_RESULT') {
    renderResult(message.data || {});
  }
});

chrome.storage.local.get(['isActive', 'lastScanResult', 'language'], (result) => {
  if (result.language) {
    language = result.language;
    langSelector.value = language;
  }

  if (result.isActive) {
    isActive = true;
    statusDiv.textContent = t('protectionOn');
    statusDiv.className = 'status active';
    toggleBtn.textContent = t('deactivate');
    infoDiv.style.display = 'block';
  }

  if (result.lastScanResult) {
    renderResult(result.lastScanResult);
  }
});
