"""Shadow313 v2 — standalone test runner (no pytest needed)."""
import sys, tempfile, traceback
sys.path.insert(0, '.')

passed = []
failed = []

def t(name, fn):
    try:
        fn()
        passed.append(name)
        print(f'  ✓ {name}')
    except Exception as e:
        failed.append((name, str(e)[:80]))
        print(f'  ✗ {name}: {e}')

# ── imports ───────────────────────────────────────────────────────────────────
from shadow313.modules.vuln.cvss import CVSSScorer
from shadow313.v2.vuln_upgrades.epss_kev import epss_label
from shadow313.v2.threat_intel.threat_intel import _detect_ioc_type
from shadow313.modules.quantum.quantum_data import classify_algorithm, QUANTUM_VULN_TABLE
from shadow313.v2.rag.tfidf_store import TFIDFVectorStore, _tokenize
from shadow313.v2.agent.agent import BUILTIN_PLANS
from shadow313.v2.network_upgrades.dns_covert import _shannon_entropy
from shadow313.core.intelligence_graph import IntelGraph
from shadow313.core.session import Session
from shadow313.core.ai_engine import AIEngine
from shadow313.core.crypto_store import SLHDSASigner

print('=== SHADOW313 MODULE TESTS ===')
print()

# ── CVSSScorer ────────────────────────────────────────────────────────────────
print('CVSSScorer:')
t('KEV promotes to 10.0', lambda: None if CVSSScorer.contextual_score(9.8,True,True,True)==10.0 else (_ for _ in ()).throw(AssertionError('expected 10.0')))
t('EPSS boost works', lambda: None if CVSSScorer.contextual_score(7.5,True,True,False)>7.5 else (_ for _ in ()).throw(AssertionError()))
t('No boost without exploit', lambda: None if CVSSScorer.contextual_score(5.0,False,False,False)==5.0 else (_ for _ in ()).throw(AssertionError()))

# ── EPSS labels ───────────────────────────────────────────────────────────────
print('EPSS labels:')
t('0.99 = CRITICAL', lambda: None if epss_label(0.99)=='CRITICAL' else (_ for _ in ()).throw(AssertionError(epss_label(0.99))))
t('0.45 = HIGH', lambda: None if epss_label(0.45)=='HIGH' else (_ for _ in ()).throw(AssertionError(epss_label(0.45))))
t('0.12 = MEDIUM', lambda: None if epss_label(0.12)=='MEDIUM' else (_ for _ in ()).throw(AssertionError(epss_label(0.12))))
t('0.005 = VERY_LOW', lambda: None if epss_label(0.005)=='VERY_LOW' else (_ for _ in ()).throw(AssertionError(epss_label(0.005))))
t('0.001 = VERY_LOW', lambda: None if epss_label(0.001)=='VERY_LOW' else (_ for _ in ()).throw(AssertionError(epss_label(0.001))))

# ── Quantum classify ──────────────────────────────────────────────────────────
print('Quantum classify_algorithm:')
cases = [
    ('SLH-DSA','SAFE'), ('SLH-DSA-SHAKE-128s','SAFE'),
    ('ML-DSA-65','SAFE'), ('ML-KEM-768','SAFE'),
    ('RSA-2048','VULNERABLE'), ('ECDSA','VULNERABLE'),
    ('DSA','VULNERABLE'), ('AES-256','SAFE'),
    ('MD5','VULNERABLE'), ('SHA-512','SAFE'),
    ('CRYSTALS-KYBER','SAFE'), ('CRYSTALS-DILITHIUM','SAFE'),
]
for algo, expected in cases:
    got = classify_algorithm(algo)['vuln']
    t(f'{algo}={expected}', lambda g=got, e=expected: None if g==e else (_ for _ in ()).throw(AssertionError(f'got {g}')))
t(f'QUANTUM_VULN_TABLE has 43+ entries', lambda: None if len(QUANTUM_VULN_TABLE)>=43 else (_ for _ in ()).throw(AssertionError(len(QUANTUM_VULN_TABLE))))

# ── Tokenizer ─────────────────────────────────────────────────────────────────
print('TFIDFVectorStore tokenizer:')
t('log4shell tokenized', lambda: None if 'log4shell' in _tokenize('CVE-2021-44228 Log4Shell') else (_ for _ in ()).throw(AssertionError(_tokenize('CVE-2021-44228 Log4Shell'))))
t('sha256 tokenized', lambda: None if 'sha256' in _tokenize('SHA256 hash') else (_ for _ in ()).throw(AssertionError()))
t('cve year tokenized', lambda: None if '2026' in _tokenize('CVE-2026-93577') else (_ for _ in ()).throw(AssertionError()))
t('rce tokenized', lambda: None if 'rce' in _tokenize('Remote Code Execution RCE') else (_ for _ in ()).throw(AssertionError()))

# ── TF-IDF store ──────────────────────────────────────────────────────────────
print('TFIDFVectorStore:')
store = TFIDFVectorStore()
store.add('CVE-2026-93577 GitLab CVSS 10.0 auth bypass KEV critical', {'id':'1'})
store.add('CVE-2026-104935 Ivanti Connect Secure zero-day RCE exploited', {'id':'2'})
store.add('CVE-2026-85046 Chrome BlueMoon zero-day APT chain exploit', {'id':'3'})
store.add('CVE-2026-68820 Microsoft Windows Lazarus zero-day wormable', {'id':'4'})
store.add('CVE-2026-62878 Microsoft wormable RCE SMB propagation', {'id':'5'})
t('GitLab query returns results', lambda: None if len(store.query('GitLab auth bypass',top_k=3))>0 else (_ for _ in ()).throw(AssertionError()))
t('Ivanti query returns results', lambda: None if len(store.query('Ivanti zero-day RCE',top_k=3))>0 else (_ for _ in ()).throw(AssertionError()))
t('Chrome query returns results', lambda: None if len(store.query('Chrome BlueMoon APT',top_k=3))>0 else (_ for _ in ()).throw(AssertionError()))
t('Wormable RCE query', lambda: None if len(store.query('wormable RCE SMB',top_k=3))>0 else (_ for _ in ()).throw(AssertionError()))
t('Scores bounded 0-1', lambda: None if all(0<=r['score']<=1 for r in store.query('CVE exploit',top_k=5)) else (_ for _ in ()).throw(AssertionError()))

# ── Agent ─────────────────────────────────────────────────────────────────────
print('Agent:')
t('4 BUILTIN_PLANS', lambda: None if len(BUILTIN_PLANS)==4 else (_ for _ in ()).throw(AssertionError(len(BUILTIN_PLANS))))
t('full_pentest 8 steps', lambda: None if len(BUILTIN_PLANS['full_pentest'])==8 else (_ for _ in ()).throw(AssertionError()))
t('quick_vuln 3 steps', lambda: None if len(BUILTIN_PLANS['quick_vuln'])==3 else (_ for _ in ()).throw(AssertionError()))
t('defense_audit 3 steps', lambda: None if len(BUILTIN_PLANS['defense_audit'])==3 else (_ for _ in ()).throw(AssertionError()))
t('crypto_audit 4 steps', lambda: None if len(BUILTIN_PLANS['crypto_audit'])==4 else (_ for _ in ()).throw(AssertionError()))

# ── DNS covert ────────────────────────────────────────────────────────────────
print('DNS covert:')
t('High entropy (CVE ID)', lambda: None if _shannon_entropy('CVE-2026-93577-GitLab-RCE')>3.0 else (_ for _ in ()).throw(AssertionError()))
t('Low entropy (aaaa)', lambda: None if _shannon_entropy('aaaaaaaaaa')<1.0 else (_ for _ in ()).throw(AssertionError()))

# ── IntelGraph ────────────────────────────────────────────────────────────────
print('IntelGraph:')
t('Importable from core', lambda: None if IntelGraph is not None else (_ for _ in ()).throw(AssertionError()))

# ── Session ───────────────────────────────────────────────────────────────────
print('Session:')
s = Session(sessions_dir=tempfile.mkdtemp())
s.write('findings.json', {'findings': [{'cve':'CVE-2026-93577','severity':'CRITICAL'}]})
s.attach_receipt('313-v4-00000001', 'vuln')
t('write/read works', lambda: None if s.read('findings.json')['findings'][0]['cve']=='CVE-2026-93577' else (_ for _ in ()).throw(AssertionError()))
t('attach_receipt works', lambda: None if len(s.get_receipts())==1 else (_ for _ in ()).throw(AssertionError()))
t('receipt has correct module', lambda: None if s.get_receipts()[0]['module']=='vuln' else (_ for _ in ()).throw(AssertionError()))

# ── AIEngine SSRF ─────────────────────────────────────────────────────────────
print('AIEngine:')
try:
    AIEngine({'backend':'ollama','endpoint':'http://169.254.169.254/metadata'})
    t('SSRF blocked', lambda: (_ for _ in ()).throw(AssertionError('should have raised')))
except ValueError:
    t('SSRF blocked (169.254.x.x)', lambda: None)

# ── SLHDSASigner ──────────────────────────────────────────────────────────────
print('SLHDSASigner:')
signer = SLHDSASigner()
t('Instantiates', lambda: None if signer is not None else (_ for _ in ()).throw(AssertionError()))
t('available matches public-key support', lambda: None if signer.available == (signer.public_key is not None) else (_ for _ in ()).throw(AssertionError('backend/public key mismatch')))
expected_algorithm = 'SPHINCS+-SHAKE-128f' if signer.available else 'HMAC-SHA3-256'
t('algorithm_name correct', lambda: None if signer.algorithm_name == expected_algorithm else (_ for _ in ()).throw(AssertionError(signer.algorithm_name)))
t('sign/verify round trip', lambda: None if signer.verify(b'test receipt', signer.sign(b'test receipt')) else (_ for _ in ()).throw(AssertionError('signature verification failed')))

# ── IOC detection ─────────────────────────────────────────────────────────────
print('IOC type detection:')
t('IP detection', lambda: None if _detect_ioc_type('185.220.101.1')=='ip' else (_ for _ in ()).throw(AssertionError()))
t('URL detection', lambda: None if _detect_ioc_type('http://evil.com/payload')=='url' else (_ for _ in ()).throw(AssertionError()))
t('SHA256 hash detection', lambda: None if _detect_ioc_type('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') == 'sha256' else (_ for _ in ()).throw(AssertionError()))
t('Domain detection', lambda: None if _detect_ioc_type('evil.com')=='domain' else (_ for _ in ()).throw(AssertionError()))
t('Unknown type', lambda: None if _detect_ioc_type('not-an-ioc')=='unknown' else (_ for _ in ()).throw(AssertionError()))

# ── Kernel ────────────────────────────────────────────────────────────────────
print('Kernel:')
from shadow313.core.kernel import Kernel
k = Kernel(load_v2=True)
t('0 load errors', lambda: None if len(k.load_errors)==0 else (_ for _ in ()).throw(AssertionError(k.load_errors)))
t('commands registered', lambda: None if len(k.registered_commands())>0 else (_ for _ in ()).throw(AssertionError(len(k.registered_commands()))))
for cmd in ['recon','vuln','quantum','campaign','sandbox','crypto_agility','cloud','network','defense','cicd']:
    t(f'command: {cmd}', lambda c=cmd: None if c in k.registered_commands() else (_ for _ in ()).throw(AssertionError(f'{c} missing')))

print()
print(f'=== RESULTS: {len(passed)} passed, {len(failed)} failed ===')
if failed:
    print('FAILURES:')
    for name, err in failed:
        print(f'  ✗ {name}: {err}')