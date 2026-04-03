"""
CipherX - Cipher Engine
Handles: Caesar, Progressive shift, Segment shift, Frequency analysis, Keyword scoring
"""

from collections import Counter
import string

# ── English reference data ─────────────────────────────────────────────────────

ENGLISH_FREQ = {
    'e':12.7,'t':9.1,'a':8.2,'o':7.5,'i':7.0,'n':6.7,'s':6.3,'h':6.1,
    'r':6.0,'d':4.3,'l':4.0,'c':2.8,'u':2.8,'m':2.4,'w':2.4,'f':2.2,
    'g':2.0,'y':2.0,'p':1.9,'b':1.5,'v':1.0,'k':0.8,'j':0.2,'x':0.2,
    'q':0.1,'z':0.1
}

COMMON_WORDS = {
    'the','and','that','have','for','not','with','you','this','but',
    'his','from','they','she','her','been','one','all','would','there',
    'their','what','out','about','who','get','which','when','make',
    'can','like','time','just','him','know','take','into','year','your',
    'good','some','could','them','see','other','than','then','now','look',
    'only','come','its','also','back','after','use','two','how','our',
    'work','well','way','even','want','because','any','these','give','day',
    'most','us','is','was','are','were','had','has','be','do','did',
    'it','of','in','to','a','an','at','on','by','as','or','if','up',
    'so','no','we','my','he','me','do','go','am'
}

# ── Core shift utilities ───────────────────────────────────────────────────────

def shift_char(c: str, n: int) -> str:
    """Shift a single alphabetic character by n positions (mod 26)."""
    if c.isalpha():
        base = ord('A') if c.isupper() else ord('a')
        return chr((ord(c) - base + n) % 26 + base)
    return c

def caesar_decode(text: str, shift: int) -> str:
    """Standard Caesar cipher decode."""
    return ''.join(shift_char(c, -shift) for c in text)

def progressive_decode(text: str, start: int, step: int) -> str:
    """
    Progressive shift: each letter is shifted by an increasing amount.
    shift for letter i = start + (i * step)
    """
    result = []
    letter_index = 0
    for c in text:
        if c.isalpha():
            shift = (start + letter_index * step) % 26
            result.append(shift_char(c, -shift))
            letter_index += 1
        else:
            result.append(c)
    return ''.join(result)

def segment_decode(text: str, shifts: list[int]) -> str:
    """
    Segment shift: text is split into len(shifts) equal segments,
    each decoded with its own shift value.
    """
    words = text.split()
    seg_size = max(1, len(words) // len(shifts))
    result = []
    for i, shift in enumerate(shifts):
        segment = words[i * seg_size : (i + 1) * seg_size]
        decoded = ' '.join(caesar_decode(w, shift) for w in segment)
        result.append(decoded)
    # tail segment (any leftover words)
    tail = words[len(shifts) * seg_size:]
    if tail:
        result.append(' '.join(caesar_decode(w, shifts[-1]) for w in tail))
    return ' '.join(result)

# ── Scoring ────────────────────────────────────────────────────────────────────

def frequency_score(text: str) -> float:
    """
    Compare letter frequency of decoded text against English reference.
    Lower score = closer to English (sum of squared differences).
    We convert to a 0-1 fitness score (higher = more English-like).
    """
    letters = [c.lower() for c in text if c.isalpha()]
    if not letters:
        return 0.0
    counts = Counter(letters)
    total = len(letters)
    score = 0.0
    for letter, expected_pct in ENGLISH_FREQ.items():
        observed_pct = (counts.get(letter, 0) / total) * 100
        score += (observed_pct - expected_pct) ** 2
    # Convert distance to fitness (lower distance = higher fitness)
    return 1 / (1 + score)

def keyword_score(text: str) -> float:
    """
    Count how many common English words appear in the decoded text.
    Returns fraction of words that are common English words.
    """
    words = [w.strip(string.punctuation).lower() for w in text.split()]
    if not words:
        return 0.0
    hits = sum(1 for w in words if w in COMMON_WORDS)
    return hits / len(words)

def combined_score(text: str) -> float:
    """Weighted combination of frequency and keyword score."""
    freq = frequency_score(text)
    kw   = keyword_score(text)
    return 0.4 * freq + 0.6 * kw   # keywords weighted higher — more decisive

# ── Auto-scan (brute force all shifts) ────────────────────────────────────────

def scan_caesar(ciphertext: str, top_n: int = 5) -> list[dict]:
    """Try all 26 Caesar shifts, return top_n ranked by combined score."""
    candidates = []
    for shift in range(26):
        decoded = caesar_decode(ciphertext, shift)
        score   = combined_score(decoded)
        candidates.append({
            'method': 'caesar',
            'shift': shift,
            'decoded': decoded,
            'score': round(score, 4),
            'keyword_hits': round(keyword_score(decoded), 4),
            'freq_fit':     round(frequency_score(decoded), 4),
        })
    candidates.sort(key=lambda x: x['score'], reverse=True)
    return candidates[:top_n]

def scan_progressive(ciphertext: str, top_n: int = 5) -> list[dict]:
    """
    Try a grid of (start, step) pairs for progressive shift.
    step=0 is just Caesar, so start step from 1.
    """
    candidates = []
    for start in range(26):
        for step in range(1, 6):   # steps 1-5 are practical
            decoded = progressive_decode(ciphertext, start, step)
            score   = combined_score(decoded)
            candidates.append({
                'method': 'progressive',
                'start': start,
                'step': step,
                'decoded': decoded,
                'score': round(score, 4),
            })
    candidates.sort(key=lambda x: x['score'], reverse=True)
    return candidates[:top_n]

def auto_decrypt(ciphertext: str, top_n: int = 5) -> list[dict]:
    """
    Run all decoders, merge results, return globally ranked top candidates.
    This is the main entry point for the API.
    """
    results = []
    results.extend(scan_caesar(ciphertext, top_n=top_n))
    results.extend(scan_progressive(ciphertext, top_n=top_n))
    results.sort(key=lambda x: x['score'], reverse=True)
    return results[:top_n]

# ── CLI quick-test ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    sample = "Khoor, zruog! Wklv lv d whvw phvvdjh."
    print("=== Auto-decrypt ===")
    for r in auto_decrypt(sample, top_n=3):
        print(f"[{r['score']:.3f}] {r['method']:12s} → {r['decoded'][:60]}")

    print("\n=== Progressive decode (start=3, step=2) ===")
    enc = "Pmttw, ewztl!"
    print(progressive_decode(enc, start=3, step=2))