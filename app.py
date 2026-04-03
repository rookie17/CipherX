# app.py
# Flask entry point. Routes only — no cipher logic lives here.
# Each route receives form data, calls the engine, returns the result.

from flask import Flask, render_template, request
from engine.caesar import caesar_encode, caesar_decode
from engine.analyzer import brute_force_caesar
from engine.progressive import brute_force_progressive, progressive_encode, progressive_decode
from engine.segment import segment_encode, segment_decode, brute_force_segment, estimate_brute_force_size
from engine.noise_handler import denoise_and_decode, detect_noise_profile, NOISE_PROFILES

app = Flask(__name__)


@app.route('/')
def index():
    # Serve the main page with no results yet
    return render_template('index.html', result=None, error=None)


@app.route('/process', methods=['POST'])
def process():
    """
    Handles the form submission.
    Reads: cipher type, operation (encode/decode), shift, and the input text.
    Returns: the processed result back to the same page.
    """

    # Pull values from the HTML form
    cipher    = request.form.get('cipher')       # e.g. "caesar"
    operation = request.form.get('operation')    # "encode" or "decode"
    text      = request.form.get('text', '')     # The input message
    shift_raw = request.form.get('shift', '3')   # Shift number as a string

    # --- Input validation ---
    if not text.strip():
        return render_template('index.html', result=None, error="Please enter some text.")

    try:
        shift = int(shift_raw)
        if not (1 <= shift <= 25):
            raise ValueError
    except ValueError:
        return render_template('index.html', result=None, error="Shift must be a whole number between 1 and 25.")

    # --- Route to the right cipher ---
    result = None

    if cipher == 'caesar':
        if operation == 'encode':
            result = caesar_encode(text, shift)
        elif operation == 'decode':
            result = caesar_decode(text, shift)

    return render_template('index.html', result=result, error=None,
                           original=text, shift=shift, operation=operation)

# Paste this route into app.py, below the existing /process route

@app.route('/brute', methods=['POST'])
def brute():
    text = request.form.get('brute_text', '')

    if not text.strip():
        return render_template('index.html', result=None, error="Please enter some text to brute-force.", brute_results=None)

    # Read the keywords field, split on commas, clean up whitespace
    raw_keywords = request.form.get('keywords', '')
    keywords = [kw.strip() for kw in raw_keywords.split(',') if kw.strip()]

    brute_results = brute_force_caesar(text, keywords)

    return render_template('index.html', result=None, error=None,
                           brute_results=brute_results, original=text,
                           keywords=raw_keywords)

@app.route('/progressive', methods=['POST'])
def progressive():
    text      = request.form.get('prog_text', '')
    mode      = request.form.get('prog_mode', 'brute')   # 'brute', 'encode', 'decode'
    raw_kws   = request.form.get('prog_keywords', '')
    keywords  = [kw.strip() for kw in raw_kws.split(',') if kw.strip()]

    if not text.strip():
        return render_template('index.html', result=None, error="Please enter some text.",
                               prog_results=None)

    # Known-key encode/decode path
    if mode in ('encode', 'decode'):
        try:
            start = int(request.form.get('prog_start', 0))
            step  = int(request.form.get('prog_step', 1))
            if not (0 <= start <= 25 and 0 <= step <= 25):
                raise ValueError
        except ValueError:
            return render_template('index.html', result=None,
                                   error="Start and step must be whole numbers between 0 and 25.",
                                   prog_results=None)

        if mode == 'encode':
            prog_result = progressive_encode(text, start, step)
        else:
            prog_result = progressive_decode(text, start, step)

        return render_template('index.html', result=None, error=None,
                               prog_result=prog_result, prog_mode=mode,
                               prog_start=start, prog_step=step)

    # Brute force path — start and step unknown
    prog_results = brute_force_progressive(text, keywords)

    return render_template('index.html', result=None, error=None,
                           prog_results=prog_results, prog_original=text,
                           prog_keywords=raw_kws)

@app.route('/segment', methods=['POST'])
def segment():
    text = request.form.get('seg_text', '')
    mode = request.form.get('seg_mode', 'brute')  # 'encode', 'decode', 'brute'

    if not text.strip():
        return render_template('index.html', result=None,
                               error="Please enter some text.", seg_results=None)

    # Parse segment size — shared across all modes
    try:
        seg_size = int(request.form.get('seg_size', 5))
        if seg_size < 1:
            raise ValueError
    except ValueError:
        return render_template('index.html', result=None,
                               error="Segment size must be a positive whole number.", seg_results=None)

    # ── Known-key encode / decode ──
    if mode in ('encode', 'decode'):
        raw_shifts = request.form.get('seg_shifts', '3,7')
        try:
            shifts = [int(s.strip()) for s in raw_shifts.split(',') if s.strip()]
            if not shifts or any(not (0 <= s <= 25) for s in shifts):
                raise ValueError
        except ValueError:
            return render_template('index.html', result=None,
                                   error="Shifts must be comma-separated numbers between 0 and 25.", seg_results=None)

        if mode == 'encode':
            seg_result = segment_encode(text, seg_size, shifts)
        else:
            seg_result = segment_decode(text, seg_size, shifts)

        return render_template('index.html', result=None, error=None,
                               seg_result=seg_result, seg_mode=mode,
                               seg_size=seg_size, seg_shifts=raw_shifts)

    # ── Brute force ──
    try:
        num_shifts = int(request.form.get('num_shifts', 2))
        if not (1 <= num_shifts <= 3):
            raise ValueError
    except ValueError:
        return render_template('index.html', result=None,
                               error="Number of shifts must be 1, 2, or 3 for brute force.", seg_results=None)

    raw_kws  = request.form.get('seg_keywords', '')
    keywords = [kw.strip() for kw in raw_kws.split(',') if kw.strip()]

    total_candidates = estimate_brute_force_size(num_shifts)
    seg_results      = brute_force_segment(text, seg_size, num_shifts, keywords)

    return render_template('index.html', result=None, error=None,
                           seg_results=seg_results, seg_original=text,
                           seg_keywords=raw_kws, seg_size=seg_size,
                           total_candidates=total_candidates)

@app.route('/denoise', methods=['POST'])
def denoise():
    text = request.form.get('noisy_text', '')

    if not text.strip():
        return render_template('index.html', result=None,
                               error="Please enter some text.", noise_result=None)

    raw_kws  = request.form.get('noise_keywords', '')
    keywords = [kw.strip() for kw in raw_kws.split(',') if kw.strip()]

    try:
        nth = int(request.form.get('nth', 2))
        if nth < 2:
            raise ValueError
    except ValueError:
        return render_template('index.html', result=None,
                               error="N must be 2 or greater.", noise_result=None)

    detected     = detect_noise_profile(text)
    noise_result = denoise_and_decode(text, keywords, nth)

    return render_template('index.html', result=None, error=None,
                           noise_result=noise_result,
                           noise_original=text,
                           noise_detected=detected,
                           noise_keywords=raw_kws)

if __name__ == '__main__':
    # debug=True auto-reloads the server when you save a file — very handy during development
    app.run(debug=True)