# app.py
# Flask entry point. Routes only — no cipher logic lives here.
# Each route receives form data, calls the engine, returns the result.

from flask import Flask, render_template, request
from engine.caesar import caesar_encode, caesar_decode
from engine.analyzer import brute_force_caesar

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
    """
    Brute-force route: tries all 26 shifts and returns ranked results.
    The user doesn't need to know the shift — we figure out the best guess.
    """

    text = request.form.get('brute_text', '')

    # Basic validation — nothing to do if the box is empty
    if not text.strip():
        return render_template('index.html', result=None, error="Please enter some text to brute-force.", brute_results=None)

    # Run all 26 shifts and get them ranked by score
    brute_results = brute_force_caesar(text)

    return render_template('index.html', result=None, error=None, brute_results=brute_results, original=text)

if __name__ == '__main__':
    # debug=True auto-reloads the server when you save a file — very handy during development
    app.run(debug=True)