#!/usr/bin/env python3
"""
CTF Challenge: Python Jail Escape (Web Edition)
Category: Exploitation / Sandbox Escape
Difficulty: Expert ⚠️⚠️⚠️
Flag: JCOECTF{pyth0n_j41l_3sc4p3_m4st3r_2024}
"""

from flask import Flask, request, jsonify
import builtins
import dis

app = Flask(__name__)

FLAG = "JCOECTF{pyth0n_j41l_3sc4p3_m4st3r_2024}"

BLACKLIST = [
    'import', '__import__', 'open', 'file', 'exec', 'eval',
    'compile', 'input', '__builtins__', 'globals', 'locals', 'vars',
    'dir', 'help', 'license', 'exit', 'quit', 'sys', 'os', 'subprocess',
    '__class__', '__base__', '__subclasses__', '__mro__', '__init__',
    '__globals__', '__code__', '__dict__', '__loader__', '__spec__',
    '__package__', 'memoryview', 'bytearray', 'bytes'
]

WHITELIST_BUILTINS = {
    'print': print, 'len': len, 'str': str, 'int': int,
    'bool': bool, 'list': list, 'dict': dict, 'tuple': tuple,
    'set': set, 'abs': abs, 'min': min, 'max': max, 'sum': sum,
    'sorted': sorted, 'reversed': reversed, 'range': range,
    'enumerate': enumerate, 'zip': zip, 'map': map, 'filter': filter
}


def check_code(code):
    code_lower = code.lower()
    for word in BLACKLIST:
        if word in code_lower:
            return False, f"Forbidden word detected: {word}"
    if any(p in code for p in ['.', '[', ']', '{', '}', '__', 'lambda', 'chr', 'ord']):
        return False, "Dangerous pattern detected!"
    if len(code) > 100:
        return False, "Code too long! (max 100 chars)"
    return True, "OK"


def safe_eval(code):
    try:
        allowed, msg = check_code(code)
        if not allowed:
            return f"[-] Security violation: {msg}"

        code_obj = compile(code, "<sandbox>", "eval")
        for instr in dis.Bytecode(code_obj):
            if instr.opname in ['IMPORT_NAME', 'IMPORT_FROM', 'LOAD_BUILD_CLASS']:
                return "[-] Import detected in bytecode!"

        safe_globals = {'__builtins__': WHITELIST_BUILTINS}
        result = eval(code_obj, safe_globals, {})
        return str(result)
    except Exception as e:
        return f"[-] Error: {type(e).__name__}: {e}"


@app.route('/')
def index():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>🐍 Python Jail Escape</title>
        <style>
            body {
                background-color: #000;
                color: #0f0;
                font-family: monospace;
                padding: 20px;
            }
            #terminal {
                background-color: #111;
                border: 2px solid #0f0;
                padding: 15px;
                height: 400px;
                overflow-y: auto;
                white-space: pre-wrap;
            }
            input {
                background: #000;
                color: #0f0;
                border: none;
                border-bottom: 2px solid #0f0;
                width: 100%;
                font-family: monospace;
                font-size: 16px;
                padding: 5px;
                outline: none;
            }
            h1 { color: #0f0; text-align: center; }
            button {
                background: #0f0;
                color: #000;
                font-weight: bold;
                border: 2px solid #0f0;
                padding: 5px 10px;
                cursor: pointer;
                margin-top: 5px;
            }
        </style>
    </head>
    <body>
        <h1>🐍 PYTHON JAIL ESCAPE</h1>
        <div id="terminal">
Welcome to the Maximum Security Python Jail.
Your mission: Escape and read the flag.

Restrictions:
[X] Most builtins disabled
[X] Import blocked
[X] No attribute access (., __, [])
[X] No lambda, chr, ord
[X] Max 100 chars
[X] Bytecode inspection enabled

Type 'help' to list functions.
---------------------------------------------------
        </div>
        <form id="jailForm">
            <input id="code" type="text" placeholder="jail> your code here" autocomplete="off" />
            <button type="submit">Run</button>
        </form>
        <script>
        const form = document.getElementById("jailForm");
        const terminal = document.getElementById("terminal");
        const codeInput = document.getElementById("code");

        form.addEventListener("submit", async (e) => {
            e.preventDefault();
            const code = codeInput.value.trim();
            if (!code) return;
            terminal.innerHTML += "\\njail> " + code;
            const res = await fetch("/run", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({code})
            });
            const data = await res.json();
            terminal.innerHTML += "\\n" + data.output;
            terminal.scrollTop = terminal.scrollHeight;
            codeInput.value = "";
        });
        </script>
    </body>
    </html>
    """


@app.route('/run', methods=['POST'])
def run_code():
    code = request.json.get('code', '')
    if code.strip().lower() == 'help':
        return jsonify({'output': "Available: " + ", ".join(WHITELIST_BUILTINS.keys())})
    elif code.strip().lower() == 'flag':
        return jsonify({'output': f"The flag is hidden in memory... find a way to reveal it! 😉"})
    elif code.strip().lower() == 'giveup':
        return jsonify({'output': f"You gave up! The flag was: {FLAG}"})
    else:
        output = safe_eval(code)
        return jsonify({'output': output})


if __name__ == "__main__":
    print("[*] Python Jail Escape running on port 9015")
    print("[*] Challenge URL: http://localhost:9015")
    app.run(host="0.0.0.0", port=9015)
