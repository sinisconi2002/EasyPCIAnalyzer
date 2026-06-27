import os
import re
import json
import string

from flask import Flask, request, jsonify
from blob_utils import download_blob_to_memory, test_connection
from analyzer_engine import scan_coredump, scan_logs, add_custom_rule

app = Flask(__name__)
RULES_FILE = 'custom_rules.json'
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "easypci-dumps")


def extract_strings_from_stream(byte_stream, min_length=4):
    data = byte_stream.read()
    printable = set(bytes(string.printable, 'ascii'))
    result = []
    current_string = bytearray()
    for byte in data:
        if byte in printable:
            current_string.append(byte)
        else:
            if len(current_string) >= min_length:
                result.append(current_string.decode('ascii'))
            current_string = bytearray()
    if len(current_string) >= min_length:
        result.append(current_string.decode('ascii'))
    return " ".join(result)


def load_saved_rules():
    if os.path.exists(RULES_FILE) and os.path.getsize(RULES_FILE) > 0:
        try:
            with open(RULES_FILE, 'r') as f:
                rules = json.load(f)
                for rule in rules:
                    add_custom_rule(rule.get('rule_name', rule['entity']), rule['entity'], rule['patterns'], rule['context'])
            print("[OK] Reguli custom încărcate în motorul Presidio.")
        except Exception as e:
            print(f"[ERROR] Eroare la încărcarea regulilor: {e}")


@app.route('/rules', methods=['GET'])
def get_rules():
    if os.path.exists(RULES_FILE) and os.path.getsize(RULES_FILE) > 0:
        with open(RULES_FILE, 'r') as f:
            return jsonify(json.load(f)), 200
    return jsonify([]), 200


@app.route('/rules/upload', methods=['POST'])
def upload_rule():
    data = request.json
    entity = data.get('entity')
    patterns = data.get('patterns', [])
    context = data.get('context', [])

    if not entity or not patterns:
        return jsonify({"error": "Entity și patterns sunt obligatorii!"}), 400

    add_custom_rule(entity, patterns, context)

    saved_rules = []
    if os.path.exists(RULES_FILE) and os.path.getsize(RULES_FILE) > 0:
        with open(RULES_FILE, 'r') as f:
            saved_rules = json.load(f)

    saved_rules.append({"entity": entity, "patterns": patterns, "context": context})
    with open(RULES_FILE, 'w') as f:
        json.dump(saved_rules, f, indent=4)

    return jsonify({"message": f"Regulă pentru '{entity}' salvată și activată."}), 200


@app.route('/scan/modern', methods=['POST'])
def scan_modern():
    data = request.json

    if 'binary_file_name' in data:
        file_name = data['binary_file_name']
        try:
            memory_stream = download_blob_to_memory(R2_BUCKET_NAME, file_name)
            text_to_scan = extract_strings_from_stream(memory_stream)
            alerts = scan_coredump(text_to_scan)
        except Exception as e:
            return jsonify([f"[EROARE R2] {str(e)}"]), 500

    elif 'text' in data:
        text_to_scan = data['text']
        alerts = scan_logs(text_to_scan)
        if alerts:
            alerts.insert(0, "[PCI DSS Req. 10]: Jurnal nesecurizat!")

    else:
        return jsonify(["[EROARE] Payload invalid."]), 400

    if not alerts:
        alerts.append("[OK] Nu au fost detectate date sensibile.")

    return jsonify(alerts), 200


@app.route('/scan/classic', methods=['POST'])
def scan_classic():
    data = request.json
    text_to_scan = ""

    if 'binary_file_name' in data:
        try:
            memory_stream = download_blob_to_memory(R2_BUCKET_NAME, data['binary_file_name'])
            text_to_scan = extract_strings_from_stream(memory_stream)
        except Exception as e:
            return jsonify([f"[EROARE R2] {str(e)}"]), 500
    elif 'text' in data:
        text_to_scan = data['text']
    else:
        return jsonify(["[EROARE] Payload invalid."]), 400

    alerts = []
    pan_pattern = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
    matches = pan_pattern.findall(text_to_scan)

    for match in set(matches):
        clean_match = re.sub(r'\D', '', match)
        if 13 <= len(clean_match) <= 19:
            alerts.append(f"[CLASSIC REGEX] Posibil PAN brut: {clean_match}")

    if not alerts:
        alerts.append("[OK] Motorul Classic (Regex) nu a găsit potriviri.")

    return jsonify(alerts), 200


@app.route('/rules/auto-extract', methods=['POST'])
def auto_extract_rule_from_file():

    data = request.json
    code_text = data.get('code_text', '')

    if not code_text:
        return jsonify({"error": "Nu ai trimis niciun cod sursă."}), 400

    class_match = re.search(r'class\s+([A-Za-z0-9_]+)', code_text)
    if not class_match:
        return jsonify({"error": "Nu s-a găsit nicio definiție de clasă în fișier."}), 400

    class_name = class_match.group(1)


    words = set(re.findall(r'\b[a-z]+[A-Z][a-zA-Z0-9]+\b', code_text))


    new_context = [class_name] + list(words)


    default_pan_patterns = [r"\b(?:\d[ -]*?){13,19}\b"]
    add_custom_rule(f"StructLeak_{class_name}", "CREDIT_CARD", default_pan_patterns, new_context)

    saved_rules = []
    if os.path.exists(RULES_FILE) and os.path.getsize(RULES_FILE) > 0:
        with open(RULES_FILE, 'r') as f:
            saved_rules = json.load(f)

    saved_rules.append({
        "rule_name": f"StructLeak_{class_name}",
        "entity": "CREDIT_CARD",
        "patterns": default_pan_patterns,
        "context": new_context
    })

    with open(RULES_FILE, 'w') as f:
        json.dump(saved_rules, f, indent=4)

    return jsonify({
        "message": f"Succes! AI-ul a învățat clasa '{class_name}'.",
        "extracted_context": new_context
    }), 200

@app.route('/dummy_route', methods=['GET'])
def dummy_route():
    return jsonify({"status": "EasyPCI Analyzer is running"}), 200


load_saved_rules()

if __name__ == '__main__':
    # test_connection() # Oprește testul de conexiune la start dacă te încurcă
    app.run(host='0.0.0.0', port=5000)