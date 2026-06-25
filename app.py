import os
import re
import json
import string

from flask import Flask, request, jsonify
from blob_utils import download_blob_to_memory, test_connection
from analyzer_engine import scan_with_presidio, add_custom_rule

app = Flask(__name__)
RULES_FILE = 'custom_rules.json'

# Bucket-ul R2 din care tragem coredump-urile
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "easypci-dumps")


# ── Utilitar: extragere strings printabile din stream binar ──────────
def extract_strings_from_stream(byte_stream, min_length=4):
    """Extrage caracterele printabile dintr-un coredump binar (echivalent 'strings')."""
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


# ── Încărcare reguli custom salvate (la pornire) ────────────────────
def load_saved_rules():
    """Încarcă regulile persistate la pornirea aplicației."""
    if os.path.exists(RULES_FILE) and os.path.getsize(RULES_FILE) > 0:
        try:
            with open(RULES_FILE, 'r') as f:
                rules = json.load(f)
                for rule in rules:
                    add_custom_rule(rule['entity'], rule['patterns'], rule['context'])
            print("[OK] Reguli custom încărcate în motorul Presidio.")
        except Exception as e:
            print(f"[ERROR] Eroare la încărcarea regulilor: {e}")


# ══════════════════════════════════════════════════════════════════════
#  RUTE API
# ══════════════════════════════════════════════════════════════════════

# ── GET /rules — Listează regulile custom încărcate ──────────────────
@app.route('/rules', methods=['GET'])
def get_rules():
    if os.path.exists(RULES_FILE) and os.path.getsize(RULES_FILE) > 0:
        with open(RULES_FILE, 'r') as f:
            return jsonify(json.load(f)), 200
    return jsonify([]), 200


# ── POST /rules/upload — Adaugă o regulă custom în Presidio ─────────
@app.route('/rules/upload', methods=['POST'])
def upload_rule():
    data = request.json
    entity = data.get('entity')
    patterns = data.get('patterns', [])
    context = data.get('context', [])

    if not entity or not patterns:
        return jsonify({"error": "Entity și patterns sunt obligatorii!"}), 400

    # Injectare în motorul unic din analyzer_engine.py
    add_custom_rule(entity, patterns, context)

    # Persistare pe disc (supraviețuiește restart-urilor)
    saved_rules = []
    if os.path.exists(RULES_FILE) and os.path.getsize(RULES_FILE) > 0:
        with open(RULES_FILE, 'r') as f:
            saved_rules = json.load(f)

    saved_rules.append({"entity": entity, "patterns": patterns, "context": context})
    with open(RULES_FILE, 'w') as f:
        json.dump(saved_rules, f, indent=4)

    return jsonify({"message": f"Regulă pentru '{entity}' salvată și activată."}), 200


# ── POST /scan/modern — Motor NLP Hibrid (EasyPCI 2.0) ──────────────
#    Presidio + Luhn + Sliding Window + CVV contextual
#    Acceptă: core dump binar (via R2) SAU text cleartext (loguri)
@app.route('/scan/modern', methods=['POST'])
def scan_modern():
    data = request.json
    text_to_scan = ""
    is_cleartext_log = False

    # Scenariul A: Core Dump binar din Cloudflare R2
    if 'binary_file_name' in data:
        file_name = data['binary_file_name']
        try:
            memory_stream = download_blob_to_memory(R2_BUCKET_NAME, file_name)
            text_to_scan = extract_strings_from_stream(memory_stream)
        except Exception as e:
            return jsonify([f"[EROARE R2] Nu s-a putut procesa coredump-ul: {str(e)}"]), 500

    # Scenariul B: Log cleartext (Cerința 10 PCI DSS)
    elif 'text' in data:
        text_to_scan = data['text']
        is_cleartext_log = True

    else:
        return jsonify(["[EROARE] Payload invalid — trimite binary_file_name sau text."]), 400

    # Scanare prin motorul hibrid (Presidio + Luhn + Sliding Window)
    alerts = scan_with_presidio(text_to_scan)

    # Avertizare specifică PCI DSS Cerința 10
    if is_cleartext_log and alerts:
        alerts.insert(0, "[PCI DSS Req. 10] VIOLAȚIE: Date sensibile detectate în jurnale cleartext!")

    if not alerts:
        alerts.append("[OK] Nu au fost detectate date sensibile.")

    return jsonify(alerts), 200


# ── POST /scan/classic — Motor Regex pur (EasyPCI 1.0) ───────────────
#    Fără validare Luhn, fără context semantic — demonstrează fals-pozitive
@app.route('/scan/classic', methods=['POST'])
def scan_classic():
    data = request.json
    text_to_scan = ""

    if 'binary_file_name' in data:
        file_name = data['binary_file_name']
        try:
            memory_stream = download_blob_to_memory(R2_BUCKET_NAME, file_name)
            text_to_scan = extract_strings_from_stream(memory_stream)
        except Exception as e:
            return jsonify([f"[EROARE R2] Scanare clasică eșuată: {str(e)}"]), 500
    elif 'text' in data:
        text_to_scan = data['text']
    else:
        return jsonify(["[EROARE] Lipsește binary_file_name sau text."]), 400

    alerts = []

    # Match exact pe cardul specific (dacă e trimis)
    if 'cardData' in data and data['cardData']:
        specific_pan = data['cardData'].get('Pan', '')
        if specific_pan and specific_pan in text_to_scan:
            alerts.append(f"[CLASSIC REGEX] MATCH EXACT: Cardul ({specific_pan}) găsit în clar în memorie!")

    # Regex brut — orice secvență de 13-19 cifre
    pan_pattern = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
    matches = pan_pattern.findall(text_to_scan)

    for match in set(matches):
        clean_match = re.sub(r'\D', '', match)
        if 13 <= len(clean_match) <= 19:
            alerts.append(f"[CLASSIC REGEX] Posibil PAN brut: {clean_match}")

    if not alerts:
        alerts.append("[OK] Motorul Classic (Regex) nu a găsit potriviri.")

    return jsonify(alerts), 200


# ── GET /dummy_route — Health check simplu ───────────────────────────
@app.route('/dummy_route', methods=['GET'])
def dummy_route():
    return jsonify({"status": "EasyPCI Analyzer is running"}), 200


# ══════════════════════════════════════════════════════════════════════
#  PORNIRE APLICAȚIE
# ══════════════════════════════════════════════════════════════════════
load_saved_rules()

if __name__ == '__main__':
    test_connection()
    app.run(host='0.0.0.0', port=5000)