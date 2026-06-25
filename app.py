from flask import Flask, request, jsonify
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
import boto3
import os
import json
import string

app = Flask(__name__)
presidio_engine = AnalyzerEngine()
RULES_FILE = 'custom_rules.json'

# --- CONFIGURARE CLOUDFLARE R2 ---
R2_ENDPOINT = os.getenv("R2_ENDPOINT", "https://<account_id>.r2.cloudflarestorage.com")
R2_ACCESS_KEY = os.getenv("R2_ACCESS_KEY", "cheia_ta")
R2_SECRET_KEY = os.getenv("R2_SECRET_KEY", "secretul_tau")
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "easypci-dumps")

s3_client = boto3.client(
    's3',
    endpoint_url=R2_ENDPOINT,
    aws_access_key_id=R2_ACCESS_KEY,
    aws_secret_access_key=R2_SECRET_KEY
)


def load_saved_rules():
    """Încarcă regulile la pornire, protejat la fișiere goale."""
    if os.path.exists(RULES_FILE) and os.path.getsize(RULES_FILE) > 0:
        try:
            with open(RULES_FILE, 'r') as f:
                rules = json.load(f)
                for rule in rules:
                    inject_rule_to_presidio(rule['entity'], rule['patterns'], rule['context'])
            print(f"[OK] Incarcat reguli custom.")
        except Exception as e:
            print(f"[ERROR] JSON invalid: {e}")


def inject_rule_to_presidio(entity, patterns, context):
    presidio_patterns = [Pattern(name=f"{entity}_pat_{i}", regex=p, score=0.8) for i, p in enumerate(patterns)]
    custom_recognizer = PatternRecognizer(supported_entity=entity, patterns=presidio_patterns, context=context)
    presidio_engine.registry.add_recognizer(custom_recognizer)


def extract_strings_from_binary(file_path, min_length=4):
    """Extrage caracterele printabile dintr-un coredump binar (simulează comanda 'strings')"""
    with open(file_path, 'rb') as f:
        data = f.read()
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


# --- RUTE API ---

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

    inject_rule_to_presidio(entity, patterns, context)

    saved_rules = []
    if os.path.exists(RULES_FILE) and os.path.getsize(RULES_FILE) > 0:
        with open(RULES_FILE, 'r') as f:
            saved_rules = json.load(f)

    saved_rules.append({"entity": entity, "patterns": patterns, "context": context})
    with open(RULES_FILE, 'w') as f:
        json.dump(saved_rules, f, indent=4)

    return jsonify({"message": "Regula salvata."}), 200


@app.route('/scan/modern', methods=['POST'])
def scan_modern():
    data = request.json
    text_to_scan = ""

    # Scenariul A: Apel venit din RunTest-ul tău original (Coredump via R2)
    if 'binary_file_name' in data:
        file_name = data['binary_file_name']
        local_file_path = f"/tmp/{file_name}"
        try:
            s3_client.download_file(R2_BUCKET_NAME, file_name, local_file_path)
            text_to_scan = extract_strings_from_binary(local_file_path)
        except Exception as e:
            return jsonify([f"[EROARE R2] Nu s-a putut procesa coredump-ul: {str(e)}"]), 500
        finally:
            if os.path.exists(local_file_path):
                os.remove(local_file_path)

    # Scenariul B: Apel venit din noua pagină de Log-uri text chior (Req 10)
    elif 'text' in data:
        text_to_scan = data['text']
    else:
        return jsonify(["[EROARE] Payload invalid."]), 400

    # Scanare cu Presidio AI
    results = presidio_engine.analyze(text=text_to_scan, language='en')
    alerts = []
    for res in results:
        alerts.append(f"[PCI DSS Alert] - Detectat {res.entity_type} (Scor: {res.score})")

    if not alerts:
        alerts.append("[OK] Nu au fost detectate date sensibile.")
    return jsonify(alerts), 200



@app.route('/dummy_route', methods=['GET'])
def get_rules():
    return jsonify({"rules": "dummy rules"}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

# from flask import Flask, request, jsonify
# from config import load_rules
# from blob_utils import download_blob_to_memory
# from pattern_matching import search_pattern_in_binary_content
# from Card import Card
# from pydantic import ValidationError

# app = Flask(__name__)

# @app.route('/analyze', methods=['POST'])
# def analyze():
#     try:
#         data = request.get_json()
#         card_data = data['cardData']
#         binary_file_name = data['binary_file_name']
#         card = Card(**card_data)
#     except ValidationError as e:
#         return jsonify(e.errors()), 400
#     except KeyError:
#         return jsonify({"error": "Invalid input"}), 400

#     rules, account_name, account_key, container_name = load_rules()

#     binary_file = download_blob_to_memory(account_name, account_key, container_name, binary_file_name)
#     binary_content = binary_file.read()

#     matches = search_pattern_in_binary_content(binary_content, rules, card)
    
#     if len(matches) == 0:
#         return jsonify(["No sensitive data found in the transaction!"]), 200
#     return jsonify(matches), 200

# @app.route('/dummy_route', methods=['GET'])
# def get_rules():
#     return jsonify({"rules": "dummy rules"}), 200

# if __name__ == '__main__':
#     app.run(debug=True)
