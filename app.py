import os
from flask import Flask, request, jsonify
from config import load_rules
from blob_utils import download_blob_to_memory
from pattern_matching import search_pattern_in_binary_content
from Card import Card
from pydantic import ValidationError
from analyzer_engine import scan_with_presidio, add_custom_rule

app = Flask(__name__)


# Endpoint-ul original: Regex (EasyPCI 1.0)
@app.route('/scan/classic', methods=['POST'])
def analyze_classic():
    try:
        data = request.get_json()
        card_data = data.get('cardData', {})
        binary_file_name = data.get('binary_file_name')
        card = Card(**card_data)
    except ValidationError as e:
        return jsonify(e.errors()), 400
    except KeyError:
        return jsonify({"error": "Invalid input"}), 400

    rules, _, _, _ = load_rules()

    bucket = os.getenv('R2_BUCKET_NAME')
    binary_file = download_blob_to_memory(bucket, binary_file_name)
    binary_content = binary_file.read()

    matches = search_pattern_in_binary_content(binary_content, rules, card)

    if len(matches) == 0:
        return jsonify(["No sensitive data found in the transaction!"]), 200
    return jsonify(matches), 200


# Endpoint-ul nou: Presidio + Luhn + Sliding Window (EasyPCI 2.0)
@app.route('/scan/modern', methods=['POST'])
def analyze_modern():
    data = request.get_json()
    content = None
    is_cleartext_log = False

    # Ingestie Artefact (Core Dump binar din R2)
    if 'binary_file_name' in data:
        bucket = os.getenv('R2_BUCKET_NAME')
        binary_file = download_blob_to_memory(bucket, data['binary_file_name'])
        content = binary_file.read().decode('utf-8', errors='ignore')

    # Ingestie Jurnale Cleartext (Log audit)
    elif 'text' in data:
        content = data['text']
        is_cleartext_log = True
    else:
        return jsonify({"error": "No binary_file_name or text provided"}), 400

    # Scanarea prin motorul AI
    results = scan_with_presidio(content)

    if len(results) == 0:
        return jsonify(["No sensitive data found in the transaction/dump!"]), 200

    # Cerința 10 PCI DSS (Avertizare specifică pentru Cleartext Logging)
    if is_cleartext_log:
        results.insert(0, "PCI DSS Requirement 10 Violation: Cleartext Logging Detected!")

    return jsonify(results), 200


# Endpoint pentru injectare de reguli customizate
@app.route('/rules/upload', methods=['POST'])
def upload_rules():
    data = request.get_json()

    entity = data.get("entity")
    patterns = data.get("patterns", [])
    context = data.get("context", [])

    if not entity or not patterns:
        return jsonify({"error": "Entity and patterns are required!"}), 400

    # Adăugare dinamică în motorul NLP
    add_custom_rule(entity, patterns, context)

    return jsonify({"status": "Success", "message": f"Added custom rule for {entity}"}), 200


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
