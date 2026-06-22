from flask import Flask, request, jsonify
from config import load_rules
from blob_utils import download_blob_to_memory
from pattern_matching import search_pattern_in_binary_content
from Card import Card
from pydantic import ValidationError

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        card_data = data['cardData']
        binary_file_name = data['binary_file_name']
        card = Card(**card_data)
    except ValidationError as e:
        return jsonify(e.errors()), 400
    except KeyError:
        return jsonify({"error": "Invalid input"}), 400

    rules, account_name, account_key, container_name = load_rules()

    binary_file = download_blob_to_memory(account_name, account_key, container_name, binary_file_name)
    binary_content = binary_file.read()

    matches = search_pattern_in_binary_content(binary_content, rules, card)
    
    if len(matches) == 0:
        return jsonify(["No sensitive data found in the transaction!"]), 200
    return jsonify(matches), 200

@app.route('/dummy_route', methods=['GET'])
def get_rules():
    return jsonify({"rules": "dummy rules"}), 200

if __name__ == '__main__':
    app.run(debug=True)
