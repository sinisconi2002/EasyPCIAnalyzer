import re
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider

configuration = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
}
provider = NlpEngineProvider(nlp_configuration=configuration)
nlp_engine = provider.create_engine()

presidio_engine = AnalyzerEngine(
    nlp_engine=nlp_engine,
    supported_languages=["en"]
)

# Recunoscător custom CVV (Baseline)
cvv_recognizer = PatternRecognizer(
    supported_entity="CVV",
    name="Baseline_CVV_Rule",
    patterns=[Pattern(name="cvv_pattern", regex=r"\b\d{3,4}\b", score=0.2)],
    context=["cvv", "cvv2", "security", "security_code", "check", "auth", "cvc"]
)
presidio_engine.registry.add_recognizer(cvv_recognizer)


def luhn_valid(number: str) -> bool:
    try:
        digits = [int(d) for d in str(number)]
    except ValueError:
        return False
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


def normalize_pan(pan: str) -> str:
    return pan.replace("-", "").replace(" ", "").strip()


def extract_rule_from_cpp(cpp_code: str):
    class_match = re.search(r'(?:class|struct)\s+([A-Za-z0-9_]+)', cpp_code)
    if not class_match:
        raise ValueError("Nu s-a găsit nicio clasă sau structură validă în fișierul C++.")

    class_name = class_match.group(1)

    member_vars = re.findall(
        r'\b(?:std::)?(?:string|int|double|char|bool|float|long)\s*\*?\s*'
        r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[;,=)]',
        cpp_code
    )

    all_identifiers = set(re.findall(r'\b([a-z][a-zA-Z0-9_]{2,})\b', cpp_code))

    cpp_keywords = {
        'std', 'string', 'int', 'double', 'char', 'bool', 'float', 'long',
        'void', 'public', 'private', 'protected', 'class', 'struct', 'return',
        'const', 'static', 'include', 'using', 'namespace', 'this', 'new', 'delete'
    }

    context_words = set(member_vars) | all_identifiers
    context_words = [w for w in context_words if w not in cpp_keywords]
    context_words = [class_name] + sorted(context_words)

    rule_name = f"StructLeak_{class_name}"

    return rule_name, context_words


def add_custom_rule(rule_name: str, entity: str, patterns: list, context: list):
    presidio_patterns = [
        Pattern(name=f"{rule_name}_pattern_{i}", regex=p, score=0.6)
        for i, p in enumerate(patterns)
    ]
    custom_recognizer = PatternRecognizer(
        supported_entity=entity,
        name=rule_name,
        patterns=presidio_patterns,
        context=context
    )
    presidio_engine.registry.add_recognizer(custom_recognizer)


def add_rule_from_cpp(cpp_code: str, entity: str = "STRUCT_LEAK"):

    rule_name, context_words = extract_rule_from_cpp(cpp_code)

    pan_pattern = Pattern(name=f"{rule_name}_pan", regex=r"\b\d{13,19}\b", score=0.3)

    recognizer = PatternRecognizer(
        supported_entity=entity,
        name=rule_name,
        patterns=[pan_pattern],
        context=context_words
    )
    presidio_engine.registry.add_recognizer(recognizer)

    return rule_name, context_words


def scan_coredump(text: str, chunk_size: int = 100000, overlap: int = 200) -> list:
    if not text:
        return []

    found_pans = {}
    found_cvvs = {}

    for i in range(0, len(text), chunk_size - overlap):
        chunk = text[i: i + chunk_size]
        results = presidio_engine.analyze(
            text=chunk,
            entities=["CREDIT_CARD", "CVV", "STRUCT_LEAK"],
            language="en",
            return_decision_process=True
        )

        pans_in_chunk = [r for r in results if r.entity_type in ("CREDIT_CARD", "STRUCT_LEAK") and r.score > 0.4]
        for r in pans_in_chunk:
            pan_str = normalize_pan(chunk[r.start:r.end])
            if luhn_valid(pan_str):
                rule_triggered = "Default_Model"
                if r.analysis_explanation and r.analysis_explanation.recognizer_name:
                    rule_triggered = r.analysis_explanation.recognizer_name
                found_pans[pan_str] = rule_triggered

        if pans_in_chunk:
            cvvs_in_chunk = [r for r in results if r.entity_type == "CVV" and r.score > 0.4]
            for r in cvvs_in_chunk:
                cvv_str = chunk[r.start:r.end]
                rule_triggered = "Default_Model"
                if r.analysis_explanation and r.analysis_explanation.recognizer_name:
                    rule_triggered = r.analysis_explanation.recognizer_name
                found_cvvs[cvv_str] = rule_triggered

    matches = []
    for pan, rule in found_pans.items():
        matches.append(f"CRITICAL [COREDUMP]: Found PAN linked to context [{rule}] -> {pan}")
    for cvv, rule in found_cvvs.items():
        matches.append(f"WARNING [COREDUMP]: Found CVV/CVC linked to context [{rule}] -> {cvv}")

    return matches

def scan_logs(text: str) -> list:
    if not text:
        return []

    results = presidio_engine.analyze(
        text=text,
        entities=["CREDIT_CARD", "EMAIL_ADDRESS", "IP_ADDRESS"],
        language="en"
    )

    matches = []
    for r in results:
        if r.score >= 0.5:
            found_value = text[r.start:r.end]
            matches.append(f"ALERTĂ LOG: Detectat {r.entity_type} -> {found_value}")

    return list(set(matches))