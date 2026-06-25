import re
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerRegistry

# from presidio_analyzer.nlp_engine import NlpEngineProvider

# # Configurăm Presidio să folosească modelul "sm" (Lightweight pentru Render)
# configuration = {
#     "nlp_engine_name": "spacy",
#     "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
# }
# provider = NlpEngineProvider(nlp_configuration=configuration)
# # nlp_engine = provider.create_engine()
#
#
# # Inițializare motor Presidio cu motorul ușor
# presidio_engine = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])

# Presidio fără spaCy — mod Pattern-Only (lightweight pentru Render Free)
registry = RecognizerRegistry()
registry.load_predefined_recognizers()

# Augmentăm cu recunoscător custom CVV
cvv_recognizer = PatternRecognizer(
    supported_entity="CVV",
    patterns=[Pattern(name="cvv_pattern", regex=r"\b\d{3,4}\b", score=0.2)],
    context=["cvv", "cvv2", "security", "security_code", "check", "auth", "cvc"]
)
registry.add_recognizer(cvv_recognizer)

# Motor fără NLP engine — folosește doar pattern recognizers + Luhn intern
presidio_engine = AnalyzerEngine(registry=registry, supported_languages=["en"], nlp_engine=None)

# Augmentăm motorul cu un recunoscător custom pentru CVV-uri
cvv_recognizer = PatternRecognizer(
    supported_entity="CVV",
    patterns=[Pattern(name="cvv_pattern", regex=r"\b\d{3,4}\b", score=0.2)],
    context=["cvv", "cvv2", "security", "security_code", "check", "auth", "cvc"]
)
presidio_engine.registry.add_recognizer(cvv_recognizer)


def luhn_valid(number: str) -> bool:
    """Verifică dacă un număr respectă algoritmul matematic Luhn."""
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
    """Normalizează PAN-ul (fără liniuțe sau spații) pentru validare."""
    return pan.replace("-", "").replace(" ", "").strip()


def scan_with_presidio(text: str, chunk_size: int = 100000, overlap: int = 200) -> list:
    """
    Logica de producție: Analiză NLP Hibridă cu Sliding Window
    pentru evitarea epuizării resurselor pe artefacte masive.
    """
    if not text:
        return []

    found_pans_set = set()
    found_cvvs_set = set()

    # Procesăm în chunks pentru performanță (Sliding Window)
    for i in range(0, len(text), chunk_size - overlap):
        chunk = text[i: i + chunk_size]
        results = presidio_engine.analyze(
            text=chunk,
            entities=["CREDIT_CARD", "CVV"],
            language="en"
        )

        pans_in_chunk = [r for r in results if r.entity_type == "CREDIT_CARD" and r.score > 0.6]
        for r in pans_in_chunk:
            pan_str = normalize_pan(chunk[r.start:r.end])
            if luhn_valid(pan_str):  # Filtrarea matematică finală
                found_pans_set.add(pan_str)

        # Contextualizare: căutăm CVV doar în vecinătatea unui PAN găsit (RCA Window)
        if pans_in_chunk:
            cvvs_in_chunk = [r for r in results if r.entity_type == "CVV" and r.score > 0.5]
            for r in cvvs_in_chunk:
                found_cvvs_set.add(chunk[r.start:r.end])

    matches = []
    for pan in found_pans_set:
        matches.append(f"CRITICAL: Found Credit Card (PAN): {pan}")
    for cvv in found_cvvs_set:
        matches.append(f"WARNING: Found CVV/CVC: {cvv}")

    return matches


def add_custom_rule(entity: str, patterns: list, context: list):
    """Încarcă reguli definite de user direct în memoria Presidio."""
    presidio_patterns = [Pattern(name=f"{entity}_pattern_{i}", regex=p, score=0.5) for i, p in enumerate(patterns)]

    custom_recognizer = PatternRecognizer(
        supported_entity=entity,
        patterns=presidio_patterns,
        context=context
    )
    presidio_engine.registry.add_recognizer(custom_recognizer)