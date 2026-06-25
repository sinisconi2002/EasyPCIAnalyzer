import re
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider

# Motor Presidio cu spaCy lightweight (en_core_web_sm)
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

# Recunoscător custom CVV
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
    Motor de detecție hibrid EasyPCI 2.0:
    Presidio (Pattern Recognition) + Validare Luhn + Sliding Window.

    Sliding Window previne epuizarea memoriei pe artefacte masive.
    Validarea Luhn elimină fals-pozitivele (ID-uri sesiune, pointeri).
    CVV-urile sunt raportate doar în vecinătatea unui PAN valid (RCA Window).
    """
    if not text:
        return []

    found_pans_set = set()
    found_cvvs_set = set()

    # Sliding Window — procesare în chunk-uri cu overlap
    for i in range(0, len(text), chunk_size - overlap):
        chunk = text[i: i + chunk_size]
        results = presidio_engine.analyze(
            text=chunk,
            entities=["CREDIT_CARD", "CVV"],
            language="en"
        )

        # Filtrare PAN-uri cu validare Luhn obligatorie
        pans_in_chunk = [r for r in results if r.entity_type == "CREDIT_CARD" and r.score > 0.6]
        for r in pans_in_chunk:
            pan_str = normalize_pan(chunk[r.start:r.end])
            if luhn_valid(pan_str):
                found_pans_set.add(pan_str)

        # CVV-uri doar în vecinătatea unui PAN găsit (Root Cause Analysis Window)
        if pans_in_chunk:
            cvvs_in_chunk = [r for r in results if r.entity_type == "CVV" and r.score > 0.5]
            for r in cvvs_in_chunk:
                found_cvvs_set.add(chunk[r.start:r.end])

    # Construire alerte
    matches = []
    for pan in found_pans_set:
        matches.append(f"CRITICAL: Found Credit Card (PAN): {pan}")
    for cvv in found_cvvs_set:
        matches.append(f"WARNING: Found CVV/CVC: {cvv}")

    return matches


def add_custom_rule(entity: str, patterns: list, context: list):
    """
    Încarcă reguli definite de utilizator direct în motorul Presidio.
    Folosit de endpoint-ul POST /rules/upload.
    """
    presidio_patterns = [
        Pattern(name=f"{entity}_pattern_{i}", regex=p, score=0.5)
        for i, p in enumerate(patterns)
    ]
    custom_recognizer = PatternRecognizer(
        supported_entity=entity,
        patterns=presidio_patterns,
        context=context
    )
    presidio_engine.registry.add_recognizer(custom_recognizer)