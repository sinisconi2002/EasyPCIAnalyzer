import re
from Card import Card

def build_pattern(pattern, card: Card):
    return pattern.format(
        cardNumber=card.CardNumber,
        expirationDate=card.ExpirationDate,
        CVV=card.CVVCode,
        cardNetwork=card.CardType,
        cardHolder=card.CardHolder,
        currency="USD",
        operation_code="BINQ",  
        prefix=card.CardNumber[:6]
    ).encode()

def search_pattern_in_binary_content(binary_content, patterns, card: Card):
    results = []
    for key in patterns:
        pattern = build_pattern(patterns[key], card)
        print(f"Trying pattern: {pattern.decode('utf-8', 'ignore')}")
        compiled_pattern = re.compile(pattern, re.DOTALL)

        match = compiled_pattern.search(binary_content)
        if match:
            results.append("Sensitive data found in " + key + " level")

    return results
