import re
from Card import Card

def build_pattern(pattern, card: Card):
    """Build a regex pattern from the config file pattern."""
    return pattern.format(
        cardNumber=card.CardNumber,
        expirationDate=card.ExpirationDate,
        CVV=card.CVVCode,
        cardNetwork=card.CardType,
        cardHolder=card.CardHolder,
        currency="USD",  # Use example or dynamic values as required
        operation_code="BINQ",  # Use example or dynamic values as required
        prefix="37000"  # Use example or dynamic values as required
    ).encode()

def search_pattern_in_binary_content(binary_content, patterns, card: Card):
    results = []
    for key in patterns:
        pattern = build_pattern(patterns[key], card)
        print(f"Trying pattern: {pattern.decode('utf-8', 'ignore')}")  # Debug statement to show pattern as string
        compiled_pattern = re.compile(pattern, re.DOTALL)

        match = compiled_pattern.search(binary_content)
        if match:
            print(f"Match found for pattern: {pattern.decode('utf-8', 'ignore')}")  # Debug statement for match
            results.append(key)
        else:
            print(f"No match for pattern: {pattern.decode('utf-8', 'ignore')}")  # Debug statement if no match

    return results
