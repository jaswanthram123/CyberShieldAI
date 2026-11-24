
import re


def extract_message_indicators(message: str) -> list[str]:

    indicators = []

    text = message.lower()

    # Urgency-related language
    if re.search(
        r"\b(urgent|immediately|act now|within 24 hours)\b",
        text
    ):
        indicators.append(
            "Message contains urgency-related language"
        )

    # Requests for credentials
    if re.search(
        r"\b(password|otp|pin|verification code)\b",
        text
    ):
        indicators.append(
            "Message mentions passwords, OTPs or other credentials"
        )

    # Threats involving accounts
    if re.search(
        r"\b(blocked|suspended|locked|terminated)\b",
        text
    ):
        indicators.append(
            "Message contains account restriction language"
        )

    # URLs
    if re.search(
        r"https?://[^\s]+",
        message,
        flags=re.IGNORECASE
    ):
        indicators.append(
            "Message contains a URL"
        )

    # Requests for sensitive information
    if re.search(
        r"\b(bank details|card number|cvv)\b",
        text
    ):
        indicators.append(
            "Message mentions sensitive financial information"
        )

    return indicators[:10]
