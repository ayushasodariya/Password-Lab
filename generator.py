from __future__ import annotations

import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

# Simple word list for memorable phrases. These are not guaranteed to be uniformly
# selected from a large audited dictionary; use random passwords for maximum control.
PASSPHRASE_WORDS = """
amber anchor apple arch arrow artist atlas autumn bamboo beacon berry birch blossom
blue breeze brook cabin cactus candle canyon canvas cedar cherry cloud clover coast
comet copper coral cosmos cricket crystal dawn delta desert diamond dune eagle earth
echo ember emerald evening falcon fern field finch flame forest fossil fox galaxy garden
garlic gentle glacier glow golden granite harbor hazel heart hill honey horizon island
ivory jade jasmine juniper kettle kiwi lagoon lantern lemon lilac linen lotus lunar maple
marble meadow melon memory mercury midnight mint mirror mist moon moss mountain nectar
ocean olive onyx orbit orchid otter oyster panda paper pebble pepper phoenix piano pine
planet plum pocket poetry pollen pond poppy prism pumpkin quartz quiet rabbit radar rain
raven river robin rocket saffron sage sailor salmon satin scarlet season shadow shell
silver sky slate snow solar sparrow spirit spruce star stone storm sugar summer sunset
teal thistle thunder timber toast tomato topaz tulip valley velvet violet walnut water
willow window winter wonderwood yellow zephyr zipper
""".split()


def generate_password(length: int = 20, uppercase: bool = True, lowercase: bool = True,
                      digits: bool = True, symbols: bool = True,
                      exclude_ambiguous: bool = False) -> str:
    """Generate a secure random password, guaranteeing each enabled group is present."""
    if not 8 <= length <= 128:
        raise ValueError("Password length must be between 8 and 128 characters.")
    groups = []
    if lowercase:
        groups.append(string.ascii_lowercase)
    if uppercase:
        groups.append(string.ascii_uppercase)
    if digits:
        groups.append(string.digits)
    if symbols:
        groups.append(SYMBOLS)
    if not groups:
        raise ValueError("Enable at least one character group.")
    if len(groups) > length:
        raise ValueError("Password length is too short for the selected groups.")

    if exclude_ambiguous:
        ambiguous = set("O0oIl1|`'\"{}[]()")
        groups = ["".join(ch for ch in group if ch not in ambiguous) for group in groups]
        groups = [group for group in groups if group]
        if not groups:
            raise ValueError("No characters remain after excluding ambiguous characters.")

    alphabet = "".join(groups)
    chars = [secrets.choice(group) for group in groups]
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(word_count: int = 5, separator: str = "-",
                        add_number: bool = True, capitalize: bool = False) -> str:
    """Generate a memorable phrase from randomly selected words."""
    if not 3 <= word_count <= 10:
        raise ValueError("Choose between 3 and 10 words.")
    words = [secrets.choice(PASSPHRASE_WORDS) for _ in range(word_count)]
    if capitalize:
        words = [word.capitalize() for word in words]
    phrase = separator.join(words)
    if add_number:
        phrase += separator + str(secrets.randbelow(90) + 10)
    return phrase
