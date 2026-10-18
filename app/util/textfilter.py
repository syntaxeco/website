
from app.util.badwords import BadWords, ExtendedBadWords

# Precomputed once at import; never mutate the shared BadWords global at runtime.
# Sorted longest-first so greedy replacement masks the longest match first.
_BASE_SORTED = sorted(set(BadWords), key=len, reverse=True)
_EXT_SORTED = sorted(set(BadWords) | set(ExtendedBadWords), key=len, reverse=True)

class TextNotAllowedException(Exception):
    pass

def FilterText( 
    Text : str,
    ReplaceWith : str = "#",
    ThrowException : bool = False,
    UseExtendedBadWords : bool = False
):
    # This is a very basic filter, but it works for now
    
    OriginalText = Text
    Text = Text.lower()

    WordList = _EXT_SORTED if UseExtendedBadWords else _BASE_SORTED

    for BadWord in WordList:
        if BadWord in Text:
            if ThrowException:
                raise TextNotAllowedException(f"Text contains a bad word, " + BadWord)
        Text = Text.replace(BadWord, ReplaceWith * len(BadWord))
    
    for i in range(len(OriginalText)):
        if OriginalText[i].isupper():
            Text = Text[:i] + Text[i].upper() + Text[i+1:]

    return Text

