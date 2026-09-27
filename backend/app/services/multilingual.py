"""Auditable language-rule coverage; no claim of a multilingual trained model."""
import re

RULES = [
 ('Urgency', r'तुरंत|तत्काल|जल्दी|अभी|turant|jaldi|abhi|உடனே|உடனடியாக|వెంటనే|తక్షణమే|এখনই|অবিলম্বে|તરત|તાત્કાલિક|ತಕ್ಷಣ|ഉടൻ|ਤੁਰੰਤ', 3),
 ('Credential request', r'पासवर्ड|पासवर्ड बताओ|पासवर्ड भेज|password\s*(?:bhej|bata|do)|கடவுச்சொல்|పాస్‌వర్డ్|পাসওয়ার্ড|પાસવર્ડ|ಪಾಸ್.?ವರ್ಡ್|പാസ്‌വേഡ്|ਪਾਸਵਰਡ', 7),
 ('OTP request', r'ओटीपी|ओ टी पी|otp\s*(?:bhej|bata|do|share)|ஓடிபி|ఓటీపీ|ওটিপি|ઓટીપી|ಒಟಿಪಿ|ഒടിപി|ਓਟੀਪੀ', 8),
 ('Payment instructions', r'पैसे भेज|पैसे ट्रांसफर|रकम भेज|पैसे पाठवा|paise\s*(?:bhej|transfer)|paisa\s*bhej|பணம் அனுப்பு|డబ్బు పంప|টাকা পাঠা|પૈસા મોકલ|ಹಣ ಕಳುಹಿ|പണം അയ|ਪੈਸੇ ਭੇਜ', 6),
 ('Account suspension', r'खाता बंद|अकाउंट बंद|खाता निलंबित|account\s*band|கணக்கு முடக்க|ఖాతా నిలిపి|অ্যাকাউন্ট বন্ধ|ખાતું બંધ|ಖಾತೆ ಸ್ಥಗಿತ', 5),
]
NEGATION = r'कभी.*(?:न.*(?:भेज|बत|साझा)|मत)|मत (?:भेज|बत|साझा)|(?:share|bhej|bata).*mat|kabhi.*(?:nahi|mat)|பகிர வேண்டாம்|పంచుకోవద్దు|শেয়ার করবেন না'
SCRIPTS = {'Devanagari':r'[\u0900-\u097f]','Bengali':r'[\u0980-\u09ff]','Gurmukhi':r'[\u0a00-\u0a7f]','Gujarati':r'[\u0a80-\u0aff]','Tamil':r'[\u0b80-\u0bff]','Telugu':r'[\u0c00-\u0c7f]','Kannada':r'[\u0c80-\u0cff]','Malayalam':r'[\u0d00-\u0d7f]','Odia':r'[\u0b00-\u0b7f]'}

def inspect(text):
    scripts=[name for name,pattern in SCRIPTS.items() if re.search(pattern,text)]
    sentences=re.split(r'(?<=[.!?।])\s*|\n+',text)
    signals=[]
    for name,pattern,weight in RULES:
        quotes=[s[:500] for s in sentences if re.search(pattern,s,re.I) and not re.search(NEGATION,s,re.I)][:3]
        if quotes: signals.append({'signal':name,'weight':weight,'evidence':quotes,'source':'multilingual security rules'})
    hinglish=bool(re.search(r'\b(jaldi|turant|paise|bhejo|batao|karo)\b',text,re.I))
    return signals, {'scripts':scripts,'hinglish_signals':hinglish,'coverage':'Limited phrase rules for Hindi/Hinglish and selected Indian scripts; English model probability is not validated for these languages.' if scripts or hinglish else 'English classifier and security rules; language not independently verified.', 'model_applicable':not scripts and not hinglish}
