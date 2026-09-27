import hashlib
from pathlib import PurePath

EXECUTABLE = {'.apk','.exe','.js','.vbs','.bat','.cmd','.ps1','.scr','.com','.msi'}
CONTAINERS = {'.zip','.rar','.iso','.7z','.doc','.docx','.xls','.xlsx','.docm','.xlsm','.pdf','.ppt','.pptx'}
def analyze_attachments(items):
    result = []
    for item in items:
        ext = PurePath(item['filename']).suffix.lower()
        suffixes = [x.lower() for x in PurePath(item['filename']).suffixes]
        signals = []
        if ext in EXECUTABLE: signals.append('Potentially executable attachment')
        elif ext in CONTAINERS: signals.append('Document or archive requires further inspection')
        if len(suffixes)>1 and ext in EXECUTABLE and any(s in CONTAINERS for s in suffixes[:-1]): signals.append('Misleading double extension')
        data = item['data']
        if data.startswith(b'MZ') and ext not in EXECUTABLE: signals.append('Executable signature inconsistent with extension')
        result.append({'filename':item['filename'],'extension':ext,'mime_type':item['mime_type'],'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'signals':signals,'verdict':'Requires review' if signals else 'No static type warning','limitation':'Static metadata only; no execution, archive extraction, or malware verdict.'})
    return result
