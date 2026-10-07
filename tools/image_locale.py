"""Image metadata drives localized resource paths; tool messages stay English."""
import re
def image_languages(windows):
    values=[e.text for e in windows.findall('LANGUAGES/LANGUAGE') if e.text]
    primary=windows.findtext('LANGUAGES/DEFAULT') or (values[0] if values else '')
    if not re.fullmatch(r'[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})+',primary):raise RuntimeError('Invalid/missing image language')
    if primary not in values:values.insert(0,primary)
    return primary,values
def localized_path(path,language):return path.replace('ru-RU',language)
def resource_file(path):return path.lower().endswith(('.mui','.pri','.mun','.msstyles','.png','.bmp','.ttf','.ico','.xml'))
