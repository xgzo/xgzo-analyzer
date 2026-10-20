import os
import sys
import webview
from api import API

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

if __name__ == '__main__':
    api = API()
    
    # Get absolute path to index.html
    html_file = resource_path('ui/index.html')
    
    # Format as a proper local file URL (fixes the 404)
    html_url = f'file:///{html_file.replace(os.sep, "/")}'
    
    window = webview.create_window(
        'xgzo analyzer // soc', 
        html_url, 
        js_api=api,
        width=1440, 
        height=900,
        background_color='#0a0a0c'
    )
    webview.start()