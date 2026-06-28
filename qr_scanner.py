from pyzbar.pyzbar import decode
from PIL import Image

def scan_qr_code(image_path):
    try:
        img = Image.open(image_path)
        decoded = decode(img)
        if decoded:
            qr_data = decoded[0].data.decode("utf-8")
            return qr_data
        else:
            return None
    except Exception as e:
        return None
