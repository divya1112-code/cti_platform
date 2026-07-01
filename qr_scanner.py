from pyzbar.pyzbar import decode
from PIL import Image

def scan_qr_code(image_path):
    try:
        img = Image.open(image_path)
        decoded = decode(img)
        if decoded:
            return decoded[0].data.decode("utf-8")
        img = img.convert("RGB")
        decoded = decode(img)
        if decoded:
            return decoded[0].data.decode("utf-8")
        img = img.convert("L")
        decoded = decode(img)
        if decoded:
            return decoded[0].data.decode("utf-8")
        return None
    except Exception as e:
        print(f"QR Error: {e}")
        return None
