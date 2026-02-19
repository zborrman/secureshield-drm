import hashlib

def generate_user_fingerprint(owner_id: str) -> int:
    """
    Создает уникальное 32-битное число на основе ID сотрудника.
    Это число будет использоваться Wasm для Invisible Tracing.
    """
    hash_obj = hashlib.sha256(owner_id.encode())
    # Берем первые 4 байта хеша и превращаем в integer
    return int.from_bytes(hash_obj.digest()[:4], byteorder='big')
