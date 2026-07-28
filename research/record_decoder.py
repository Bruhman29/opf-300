"""
Attendance kayit decode aracı (R701/FKAttend ailesi formatına göre).
OP-F300'den gercek 12-byte'lik kayit verisi elde edildiginde, bu formatin
uyup uymadigini test etmek icin kullanilabilir.
"""

def decode_record(record_bytes: bytes):
    if len(record_bytes) != 12:
        raise ValueError(f"Kayit 12 byte olmali, {len(record_bytes)} byte geldi")

    employee_id = int.from_bytes(record_bytes[4:8], "little")

    clock_bits = record_bytes[1] >> 6
    clock_map = {0: "1. Giris", 1: "1. Cikis", 2: "2. Giris", 3: "2. Cikis"}
    clock = clock_map[clock_bits]

    dt = int.from_bytes(record_bytes[8:12], "little")
    year = dt & 0x0FFF
    month = (dt >> 12) & 0x0F
    day = (dt >> 16) & 0x1F
    hour = (dt >> 21) & 0x1F
    minute = (dt >> 26) & 0x3F

    return {
        "employee_id": employee_id,
        "clock": clock,
        "year": year,
        "month": month,
        "day": day,
        "hour": hour,
        "minute": minute,
        "raw_bytes0_3": record_bytes[0:4].hex(' '),
    }


if __name__ == "__main__":
    # Blog'daki test verisiyle dogrulama
    test = bytes([0x10, 0x23, 0x0b, 0x1d, 0x01, 0, 0, 0, 0xb2, 0x17, 0x01, 0])
    result = decode_record(test)
    print("Test kaydi cozumu:")
    for k, v in result.items():
        print(f"  {k}: {v}")
    print("\nBeklenen: employee_id=1, clock=1. Giris, 1970-01-01 00:00")