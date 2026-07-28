"""
OP-F300 - Sirali komut gonderici (Download Record akisi testi)
================================================================
Resmi yazilimin izledigi 52 -> 0B -> 0B -> 06 -> 07 sirasini,
ayni TCP baglantisi uzerinde, kisa araliklarla gonderir.
Her adimin GONDERILEN paketini ve gelen TUM cevaplarini
zaman damgasiyle hem ekrana hem de bir .log dosyasina yazar.
"""

import socket
import time
from datetime import datetime

IP = "192.168.0.224"
PORT = 5005

# Gonderilecek komutlar (checksum HARIC, 14 byte ham veri).
# Checksum program tarafindan otomatik hesaplanip eklenir.
COMMANDS = [
    ("52", "55aa010079195200000000000000"),
    ("06", "55aa010079190601000000000000"),
    ("cmd10", "55aa010079191001000000000000"),
    ("06", "55aa010079190601000000000000"),
    ("cmd11", "55aa010079191101000000000000"),
    ("06", "55aa010079190601000000000000"),
    ("cmd14", "55aa010079191401000000000000"),
    ("06", "55aa010079190601000000000000"),
    ("cmd15", "55aa010079191501000000000000"),
    ("06", "55aa010079190601000000000000"),
    ("cmd17", "55aa010079191701000000000000"),
    ("06", "55aa010079190601000000000000"),
    ("cmd18", "55aa010079191801000000000000"),
    ("06", "55aa010079190601000000000000"),
    ("cmd19", "55aa010079191901000000000000"),
    ("06", "55aa010079190601000000000000"),
    ("06-subcode00", "55aa010079190600000000000000"),
    ("06", "55aa010079190601000000000000"),
    ("06-subcode02", "55aa010079190602000000000000"),
    ("06", "55aa010079190601000000000000"),
    ("06-subcode03", "55aa010079190603000000000000"),
    ("06", "55aa010079190601000000000000"),
]

# Komutlar arasi bekleme suresi (saniye). Cihaz "calisiyor" yaziyorsa
# cok hizli gonderim sorun yaratabilir, bu yuzden varsayilan 1.0 sn.
DELAY_BETWEEN_COMMANDS = 1.0

# Her komuttan sonra cevap icin toplam bekleme suresi (saniye)
RECV_TIMEOUT = 2.0

# 07 (Download Record) icin ozel, daha uzun bekleme suresi.
# Son testte 07'ye sadece ACK gelip DATA paketi gelmeden baglanti
# kapanmis olabilir -- cihaz bu komutta daha yavas cevap veriyor olabilir.
RECV_TIMEOUT_07 = 8.0

# 07 onayindan sonra hicbir sey gondermeden pasif dinleme suresi (saniye).
# Cihaz onaydan sonra gercek veriyi kendiliginden gonderiyor olabilir.
PASSIVE_WAIT = 10.0


def calc_checksum(data: bytes) -> bytes:
    s = sum(data) & 0xFFFF
    return s.to_bytes(2, "little")


EXPECTED_DATA_LEN = 14  # tum bilinen komutlar bu uzunlukta (checksum haric)


def validate_commands():
    """Gondermeden once TUM komutlarin 14 byte oldugunu dogrular.
    Onceki bir hatada 52 ve 06 komutlari 13 byte olarak yazilmisti
    ve cihaz sessizce cevap vermemisti -- bu kontrol o hatayi
    calisma zamanindan once, hicbir sey gonderilmeden yakalar."""
    problems = []
    for name, hex_str in COMMANDS:
        if hex_str is None:
            continue  # pasif dinleme adimi, gonderilecek veri yok
        data = bytes.fromhex(hex_str)
        if len(data) != EXPECTED_DATA_LEN:
            problems.append(f"[{name}] {len(data)} byte (beklenen {EXPECTED_DATA_LEN}): {hex_str}")
    if problems:
        print("HATA: Asagidaki komutlarin uzunlugu yanlis, gonderim durduruldu:")
        for p in problems:
            print("  " + p)
        raise SystemExit(1)


def make_log_path() -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"OPF300_SEQ_{ts}.log"


def log_line(f, text: str):
    stamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{stamp}] {text}"
    print(line)
    f.write(line + "\n")
    f.flush()


def recv_all(sock, timeout: float, idle_gap: float = 1.5) -> tuple:
    """Belirtilen sure boyunca gelen tum veriyi toplar.
    Veri gelmeye basladiktan sonra `idle_gap` saniye sessizlik olursa
    erken cikar (hizli komutlari beklemeden bitirmek icin); hic veri
    gelmezse tam `timeout` suresi kadar bekler (gec cevaplari yakalamak icin).
    Donus: (veri, bağlantı_karsi_taraftan_kapandi_mi)"""
    sock.settimeout(0.2)
    end_time = time.time() + timeout
    chunks = []
    last_data_time = None
    closed = False
    while time.time() < end_time:
        try:
            r = sock.recv(4096)
            if not r:
                closed = True
                break
            chunks.append(r)
            last_data_time = time.time()
        except socket.timeout:
            if last_data_time is not None and (time.time() - last_data_time) >= idle_gap:
                break
            continue
        except Exception:
            break
    return b"".join(chunks), closed


def main():
    validate_commands()

    log_path = make_log_path()
    with open(log_path, "w", encoding="utf-8") as f:
        log_line(f, "=" * 60)
        log_line(f, f"OP-F300 SIRALI KOMUT TESTI  ({IP}:{PORT})")
        log_line(f, "=" * 60)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((IP, PORT))
            log_line(f, "Baglandi.")
        except Exception as e:
            log_line(f, f"BAGLANTI HATASI: {e}")
            return

        try:
            for name, hex_str in COMMANDS:
                if hex_str is None:
                    # Pasif dinleme adimi: hicbir sey gondermeden, cihazin
                    # kendiliginden veri gonderip gondermedigine bak.
                    log_line(f, "-" * 60)
                    log_line(f, f"[{name}] (gonderim yok, {PASSIVE_WAIT}sn pasif dinleniyor)")
                    resp, closed = recv_all(sock, PASSIVE_WAIT, idle_gap=PASSIVE_WAIT + 1)
                    if closed:
                        log_line(f, "UYARI: Cihaz baglantiyi kapatti (FIN alindi).")
                    if resp:
                        ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in resp)
                        log_line(f, f"CEVAP HEX   : {resp.hex(' ')}")
                        log_line(f, f"CEVAP ASCII : {ascii_repr}")
                        log_line(f, f"CEVAP BYTE  : {len(resp)}")
                    else:
                        log_line(f, "CEVAP YOK (pasif bekleme suresince veri gelmedi)")
                    time.sleep(DELAY_BETWEEN_COMMANDS)
                    continue

                data = bytes.fromhex(hex_str)
                pkt = data + calc_checksum(data)

                log_line(f, "-" * 60)
                log_line(f, f"GONDER [{name}]  {pkt.hex(' ')}")

                try:
                    sock.sendall(pkt)
                except Exception as e:
                    log_line(f, f"GONDERME HATASI: {e}")
                    break

                if name.startswith("07"):
                    # Erken cikisi kapat: ACK gelir gelmez durmasin,
                    # gecikmeli DATA paketini yakalamak icin tam sureyi bekle.
                    resp, closed = recv_all(sock, RECV_TIMEOUT_07, idle_gap=RECV_TIMEOUT_07 + 1)
                else:
                    resp, closed = recv_all(sock, RECV_TIMEOUT)

                if closed:
                    log_line(f, "UYARI: Cihaz baglantiyi kapatti (FIN alindi).")

                if resp:
                    ascii_repr = "".join(
                        chr(b) if 32 <= b <= 126 else "." for b in resp
                    )
                    log_line(f, f"CEVAP HEX   : {resp.hex(' ')}")
                    log_line(f, f"CEVAP ASCII : {ascii_repr}")
                    log_line(f, f"CEVAP BYTE  : {len(resp)}")
                else:
                    log_line(f, "CEVAP YOK (timeout)")

                time.sleep(DELAY_BETWEEN_COMMANDS)

        finally:
            sock.close()
            log_line(f, "-" * 60)
            log_line(f, "Baglanti kapandi.")
            log_line(f, f"Log dosyasi: {log_path}")


if __name__ == "__main__":
    main()
