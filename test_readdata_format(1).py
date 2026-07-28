"""
OP-F300 - FV_ReadDataFromFK format testi (checksum'suz paket)
================================================================
FUN_10005450'nin kaynak kodundan cikarilan YENI ve FARKLI paket
formatini test eder. Bu, FV_SendCommandToFK'nin checksum'li
formatindan TAMAMEN farkli -- bu format checksum ICERMIYOR.

Paket (16 byte, sabit):
  offset 0-1  : 55 AA               (header)
  offset 2    : cmd1                (Machine ID, genelde 1)
  offset 3    : cmd2                (0xA4 = All Record, 0xA1 = New Record)
  offset 4-7  : param3              (genelde 0)
  offset 8-9  : devam/continuation token (ilk cagride 0)
  offset 10-11: blok numarasi       (ilk cagride 0, sonraki cagrilarda +1)
  offset 12-13: istenen veri boyutu (kac byte istiyoruz)
  offset 14-15: ic sequence sayaci  (1'den baslar, biz sabit 1 kullaniyoruz)

Kullanim:
    python3 test_readdata_format.py
"""

import socket
import struct
import time

IP = "192.168.0.224"
PORT = 5005


def build_packet(cmd1, cmd2, continuation, block_no, chunk_size, seq):
    pkt = struct.pack('<BBBB', 0x55, 0xAA, cmd1, cmd2)
    pkt += struct.pack('<I', 0)  # param3, genelde 0
    pkt += struct.pack('<HH', continuation, block_no)
    pkt += struct.pack('<HH', chunk_size, seq)
    return pkt


def recv_patient(sock, timeout=8.0, idle_gap=2.0):
    sock.settimeout(0.2)
    end_time = time.time() + timeout
    chunks = []
    last_data = None
    while time.time() < end_time:
        try:
            r = sock.recv(65536)
            if not r:
                print("  (baglanti kapandi - FIN)")
                break
            chunks.append(r)
            last_data = time.time()
            print(f"  [parca alindi: {len(r)} byte]")
        except socket.timeout:
            if last_data is not None and (time.time() - last_data) >= idle_gap:
                break
            continue
    return b"".join(chunks)


def calc_checksum(data: bytes) -> bytes:
    s = sum(data) & 0xFFFF
    return s.to_bytes(2, "little")


def main():
    print(f"Baglaniliyor: {IP}:{PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((IP, PORT))
    print("Baglandi.\n")

    # ---- Once standart "52" (kimlik) - checksum'li eski format ----
    kimlik = bytes.fromhex("55aa010079195200000000000000")
    kimlik_pkt = kimlik + calc_checksum(kimlik)
    print("GONDER [52 - kimlik, standart format]:")
    print(" ", kimlik_pkt.hex(' '))
    sock.sendall(kimlik_pkt)
    resp0 = recv_patient(sock, timeout=3, idle_gap=1)
    print(f"  CEVAP: {resp0.hex(' ') if resp0 else '(yok)'}\n")

    # ---- Test A: continuation=0 ----
    pkt = build_packet(cmd1=1, cmd2=0xA4, continuation=0, block_no=0, chunk_size=0x1000, seq=1)
    print("GONDER (cmd2=0xA4, continuation=0, blok=0):")
    print(" ", pkt.hex(' '))
    sock.sendall(pkt)
    resp = recv_patient(sock)
    print(f"TOPLAM CEVAP: {len(resp)} byte")
    if resp:
        print(" ", resp.hex(' '))
        print(" ", ''.join(chr(b) if 32 <= b <= 126 else '.' for b in resp))
    else:
        print("  (hic cevap gelmedi)")

    # ---- Test B: continuation=9 (bilinen hareket sayisi) ----
    print("\n---\n")
    pkt2 = build_packet(cmd1=1, cmd2=0xA4, continuation=9, block_no=0, chunk_size=0x1000, seq=1)
    print("GONDER (cmd2=0xA4, continuation=9, blok=0):")
    print(" ", pkt2.hex(' '))
    sock.sendall(pkt2)
    resp2 = recv_patient(sock)
    print(f"TOPLAM CEVAP: {len(resp2)} byte")
    if resp2:
        print(" ", resp2.hex(' '))
        print(" ", ''.join(chr(b) if 32 <= b <= 126 else '.' for b in resp2))
    else:
        print("  (hic cevap gelmedi)")

    sock.close()
    print("\nBaglanti kapatildi.")


if __name__ == "__main__":
    main()
