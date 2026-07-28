import socket
import tkinter as tk
from tkinter import scrolledtext, messagebox

IP = "192.168.0.224"
PORT = 5005

sock = None
last_packet = b""

# Bilinen tüm istek paketlerinin ortak başlığı ve sabit uzunluğu.
# Şu ana kadar doğrulanmış TÜM komutlar (52,16,13,06,07,04,0C,0B ...)
# checksum HARİÇ tam olarak 14 byte veri taşıyor. Bu uzunluktan sapan
# bir paket -- özellikle eksik bir "00" byte'ı gibi checksum'ı
# etkilemeyen bir hata -- cihaza yanlış yorumlanmış komutlar
# gönderebilir (bir seferinde kullanıcı/kayıt verisinin silinmesine
# yol açmıştı). Bu yüzden göndermeden önce uzunluk kontrolü yapıyoruz.
KNOWN_HEADER = bytes.fromhex("55AA01007919")  # 55 AA 01 00 79 19  (ilk 6 byte header)
EXPECTED_DATA_LEN = 14  # checksum hariç, header dahil toplam veri uzunluğu


def calc_checksum(data):
    s = sum(data) & 0xFFFF
    return s.to_bytes(2, "little")


def log(text):
    out.insert(tk.END, text + "\n")
    out.see(tk.END)


def connect():
    global sock

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip.get(), int(port.get())))
        log("Bağlandı.")
    except Exception as e:
        messagebox.showerror("Hata", str(e))


def disconnect():
    global sock

    try:
        sock.close()
    except:
        pass

    sock = None
    log("Bağlantı kapandı.")


def send_packet():

    global last_packet

    if sock is None:
        return

    try:

        h = packet.get().replace(" ", "")

        data = bytes.fromhex(h)

        # GÜVENLİK KONTROLÜ: bilinen komut başlığıyla (55 AA 01 00 79 19)
        # başlayan paketler her zaman 14 byte veri taşımalı. Uzunluk
        # tutmuyorsa -- checksum yine de "doğru" görünse bile -- kullanıcıyı
        # açıkça uyar ve onay iste. Bu, eksik/hatalı bir byte'ın cihaza
        # yanlışlıkla yıkıcı bir komut olarak gitmesini engeller.
        if data[:6] == KNOWN_HEADER and len(data) != EXPECTED_DATA_LEN:
            ok = messagebox.askyesno(
                "Uzunluk uyarısı",
                "Bu paket %d byte veri içeriyor, bilinen komutlar ise "
                "her zaman %d byte olmalı.\n\n"
                "Checksum yanlış bir eksikliği (örn. bir '00' byte'ının "
                "silinmesi) yakalayamayabilir ve cihaza beklenmedik/yıkıcı "
                "bir komut gidebilir.\n\n"
                "Yine de göndermek istiyor musun?" % (len(data), EXPECTED_DATA_LEN),
            )
            if not ok:
                log("İptal edildi (uzunluk uyuşmazlığı: %d byte, beklenen %d byte)."
                    % (len(data), EXPECTED_DATA_LEN))
                return

        pkt = data + calc_checksum(data)

        last_packet = pkt

        log("")
        log("=" * 60)
        log("GÖNDER")
        log(pkt.hex(" "))

        sock.sendall(pkt)

        while True:

            try:

                r = sock.recv(4096)

                if not r:
                    break

                log("")
                log("HEX")
                log(r.hex(" "))

                asc = "".join(chr(x) if 32 <= x <= 126 else "." for x in r)

                log("")
                log("ASCII")
                log(asc)

                log("")
                log("BYTE : %d" % len(r))

                if len(r) < 4096:
                    break

            except socket.timeout:
                break

    except Exception as e:
        log(str(e))


def resend():

    global last_packet

    if sock is None:
        return

    if last_packet == b"":
        return

    sock.sendall(last_packet)
    log("\nTEKRAR GÖNDERİLDİ\n")


def mutate():

    h = packet.get().replace(" ", "")

    try:

        b = bytearray.fromhex(h)

    except:
        return

    idx = int(index.get(), 16)
    val = int(value.get(), 16)

    if idx >= len(b):
        return

    b[idx] = val

    packet.delete(0, tk.END)
    packet.insert(0, b.hex())


root = tk.Tk()
root.title("OP-F300 Explorer")
root.geometry("900x650")

f = tk.Frame(root)
f.pack(fill="x")

tk.Label(f, text="IP").grid(row=0, column=0)
ip = tk.Entry(f, width=15)
ip.insert(0, IP)
ip.grid(row=0, column=1)

tk.Label(f, text="Port").grid(row=0, column=2)
port = tk.Entry(f, width=6)
port.insert(0, str(PORT))
port.grid(row=0, column=3)

tk.Button(f, text="Bağlan", command=connect).grid(row=0, column=4)
tk.Button(f, text="Kes", command=disconnect).grid(row=0, column=5)

packet = tk.Entry(root, font=("Consolas", 12))
packet.pack(fill="x", padx=5, pady=5)

tk.Button(root, text="Gönder", command=send_packet).pack(fill="x")
tk.Button(root, text="Son Paketi Tekrar Gönder", command=resend).pack(fill="x")

m = tk.Frame(root)
m.pack(fill="x")

tk.Label(m, text="Byte").grid(row=0, column=0)
index = tk.Entry(m, width=5)
index.insert(0, "06")
index.grid(row=0, column=1)

tk.Label(m, text="Yeni").grid(row=0, column=2)
value = tk.Entry(m, width=5)
value.insert(0, "07")
value.grid(row=0, column=3)

tk.Button(m, text="Byte Değiştir", command=mutate).grid(row=0, column=4)

out = scrolledtext.ScrolledText(root, font=("Consolas", 10))
out.pack(fill="both", expand=True)

root.mainloop()