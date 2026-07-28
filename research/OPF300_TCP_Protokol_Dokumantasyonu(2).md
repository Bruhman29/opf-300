# OP-F300 TCP Protokolü — Tersine Mühendislik Dokümantasyonu

**Cihaz:** OP-F300 (parmak izi tabanlı yoklama/erişim cihazı)
**Bağlantı:** TCP/IP, port `5005`
**Durum:** Protokol büyük ölçüde çözüldü. **Bulk kayıt indirme TCP üzerinden bulunamadı — USB export önerilen/kanıtlanmış yöntemdir.**

---

## 1. Paket Yapısı

### 1.1 İstek formatı (PC → Cihaz)

```
55 AA 01 00 79 19 [CMD] [SUBCODE] [PARAM: 4 byte] [ALAN: 2 byte] [CHECKSUM: 2 byte]
```

| Offset | Uzunluk | Alan | Açıklama |
|---|---|---|---|
| 0-1 | 2 | Header | Sabit `55 AA` |
| 2 | 1 | cmd1 | Her zaman `01` |
| 3 | 1 | cmd2 | Her zaman `00` |
| 4-5 | 2 | Sabit imza | Her zaman `79 19` |
| 6 | 1 | **CMD** | Gerçek komut byte'ı (bkz. §3) |
| 7 | 1 | SUBCODE | Genelde `01` |
| 8-11 | 4 | PARAM | Komuta göre değişen parametre (index, sayı, filtre vb.) |
| 12-13 | 2 | ALAN | İkincil parametre / blok index'i (genelde `00 00`) |
| 14-15 | 2 | Checksum | §2'ye bakınız |

Toplam paket uzunluğu **her zaman 16 byte** (checksum dahil).

### 1.2 Cevap paketleri

| Header | Anlam | Tipik uzunluk |
|---|---|---|
| `5A A5` | ACK | 8 byte |
| `AA 55` | DATA (birincil cevap) | 14 byte |
| `A5 5A` | İkincil veri paketi | 10 byte (bazen daha uzun, örn. 103 byte — bkz. §3) |

Standart `AA 55` DATA paketi formatı:
```
AA 55 01 00 00 00 [STATUS: 2 byte] [DEĞER: 4 byte] [CHECKSUM: 2 byte]
```
`STATUS = 01 00` → başarılı, `STATUS = 00 00` → boş/geçersiz/desteklenmiyor.

### 1.3 Kaynak koddan doğrulanan gerçek paket inşası

`FKViaDev.dll` içindeki `FUN_10006390` fonksiyonunun decompile çıktısı incelenerek paket inşa mantığı **kaynak kod seviyesinde** doğrulandı:

```c
void FUN_10006390(void *this, byte cmd1, byte cmd2, uint param, ushort field1, ushort field2, ushort field3)
```

- `cmd1`, `cmd2` → her zaman `1, 0` (bizim gördüğümüz sabit değerler)
- `param` (4 byte) → içinde `79 19 [CMD] [SUBCODE]` kodlanmış:
  ```
  data = (SUBCODE << 24) | (CMD << 16) | 0x1979
  ```
- Checksum, `+0xFF` sabitiyle başlıyor — bu tam olarak `0x55 + 0xAA` toplamı, yani bizim ampirik bulduğumuz "tüm byte'ların toplamı" formülüyle **matematiksel olarak birebir aynı**.

---

## 2. Checksum

**Formül:**
```
checksum = (paketteki checksum hariç tüm byte'ların toplamı) & 0xFFFF, little-endian 2 byte
```

Python:
```python
def calc_checksum(data: bytes) -> bytes:
    s = sum(data) & 0xFFFF
    return s.to_bytes(2, "little")
```

- CRC16 (Modbus/IBM/CCITT) **değildir**.
- Hem onlarca gerçek paket üzerinde ampirik olarak doğrulandı, hem de `FUN_10006390`'ın decompile edilmiş kaynak kodundan **matematiksel olarak** teyit edildi.
- ⚠️ **Önemli güvenlik notu:** Bu checksum, eksik bir `0x00` byte'ının paketten çıkarılmasını YAKALAMAZ (toplam değişmez). Bu yüzden gönderilecek her paketin **uzunluğu ayrıca kontrol edilmelidir** (bkz. §5).

---

## 3. Bilinen Komutlar (CMD byte, offset 6)

| CMD | SUBCODE/PARAM | Anlam | Durum |
|---|---|---|---|
| `0x52` | — | Sabit parametre döner (değer=54 / `0x36`) | ✅ Doğrulandı, seri no DEĞİL |
| `0x06` | subcode=01 | **AA55 kısmı:** gerçek zamanlı hareket/attendance sayısı. **A55A kısmı:** ikincil sayaç (anlamı net değil, çoğu testte 0) | ✅ AA55 kesin doğrulandı (fiziksel parmak izi testiyle) |
| `0x07` | subcode=01, param=FFFFFFFF, alan=`00 00` | "Download Record" — ama sadece `06`'daki hareket sayısını **yankılıyor**, gerçek kayıt verisi DÖNMÜYOR | ⚠️ Doğru format bulundu ama bulk veri yok |
| `0x08` | subcode=01, param=index (offset 12-13) | Index'e göre çeşitli sistem sayaçları döner: `index=2`→kullanıcı sayısı, `index=3`→parmak izi şablonu sayısı, `index=6,11`→hareket sayısı, `index=12`→1000 (muhtemelen kapasite) | ✅ Kısmen çözüldü |
| `0x0B` | subcode=01, param=`00000000`, alan=`01 00` | Cihaz ekranında "çalışıyor" gösteriyor, **yönetici işlem sayacını +1 artırıyor** (yan etki!) | ✅ Doğrulandı |
| `0x0C` | subcode=01 | Durum sorgusu / bağlantı testi (resmi yazılım sık kullanıyor) | ✅ Güvenli, zararsız |
| `0x0E` | subcode=01, param=4 | Farklı/yeni bir A5 5A formatı (6 byte, değer=1) döndürüyor | ⚠️ Kısmen anlaşıldı |
| `0x0F` | subcode=01, param=4 | Cihazdan sadece ACK geliyor, ardından istemci kendiliğinden `5A A5 + [tick counter] + checksum` (10 byte) paketi gönderiyor. Bu değer **Unix zaman damgası DEĞİL**, muhtemelen `GetTickCount()` tarzı yerel bir sayaç (muhtemelen "Set Time" fonksiyonuyla ilişkili) | ⚠️ Muhtemelen "saat ayarlama" ile ilgili, indirmeyle ilgisiz |
| `0x05` | subcode=01 | Yönetici işlem sayısı (her `0B` çağrısında ya da cihaz menüsüne girişte artan sayaç) | ✅ Doğrulandı |
| `0x20` | subcode=01 | 103 byte'lık sabit bir tampon (anlamı belirsiz, parametre bağımsız) + değer=10 (muhtemelen toplam kişi sayısı) | ⚠️ Kısmen anlaşıldı |
| `0x04`, `0x12/0x0C`, `0x13`, `0x16` | — | Eski notlardan: `0x16`→model adı ("OP-F300" ASCII), `0x13`→bilinmiyor, `0x04`/`0x12`→sayaç | ⚠️ Eski/doğrulanmamış notlar |

### Test edilip **geçersiz/no-op** çıkan komutlar
`0x01, 0x02, 0x03, 0x08(hatalı param ile), 0x09(kısmen), 0x0A, 0x0D, 0x10, 0x11, 0x15, 0x17, 0x18, 0x19, 0x1A, 0x1C, 0x1D, 0x1E(belirsiz), 0x1F, 0x22–0x28` — standart "boş/status=0000" cevabı veriyor, bilinen bir işlevleri yok.

### 🚫 KESİNLİKLE GÖNDERİLMEMESİ GEREKEN KOMUTLAR

| CMD | Sebep |
|---|---|
| **`0x14`** | Tam ve geçerli formatta olmasına rağmen hareket/kayıt sayacını **SIFIRLADI** (4→0, 14.07.2026 tarihinde doğrulandı) |
| **`0x21`** | Hareket sayacını **kalıcı olarak düşürdü** (4→1, 15.07.2026 tarihinde doğrulandı) |
| **`0x0B` (eksik/kısaltılmış byte ile)** | 1 byte eksik gönderildiğinde (checksum bunu yakalamaz!) kullanıcı/kayıt verisini **sildi** |

---

## 4. "Download Record" Neden Çalışmıyor — Kapsamlı Kanıt

Aşağıdaki **bağımsız yöntemlerin hepsi** aynı sonuca ulaştı: TCP üzerinden gerçek bulk attendance kaydı transferi **hiç gözlemlenmedi**.

1. **Ham TCP pcap yakalamaları** (Wireshark, 3+ ayrı oturum) — `07` hep sadece sayıyı yankıladı.
2. **Kör komut taraması** (`0x00`–`0x28` arası, checksum doğrulamalı) — hiçbir komut bulk veri döndürmedi.
3. **Frida ile `FV_SendCommandToFK` fonksiyon çağrılarını doğrudan yakalama** — `cmd1/cmd2/data` parametreleri incelendi, aynı sonuç.
4. **Winsock `send`/`recv`'i boyut sınırı olmadan izleme** (`ws_capture.js`) — büyük paket geçişi hiç görülmedi.
5. **Gerçek istemci yazılımının "Download Record" butonuna basılması** ("All Record" modu dahil) — yine sadece sayaç cevabı.

**Sonuç:** Yazılımın arayüzünde **"Get U Disk Record"** ve **"Get U disk FP template"** gibi ayrı, USB-tabanlı butonların bulunması, üreticinin bu cihaz ailesinde bulk veri transferini **bilinçli olarak USB'ye ayırdığını** düşündürüyor. TCP muhtemelen sadece durum sorgulama ve yönetim komutları için tasarlanmış.

---

## 5. USB Export — Kanıtlanmış Çalışan Yöntem

Cihazın kendi menüsünden USB'ye "Kayıt/Log" dışa aktarımı **başarıyla test edildi** ve temiz, okunabilir veri üretti:

| Dosya | İçerik | Format |
|---|---|---|
| `ALOG_*.txt` | Hareket/attendance kayıtları | TAB ayraçlı: `No, TMNo, EnNo, Name, GMNo, Mode, In/Out, Antipass, ProxyWork, DateTime` |
| `SLOG_*.txt` | Sistem/yönetici günlüğü | TAB ayraçlı: `No, Manager, User, Action, Result, DateTime` |
| `user_*.xml` | Kullanıcı meta verisi | XML: isim, yetki seviyesi, kart, şifre, departman |
| `user_*_fp_*.dat` | Parmak izi şablonu | 1404 byte ikili (tescilli minutiae formatı, çözülmedi/gerekmiyor) |
| `ENROLLEXTDB.DAT` | Genişletilmiş kayıt veritabanı | 16 byte, `ORNE` imzası + sayaç (çoğunlukla boş) |

`EnNo` alanı = çalışan ID, `Mode` = doğrulama yöntemi (örn. "PİZİ" = Parmak İzi), `In/Out` = vardiya durumu.

---

## 6. Yazılım Mimarisi (Statik + Dinamik Analiz)

```
ZWKQ.exe (Attendance Access System — 3. parti istemci)
    ↓
FKAttend.ocx / FK524PXN.ocx  (COM wrapper, kendi export'ları yok)
    ↓
FKViaDev.dll
    ↓
CFKViaDev::FV_SendCommandToFK(long cmd1, long cmd2, ulong data,
                                ushort* status, ulong* retData, ulong timeout)
    ↓
FUN_10005780() → 3 deneme yapar
    ↓
FUN_10005450() → paket gönderir (FUN_10006390 ile header oluşturur)
    ↓
send() / FUN_10006480() → ACK bekler
    ↓
FUN_10006500() / FUN_10005030() → cevap okur (64000 byte buffer)
    ↓
FUN_10004FD0() → paket başlangıcını ('U',0xAA imzası + packet ID) arar
```

**Doğrulanmış export'lar (`FKViaDev.dll`):**
- `FV_SendCommandToFK` / `?FV_SendCommandToFK@CFKViaDev@@QAEJJJKPAGPAKK@Z` (mangled)
- `FV_SendCommandToFK_CS` (critical-section/thread-safe versiyon)
- `FV_ReadDataFromFK`, `FV_ReadDataFromFK_CS`
- `FV_ConnectNet`, `FV_ConnectUSB`, `FV_ConnectComm`, `FV_DisConnect`
- `FV_WriteDataToFK`, `FV_WriteReadDataToFK`

---

## 7. Geliştirilen Araçlar

| Dosya | Amaç |
|---|---|
| `opf300hex.py` | Manuel hex paket gönderici (orijinal, checksum otomatik) |
| `opf300_sequence.py` | Sıralı komut gönderici + otomatik log dosyası, uzunluk doğrulamalı |
| `record_decoder.py` | R701 cihazı referans alınarak hazırlanmış 12-byte kayıt çözücü (OP-F300 için henüz doğrulanmadı, gerçek veri bulunamadığı için) |
| `opf300_panel.html` | Offline kontrol paneli — USB export dosyalarını (ALOG/SLOG/XML) görüntüleyen tarayıcı tabanlı dashboard |
| `opf300_panel_server.py` | **Canlı** kontrol paneli — Python arka planda gerçek TCP bağlantısı yönetir, tarayıcıda güzel bir arayüz sunar. Bilinen güvenli komutlar + "deneysel komut" gönderme (onaylı, otomatik sayaç kontrollü). `0x14` ve `0x21` kalıcı olarak engellendi. |
| `fk_hook.js` | Frida script'i — `FKViaDev.dll` fonksiyon çağrılarını (`FV_SendCommandToFK` dahil) parametreleriyle yakalar |
| `ws_capture.js` | Frida script'i — Winsock `send`/`recv`/`WSASend`/`WSARecv`'i boyut sınırı olmadan doğrudan kancalar, tüm trafiği hex+ASCII gösterir |

---

## 8. Genel Sonuç ve Öneri

- Protokolün **iskeleti** (checksum, paket formatı, birçok durum/sayaç komutu) tam olarak çözüldü ve hem ampirik hem statik/dinamik analizle doğrulandı.
- **Bulk kayıt indirme TCP üzerinden bulunamadı** — kapsamlı, çok yöntemli testlerle bu sonuca varıldı, muhtemelen bu cihaz ailesinde mimari olarak desteklenmiyor.
- **Pratik veri ihtiyacı için USB export kanıtlanmış, güvenilir tek yöntemdir.**
- TCP protokolü üzerinde ileride çalışılacaksa, öncelik `0x08`'in geri kalan index'lerini (13+) taramak ve `0x20`'nin 103-byte tamponunun anlamını çözmek olabilir — ama bunlar düşük öncelikli, akademik değer taşıyan konular.
