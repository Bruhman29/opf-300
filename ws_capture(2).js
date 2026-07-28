/*
Winsock Trafik Yakalayici (Frida)
====================================
ws2_32.dll icindeki send, WSASend, recv, WSARecv fonksiyonlarini
dogrudan kancalar ve gonderilen/alinan TUM byte'lari hex+ascii
olarak gosterir. API Monitor'daki kategori secimiyle ugrasmaya
gerek birakmaz -- her seyi otomatik yakalar.

Kullanim:
  frida -n "ZWKQ.exe" -l ws_capture.js

Sonra yazilimda istedigin islemi (baglan, kayit indir, senkronize
et vb.) tetikle. Her gonderim/alis icin su formatta bir blok cikar:

  >>> SEND  socket=0x1a4  len=16
      55 aa 01 00 79 19 07 01 ff ff ff ff 00 00 96 05

  <<< RECV  socket=0x1a4  len=14
      aa 55 01 00 00 00 01 00 04 00 00 00 05 01
*/

function toHexStr(buf) {
    const bytes = [];
    for (let i = 0; i < buf.length; i++) bytes.push(('0' + buf[i].toString(16)).slice(-2));
    return bytes.join(' ');
}

function asciiOf(buf) {
    let out = '';
    for (let i = 0; i < buf.length; i++) {
        const b = buf[i];
        out += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
    }
    return out;
}

function readBytes(ptr, len) {
    try {
        return new Uint8Array(ptr.readByteArray(len));
    } catch (e) {
        return null;
    }
}

function logBlock(direction, socketVal, len, ptr) {
    // ONEMLI: onceki surumde cagiran kod "len < 8192" kontrolu
    // yapiyordu, bu da buyuk paketleri (ornegin gercek kayit verisi)
    // logBlock'a hic ULASTIRMIYORDU. O sinirlar asagida kaldirildi.
    // Cok buyuk paketlerde ekran taşmasin diye ilk 4096 byte gosterilir,
    // ama GERCEK uzunluk her zaman yazdirilir.
    const showLen = Math.min(len, 4096);
    const bytes = readBytes(ptr, showLen);
    const isSend = direction.indexOf('SEND') === 0;
    console.log("\n" + (isSend ? '>>> ' : '<<< ') + direction +
        "  socket=0x" + socketVal.toString(16) + "  len=" + len +
        (len > showLen ? "  (ilk " + showLen + " byte gosteriliyor)" : ""));
    if (bytes) {
        console.log("    " + toHexStr(bytes));
        console.log("    " + asciiOf(bytes));
    } else {
        console.log("    (okunamadi)");
    }
}

function findExport(mod, name) {
    // Module.getExportByName bu Frida surumunde bazen "not a function" hatasi
    // veriyor -- export tablosunu elle tarayarak ayni isi guvenilir yapariz.
    const match = mod.enumerateExports().find(exp => exp.name === name);
    return match ? match.address : null;
}

function hookWs2_32() {
    let mod;
    try {
        mod = Process.getModuleByName("ws2_32.dll");
    } catch (e) {
        console.log("[x] ws2_32.dll bulunamadi, tekrar denenecek.");
        return false;
    }

    console.log("[+] ws2_32.dll bulundu: " + mod.base);

    // ---- send(SOCKET s, const char *buf, int len, int flags) ----
    try {
        const sendAddr = findExport(mod, "send");
        if (!sendAddr) throw new Error("export bulunamadi");
        Interceptor.attach(sendAddr, {
            onEnter: function (args) {
                const socketVal = args[0].toInt32();
                const buf = args[1];
                const len = args[2].toInt32();
                if (len > 0) {
                    logBlock('SEND', socketVal, len, buf);
                }
            }
        });
        console.log("[+] Kancalandi: send");
    } catch (e) {
        console.log("[x] send kancalanamadi: " + e.message);
    }

    // ---- recv(SOCKET s, char *buf, int len, int flags) ----
    try {
        const recvAddr = findExport(mod, "recv");
        if (!recvAddr) throw new Error("export bulunamadi");
        Interceptor.attach(recvAddr, {
            onEnter: function (args) {
                this.socketVal = args[0].toInt32();
                this.buf = args[1];
            },
            onLeave: function (retval) {
                const n = retval.toInt32();
                if (n > 0) {
                    logBlock('RECV', this.socketVal, n, this.buf);
                }
            }
        });
        console.log("[+] Kancalandi: recv");
    } catch (e) {
        console.log("[x] recv kancalanamadi: " + e.message);
    }

    // ---- WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, ...) ----
    try {
        const wsaSendAddr = findExport(mod, "WSASend");
        if (!wsaSendAddr) throw new Error("export bulunamadi");
        Interceptor.attach(wsaSendAddr, {
            onEnter: function (args) {
                const socketVal = args[0].toInt32();
                const lpBuffers = args[1];
                const count = args[2].toInt32();
                const ptrSize = Process.pointerSize;
                for (let i = 0; i < count; i++) {
                    const base = lpBuffers.add(i * (4 + ptrSize)); // WSABUF: ULONG len + char* buf
                    const len = base.readU32();
                    const bufPtr = base.add(4).readPointer();
                    if (len > 0) {
                        logBlock('SEND', socketVal, len, bufPtr);
                    }
                }
            }
        });
        console.log("[+] Kancalandi: WSASend");
    } catch (e) {
        console.log("[x] WSASend kancalanamadi: " + e.message);
    }

    // ---- WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, ...) ----
    try {
        const wsaRecvAddr = findExport(mod, "WSARecv");
        if (!wsaRecvAddr) throw new Error("export bulunamadi");
        Interceptor.attach(wsaRecvAddr, {
            onEnter: function (args) {
                this.socketVal = args[0].toInt32();
                this.lpBuffers = args[1];
                this.count = args[2].toInt32();
                this.lpNumberOfBytesRecvd = args[3];
            },
            onLeave: function (retval) {
                const rc = retval.toInt32();
                if (rc !== 0) return; // SOCKET_ERROR ya da basarisiz
                let totalRecvd;
                try {
                    totalRecvd = this.lpNumberOfBytesRecvd.readU32();
                } catch (e) {
                    return;
                }
                if (totalRecvd <= 0) return;  // 8192 sinirinin kaldirilmasi: buyuk kayit paketlerini de gorelim

                const ptrSize = Process.pointerSize;
                let remaining = totalRecvd;
                for (let i = 0; i < this.count && remaining > 0; i++) {
                    const base = this.lpBuffers.add(i * (4 + ptrSize));
                    const bufLen = base.readU32();
                    const bufPtr = base.add(4).readPointer();
                    const chunkLen = Math.min(bufLen, remaining);
                    if (chunkLen > 0) {
                        logBlock('RECV', this.socketVal, chunkLen, bufPtr);
                    }
                    remaining -= chunkLen;
                }
            }
        });
        console.log("[+] Kancalandi: WSARecv");
    } catch (e) {
        console.log("[x] WSARecv kancalanamadi: " + e.message);
    }

    // ---- sendto(SOCKET s, const char *buf, int len, int flags, ...) [UDP] ----
    try {
        const sendtoAddr = findExport(mod, "sendto");
        if (!sendtoAddr) throw new Error("export bulunamadi");
        Interceptor.attach(sendtoAddr, {
            onEnter: function (args) {
                const socketVal = args[0].toInt32();
                const buf = args[1];
                const len = args[2].toInt32();
                if (len > 0) {
                    logBlock('SEND(UDP)', socketVal, len, buf);
                }
            }
        });
        console.log("[+] Kancalandi: sendto (UDP)");
    } catch (e) {
        console.log("[x] sendto kancalanamadi: " + e.message);
    }

    // ---- recvfrom(SOCKET s, char *buf, int len, int flags, ...) [UDP] ----
    try {
        const recvfromAddr = findExport(mod, "recvfrom");
        if (!recvfromAddr) throw new Error("export bulunamadi");
        Interceptor.attach(recvfromAddr, {
            onEnter: function (args) {
                this.socketVal = args[0].toInt32();
                this.buf = args[1];
            },
            onLeave: function (retval) {
                const n = retval.toInt32();
                if (n > 0) {
                    logBlock('RECV(UDP)', this.socketVal, n, this.buf);
                }
            }
        });
        console.log("[+] Kancalandi: recvfrom (UDP)");
    } catch (e) {
        console.log("[x] recvfrom kancalanamadi: " + e.message);
    }

    return true;
}

console.log("=== Winsock Trafik Yakalayici Baslatiliyor ===");

let hooked = false;
try {
    hooked = hookWs2_32();
} catch (e) {
    console.log("[x] Hata: " + e.message);
}

if (!hooked) {
    let tries = 0;
    const interval = setInterval(() => {
        tries++;
        if (tries > 20) { clearInterval(interval); return; }
        try {
            if (hookWs2_32()) clearInterval(interval);
        } catch (e) {
            console.log("[x] Hata: " + e.message);
        }
    }, 1000);
}
