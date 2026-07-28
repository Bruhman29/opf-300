/*
FKViaDev.dll / FKAttend.ocx - Fonksiyon Cagrisi Yakalayici (Frida)
====================================================================
Amac:
  ZWKQ.exe (veya benzeri FKAttend tabanli istemci) calisirken,
  FK_GetGeneralLogData, FK_ConnectNet, FV_SendCommandToFK gibi
  fonksiyonlarin GERCEKTEN hangi parametrelerle (cmd1, cmd2, data)
  cagrildigini goruyoruz.

Kullanim:
  1) Windows makinede (istemci nerede calisiyorsa orada):
       pip install frida-tools
  2) Istemci (ornegin ZWKQ.exe / Attendance Access System) CALISIRKEN:
       frida -n "ZWKQ.exe" -l fk_hook.js
     (Process adi farkliysa, Gorev Yoneticisi'nden tam .exe adini al)

     Ya da baslatirken yakalamak icin:
       frida -f "C:\\yol\\ZWKQ.exe" -l fk_hook.js --no-pause

  3) Yazilimda "kayitlari indir / senkronize et" islemini tetikle.
  4) Frida konsolunda cikan loglari kopyalayip paylas.
*/

// Artik KESIN olarak biliyoruz ki bu iki export gercekten mevcut:
//   FV_SendCommandToFK                                  (duz/plain wrapper)
//   ?FV_SendCommandToFK@CFKViaDev@@QAEJJJKPAGPAKK@Z      (C++ mangled, gercek metod)
// Mangled imza cozumu:
//   long FV_SendCommandToFK(long cmd1, long cmd2, ulong data,
//                            ushort* status, ulong* retData, ulong timeout)
// Yani args[0]=cmd1, args[1]=cmd2, args[2]=data, args[3]=status(ptr),
// args[4]=retData(ptr), args[5]=timeout. __thiscall oldugu icin "this"
// ECX register'inda tasinir, stack argumanlari (args[]) yine de
// cmd1'den baslar -- Frida bunu otomatik dogru hizalar.
const CANDIDATES = [
    "FV_SendCommandToFK",
    "?FV_SendCommandToFK@CFKViaDev@@QAEJJJKPAGPAKK@Z",
    "?FV_SendCommandToFK_CS@CFKViaDev@@QAEJJJKPAGPAKK1@Z",
    "FV_ReadDataFromFK",
    "?FV_ReadDataFromFK@CFKViaDev@@QAEJJJPAXKKPAGPAKKPAUHWND__@@@Z",
    "?FV_ReadDataFromFK_CS@CFKViaDev@@QAEJJJPAXKKPAGPAKKPAUHWND__@@@Z",
    "?FV_WriteReadDataToFK@CFKViaDev@@QAEJJJPAXK0KPAGPAKKPAUHWND__@@@Z",
];

// Bu modullerde arayacagiz.
const MODULES = ["FKViaDev.dll", "FKAttend.ocx"];

function hexArg(val) {
    try {
        // Hem int hem pointer olabilecegi icin iki turlu de goster
        return "0x" + val.toString(16) + " (" + val.toInt32() + ")";
    } catch (e) {
        return String(val);
    }
}

function tryHook(moduleName, funcName) {
    let addr;
    try {
        addr = Module.getExportByName(moduleName, funcName);
    } catch (e) {
        // Yedek yontem: export tablosunu tarayip birebir isim eslesmesi ara.
        // (Bazi Frida surumleri '?' ve '@' iceren mangled isimlerde
        // getExportByName ile sorun yasayabiliyor.)
        try {
            const mod = Process.getModuleByName(moduleName);
            const match = mod.enumerateExports().find(exp => exp.name === funcName);
            if (match) {
                addr = match.address;
                console.log("[i] Yedek yontemle bulundu: " + moduleName + "!" + funcName);
            } else {
                console.log("[-] Bulunamadi: " + moduleName + "!" + funcName + "  -> " + e.message);
                return false;
            }
        } catch (e2) {
            console.log("[-] Bulunamadi (yedek de basarisiz): " + moduleName + "!" + funcName + "  -> " + e2.message);
            return false;
        }
    }

    console.log("[+] Bulundu: " + moduleName + "!" + funcName + " @ " + addr);

    const isSendCommand = funcName.indexOf("FV_SendCommandToFK") !== -1;

    try {
        Interceptor.attach(addr, {
        onEnter: function (args) {
            this.funcName = funcName;
            console.log("\n===== CAGRI: " + funcName + " =====");

            if (isSendCommand) {
                // long FV_SendCommandToFK(long cmd1, long cmd2, ulong data,
                //   ushort* status, ulong* retData, ulong timeout)
                this.cmd1 = args[0].toInt32();
                this.cmd2 = args[1].toInt32();
                this.dataVal = args[2].toInt32();
                this.statusPtr = args[3];
                this.retDataPtr = args[4];
                this.timeoutVal = args[5].toInt32();

                console.log("  cmd1     = " + this.cmd1 + "  (0x" + (this.cmd1 >>> 0).toString(16) + ")");
                console.log("  cmd2     = " + this.cmd2 + "  (0x" + (this.cmd2 >>> 0).toString(16) + ")");
                console.log("  data     = " + this.dataVal + "  (0x" + (this.dataVal >>> 0).toString(16) + ")");
                console.log("  status*  = " + this.statusPtr);
                console.log("  retData* = " + this.retDataPtr);
                console.log("  timeout  = " + this.timeoutVal);
            } else {
                for (let i = 0; i < 6; i++) {
                    try {
                        console.log("  arg" + i + " = " + hexArg(args[i]));
                    } catch (e) {
                        console.log("  arg" + i + " = <okunamadi>");
                    }
                }
            }
        },
        onLeave: function (retval) {
            console.log("  -> donus degeri: " + hexArg(retval));
            if (isSendCommand) {
                try {
                    if (!this.statusPtr.isNull()) {
                        const statusVal = this.statusPtr.readU16();
                        console.log("  [cikis] *status  = " + statusVal + "  (0x" + statusVal.toString(16) + ")");
                    }
                    if (!this.retDataPtr.isNull()) {
                        const retVal = this.retDataPtr.readU32();
                        console.log("  [cikis] *retData = " + retVal + "  (0x" + retVal.toString(16) + ")");
                    }
                } catch (e) {
                    console.log("  [cikis] okunamadi: " + e.message);
                }
            }
        }
    });
        console.log("[+] Kancalandi: " + moduleName + "!" + funcName);
    } catch (e) {
        console.log("[x] HATA (Interceptor.attach basarisiz): " + moduleName + "!" + funcName);
        console.log("    " + e.message);
        return false;
    }

    return true;
}

console.log("=== FKViaDev / FKAttend Hook Baslatiliyor ===");

function dumpExports(moduleName) {
    let mod;
    try {
        mod = Process.getModuleByName(moduleName);
    } catch (e) {
        return false;
    }
    console.log("\n[=] " + moduleName + " GERCEK EXPORT LISTESI:");
    const exports = mod.enumerateExports();
    if (exports.length === 0) {
        console.log("    (hic export bulunamadi -- muhtemelen COM/OCX, sadece");
        console.log("     DllGetClassObject / DllRegisterServer gibi standart");
        console.log("     COM export'lari olabilir, gercek fonksiyonlar arayuz");
        console.log("     (interface) uzerinden cagriliyor olabilir)");
    }
    exports.forEach(exp => {
        console.log("    " + exp.type.padEnd(10) + exp.name + "  @ " + exp.address);
    });
    return true;
}

// Modullerin yuklenmesini bekle, sonra GERCEK export listesini dok.
const seen = new Set();
function attemptAll() {
    let anyFound = false;
    for (const mod of MODULES.concat(["FK524PXN.ocx"])) {
        if (seen.has(mod)) { anyFound = true; continue; }
        const found = dumpExports(mod);
        if (found) {
            seen.add(mod);
            anyFound = true;
        }
        for (const fn of CANDIDATES) {
            if (tryHook(mod, fn)) anyFound = true;
        }
    }
    if (!anyFound) {
        console.log("[!] Henuz hicbir modul bulunamadi.");
    }
}

// YAKALA HER SEYI MODU: FKViaDev.dll'in TUM fonksiyon export'larina
// hafif bir logger takar. Boylece hangi fonksiyonun GERCEKTEN
// cagrildigini -- ismini tahmin etmeden -- goruruz.
function hookEverything(moduleName) {
    let mod;
    try {
        mod = Process.getModuleByName(moduleName);
    } catch (e) {
        return;
    }
    const exports = mod.enumerateExports();
    let count = 0;
    exports.forEach(exp => {
        if (exp.type !== "function") return;
        // Constructor/destructor gibi cok sik cagrilabilecekleri atla
        if (exp.name.indexOf("??0") === 0 || exp.name.indexOf("??1") === 0) return;
        try {
            Interceptor.attach(exp.address, {
                onEnter: function (args) {
                    console.log("\n>>> CAGRILDI: " + exp.name);
                    for (let i = 0; i < 4; i++) {
                        try { console.log("    arg" + i + " = " + hexArg(args[i])); } catch (e2) {}
                    }
                }
            });
            count++;
        } catch (e) {
            // bazi fonksiyonlar (ozellikle cok kucuk/inline) hooklanamayabilir, sorun degil
        }
    });
    console.log("[i] " + moduleName + ": " + count + " fonksiyona genel logger takildi (YAKALA HER SEYI modu).");
}

// Hemen dene
try {
    attemptAll();
    hookEverything("FKViaDev.dll");
} catch (e) {
    console.log("[x] attemptAll() hatasi: " + e.message);
}

// Modul sonradan yuklenirse de yakalamak icin kisa araliklarla tekrar dene
let tries = 0;
const interval = setInterval(() => {
    tries++;
    if (tries > 20) { clearInterval(interval); return; }
    try {
        attemptAll();
    } catch (e) {
        console.log("[x] attemptAll() hatasi: " + e.message);
    }
}, 1500);
