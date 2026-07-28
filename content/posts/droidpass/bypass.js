
console.log("\n--- [ 8kSec DroidPass Security Bypass Started ] ---");

Java.perform(function () {
    const SecurityModule = Java.use("com.eightksec.droidpass.SecurityModule");

    // 1. Hook the Java methods and LOG when they are called
    SecurityModule.b.implementation = function () {
        console.log("[!] Flutter called Java Root Check!");
        return false; 
    };

    SecurityModule.c.implementation = function () {
        console.log("[!] Flutter called Java Emulator Check!");
        return false;
    };
});

// 2. If the logs above DON'T appear, Flutter is calling the C++ library directly.
// We need to find the REAL names of the functions in the library.
const libName = "libsecurity-checks.so";
const module = Process.findModuleByName(libName);

if (module) {Java.perform(function () {
    const SecurityModule = Java.use("com.eightksec.droidpass.SecurityModule");

    // 1. Hook the Java methods and LOG when they are called
    SecurityModule.b.implementation = function () {
        console.log("[!] Flutter called Java Root Check!");
        return false; 
    };

    SecurityModule.c.implementation = function () {
        console.log("[!] Flutter called Java Emulator Check!");
        return false;
    };
});

// 2. If the logs above DON'T appear, Flutter is calling the C++ library directly.
// We need to find the REAL names of the functions in the library.
const libName = "libsecurity-checks.so";
const module = Process.findModuleByName(libName);

if (module) {
    console.log("[*] Found " + libName + " at " + module.base);
    
    // List ALL functions exported by this library to see the real names
    const exports = module.enumerateExports();
    for (let i = 0; i < exports.length; i++) {
        console.log("Found Native Export: " + exports[i].name);
        
        // Hook anything that sounds like "root" or "emulator" or "tamper"
        if (exports[i].name.toLowerCase().includes("root") || 
            exports[i].name.toLowerCase().includes("emulator") ||
            exports[i].name.toLowerCase().includes("tamper")) {
            
            Interceptor.attach(exports[i].address, {
                onLeave: function (retval) {
                    console.log("[+] Bypassing Native: " + exports[i].name);
                    retval.replace(0); // Force false
                }
            });
        }
    }
} else {
    console.log("[?] " + libName + " not loaded yet. Waiting...");
}
    console.log("[*] Found " + libName + " at " + module.base);
    
    // List ALL functions exported by this library to see the real names
    const exports = module.enumerateExports();
    for (let i = 0; i < exports.length; i++) {
        console.log("Found Native Export: " + exports[i].name);
        
        // Hook anything that sounds like "root" or "emulator" or "tamper"
        if (exports[i].name.toLowerCase().includes("root") || 
            exports[i].name.toLowerCase().includes("emulator") ||
            exports[i].name.toLowerCase().includes("tamper")) {
            
            Interceptor.attach(exports[i].address, {
                onLeave: function (retval) {
                    console.log("[+] Bypassing Native: " + exports[i].name);
                    retval.replace(0); // Force false
                }
            });
        }
    }
} else {
    console.log("[?] " + libName + " not loaded yet. Waiting...");
}