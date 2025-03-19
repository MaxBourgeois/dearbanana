// hook_script.js

if (Process.platform !== "windows") {
    send("Ce script doit être exécuté sur Windows.");
}

var moduleName = "%%MODULE%%";
var filterFunction = "%%FUNCTION%%";
var hookOnlyDefinedFunctions = false;
var fileHandleMap = {}

// Si aucune signature n'est définie, on crée un objet vide.
if (typeof functionSignatures === 'undefined') {
    var functionSignatures = {};
}

//@@SIGNATURES@@
// functionSignatures["CreateFileW"] = {
//     args: [
//         { name: "lpFileName", type: "wstring" },
//         { name: "dwDesiredAccess", type: "uint32" },
//         { name: "dwShareMode", type: "uint32" },
//         { name: "lpSecurityAttributes", type: "pointer" },
//         { name: "dwCreationDisposition", type: "uint32" },
//         { name: "dwFlagsAndAttributes", type: "uint32" },
//         { name: "hTemplateFile", type: "pointer" }
//     ],
//     retType: "pointer"
// };

function formatArgValue(arg, type) {
    try {
        switch (type) {
            case "uint32":
            case "int":
                return arg.toInt32();
            case "pointer":
                return arg;
            case "string":
                return Memory.readUtf8String(arg);
            case "wstring":
                return Memory.readUtf16String(arg);
            case "bool":
                return (arg.toInt32() !== 0) ? "true" : "false";
            case "void":
                return "void";
            default:
                return arg;
        }
    } catch (err) {
        return "Inaccessible";
    }
}

send("Hooking de " + moduleName + "...");

var exports = Module.enumerateExports(moduleName);
exports.forEach(function(exp) {
    if (exp.type !== "function") return;
    if (filterFunction.length > 0 && exp.name !== filterFunction) return;
    if (hookOnlyDefinedFunctions && !(exp.name in functionSignatures)) return;

    var sig = functionSignatures[exp.name];

    try {
        Interceptor.attach(exp.address, {
            onEnter: function(args) {
                if (!sig) {return;}
                if (sig && sig.args && sig.args.length > 0) {
                    this.argValues = [];
                    for (var i = 0; i < sig.args.length; i++) {
                        var param = sig.args[i];
                        var argValue = formatArgValue(args[i], param.type);
                        this.argValues.push(argValue);
                    }
                }
                send("[+] Appel de " + exp.name + "(");
                if (sig && sig.args && sig.args.length > 0) {
                    for (var i = 0; i < sig.args.length; i++) {
                        var param = sig.args[i];
                        send("    " + param.name + " (" + param.type + ") = " + this.argValues[i]);
                    }
                } else {
                    for (var i = 0; i < args.length; i++) {
                        send("    arg" + i + " = " + args[i]);
                    }
                }
                send(")");
            },
            onLeave: function(retval) {
                if (!sig) {return;}
                if (exp.name === "CreateFileW") {
                    var handleStr = retval.toString();
                    if (!retval.isNull() && handleStr !== "0xffffffff") {
                        if (this.argValues && this.argValues.length > 0) {
                            fileHandleMap[handleStr] = this.argValues[0];
                        }
                    }
                }
                if (sig && sig.retType) {
                    var retValue = formatArgValue(retval, sig.retType);
                    send("[-] Retour de " + exp.name + " = " + retValue);
                } else {
                    send("[-] Retour de " + exp.name + " = " + retval);
                }
            }
        });
    } catch (e) {
        send("Erreur lors du hook de " + exp.name + " : " + e);
    }
});
