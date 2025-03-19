var getKeyboardStateAddr = Module.getExportByName("%%MODULE%%", "%%FUNCTION%%");

Interceptor.attach(getKeyboardStateAddr, {
    onEnter: function (args) {
        send("[+] Appel de %%FUNCTION%% (")
        
        send(")")
    },
    onLeave: function (retval) {
        send("[-] Retour de %%FUNCTION%% = " + retval)
    }
});