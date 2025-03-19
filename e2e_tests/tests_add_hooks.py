from imgui_bundle import imgui, hello_imgui
import time

import IPython

wait_time = 0.5
editor_to_inject = None

import pyperclip

def set_editor_to_inject_for_test(editor):
    global editor_to_inject
    editor_to_inject = editor

def simulate_paste(ctx, text: str):
    pyperclip.copy(text)
    ctx.key_press(imgui.Key.mod_ctrl | imgui.Key.v.value)

def add_hook(ctx, process, module, function, waittime):
    # --- Step 1 : palette CTRL+P ---
    ctx.key_down(imgui.Key.left_ctrl.value)
    ctx.key_down(imgui.Key.p.value)
    ctx.key_up(imgui.Key.p.value)
    ctx.key_up(imgui.Key.left_ctrl.value)
    time.sleep(wait_time)

    # --- Step 2 ---
    ctx.item_click("**/##CommandSearch")
    ctx.key_chars("add hook")
    ctx.key_press(imgui.Key.enter.value)
    time.sleep(wait_time)

    # --- Step 3 ---
    ctx.item_click("**/##CommandSearch")
    ctx.key_chars(process)
    ctx.key_press(imgui.Key.enter.value)
    time.sleep(wait_time)

    # --- Step 4 ---
    ctx.item_click("**/##CommandSearch")
    ctx.key_chars(module)
    ctx.key_press(imgui.Key.enter.value)
    time.sleep(wait_time)

    # --- Step 5 ---
    ctx.item_click("**/##CommandSearch")
    ctx.key_chars(function)
    ctx.key_press(imgui.Key.enter.value)
    time.sleep(wait_time)
    return

def test_command_palette_sequence(ctx) -> None:
    print("Test running")

    add_hook(ctx, "notepad", "kernel32.dll", "createfilew", wait_time)
    add_hook(ctx, "notepad", "kernel32.dll", "readfile", wait_time)
    add_hook(ctx, "notepad", "kernel32.dll", "writefile", wait_time)
    add_hook(ctx, "notepad", "user32.dll", "get keyb state", wait_time)

    # --- Step 6 ---
    ctx.item_click("/GetKeyboardState #4/Start Hook")
    time.sleep(wait_time)

    # --- Step 7 ---
    ctx.item_click("/GetKeyboardState #4/Edit Script")
    time.sleep(wait_time)

    winsize = imgui.get_main_viewport().size
    ctx.mouse_move_to_pos((winsize.x / 2, winsize.y / 2))
    ctx.mouse_click()
    ctx.key_press(imgui.Key.mod_ctrl | imgui.Key.a.value)

    ctx.key_press(imgui.Key.backspace.value)

    editor_to_inject.set_text("""
var getKeyboardStateAddr = Module.getExportByName("user32.dll", "GetKeyboardState");

function isLetter(str) {
  return str.length === 1 && str.match(/^[\w\-\s]+$/);
}

Interceptor.attach(getKeyboardStateAddr, {
    onEnter: function (args) {
        // args[0] est le pointeur vers le tableau (PBYTE lpKeyState), save in this state
        this.lpKeyState = args[0];
    },
    onLeave: function (retval) {
        // Parcourir les 256 octets pour voir quelles touches sont pressées
        for (var i = 0; i < 256; i++) {
            // Lire l'octet à l'index i
            var state = Memory.readU8(this.lpKeyState.add(i));
            //if (i == 66) state = 0x80;
            // Vérifier si le bit de poids fort (0x80) est activé
            if ((state & 0x80) !== 0 && isLetter(String.fromCharCode(i))) {
                var message = {
                "Time": new Date().toISOString(),
                "EventType": "call",
                "Process": "user32.dll",
                "Function": "GetKeyboardState",
                "Return": "",
                "Args": "key (" + state.toString(16) + ") = " + String.fromCharCode(i),
                "HookID": 0,
                "Level": "INFO"
                };
                send(JSON.stringify(message));                         
            }
        }
    }
});
""")

    ctx.key_press(imgui.Key.mod_ctrl | imgui.Key.enter)

    time.sleep(wait_time)    