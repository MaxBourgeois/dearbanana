import base64
import threading
import logging
import frida

from typing import Any, Dict, List, Optional, Union, Tuple
from imgui_bundle import imgui

from commands.command_palette import AutoCompleteHelper
from ui_windows.fullscreenable_ui import FullscreenableUI

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------
# Helper: Build Frida Script
# ------------------------------------------------------------------------------

def _build_frida_script(addr_hex: str, size: int) -> str:
    """
    Constructs the Frida script string for reading memory at the given address.
    
    Args:
        addr_hex: Memory address in hexadecimal.
        size: Number of bytes to read.
    
    Returns:
        The Frida script as a string.
    """
    return f"""
(function() {{
    function b64Encode(u8) {{
        var CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var len = u8.length;
        var base64 = "";
        for (var i = 0; i < len; i += 3) {{
            var c1 = u8[i];
            var c2 = (i+1 < len) ? u8[i+1] : 0;
            var c3 = (i+2 < len) ? u8[i+2] : 0;
            base64 += CHARS[c1 >> 2];
            base64 += CHARS[((c1 & 3) << 4) | (c2 >> 4)];
            if (i+1 < len)
                base64 += CHARS[((c2 & 15) << 2) | (c3 >> 6)];
            else
                base64 += "=";
            if (i+2 < len)
                base64 += CHARS[c3 & 63];
            else
                base64 += "=";
        }}
        return base64;
    }}

    try {{
        var basePtr = ptr("{addr_hex}");
        var sizeToRead = {size};
        var bytes = Memory.readByteArray(basePtr, sizeToRead);
        if (bytes === null) {{
            send({{type:"hexreader", base64:""}});
            return;
        }}
        var u8 = new Uint8Array(bytes);
        var encoded = b64Encode(u8);
        send({{type:"hexreader", base64: encoded}});
    }} catch(e) {{
        send({{type:"error", stack: e.stack}});
    }}
}})();
"""

# ------------------------------------------------------------------------------
# Hex Viewer Class
# ------------------------------------------------------------------------------

class HexViewerUI(FullscreenableUI):
    """
    Widget that attaches to a process and displays a memory dump in hexadecimal.
    """
    def __init__(self, parent_app: Any) -> None:
        super().__init__()
        self.parent_app: Any = parent_app
        self.device: Optional[frida.Device] = None
        self.session: Optional[frida.Session] = None
        self.processes: List[str] = []
        self.process_map: Dict[int, int] = {}
        self.selected_process_index: int = 0
        self.process_filter: str = ""
        self.address_str: str = "0x7ffbc41a35a0"
        self.size_to_read: int = 128
        self.memory_data: bytes = b""
        self.status_msg: str = ""
        self.is_reading: bool = False

        try:
            self.device = frida.get_local_device()
            self._load_process_list()
        except Exception as e:
            self.status_msg = f"No local device: {e}"
            self.device = None

    # --------------------------------------------------------------------------
    # Process and Session Management
    # --------------------------------------------------------------------------
    def _load_process_list(self) -> None:
        """Loads the list of available processes on the device."""
        if not self.device:
            self.status_msg = "No local device available."
            return
        try:
            procs = self.device.enumerate_processes()
            self.processes = [f"{p.name} ({p.pid})" for p in procs]
            self.process_map = {i: p.pid for i, p in enumerate(procs)}
            self.status_msg = f"{len(self.processes)} processes found."
        except Exception as e:
            self.status_msg = f"Error enumerating processes: {e}"

    def _attach(self) -> None:
        """Attaches to the selected process."""
        if self.session:
            self._detach()
        try:
            pid = self.process_map[self.selected_process_index]
            self.session = self.device.attach(pid)  # type: ignore
            self.status_msg = f"Attached to PID {pid}"
        except Exception as e:
            self.status_msg = f"Attach error: {e}"
            self.session = None

    def _detach(self) -> None:
        """Detaches from the current process session."""
        if not self.session:
            return
        try:
            self.session.detach()
            self.status_msg = "Detached."
        except Exception as e:
            self.status_msg = f"Detach error: {e}"
        finally:
            self.session = None

    # --------------------------------------------------------------------------
    # Memory Reading
    # --------------------------------------------------------------------------
    def _read_memory_frida(self, addr_hex: str, size: int) -> None:
        """
        Reads memory from the attached process using Frida and decodes the base64 result.
        
        Args:
            addr_hex: Memory address in hexadecimal.
            size: Number of bytes to read.
        """
        if not self.session:
            self.status_msg = "Not attached to a process!"
            return

        try:
            addr_hex = eval(addr_hex)
        except Exception as e:
            print(e)
            
        if not isinstance(addr_hex, int):
            self.status_msg = "Address expression error..."
            return
        
        frida_script: str = _build_frida_script(addr_hex, size)
        message_received = threading.Event()

        def on_message(message: Dict[str, Any], data: Any) -> None:
            payload = message.get("payload", "")
            msg_type = payload.get("type", "")
            if msg_type == "hexreader":
                b64_str = payload.get("base64", "")
                if b64_str:
                    try:
                        self.memory_data = base64.b64decode(b64_str)
                        self.status_msg = f"Read {len(self.memory_data)} bytes at {addr_hex}"
                    except Exception as ex:
                        self.memory_data = b""
                        self.status_msg = f"Error decoding base64: {ex}"
                else:
                    self.memory_data = b""
                    self.status_msg = "Read 0 bytes (maybe invalid address?)"
            elif msg_type == "error":
                err = payload.get("stack", "Unknown error")
                self.status_msg = f"Frida script error: {err}"
            message_received.set()

        try:
            assert self.session is not None
            script = self.session.create_script(frida_script)
            script.on("message", on_message)
            script.load()
            if not message_received.wait(timeout=1.0):
                self.status_msg = "Timeout reading memory."
            script.unload()
        except Exception as e:
            self.status_msg = f"Frida script error: {e}"

    # --------------------------------------------------------------------------
    # Hex Dump Drawing and Construction
    # --------------------------------------------------------------------------
    def _draw_hex_dump(self) -> None:
        """
        Displays the memory dump with improved coloration:
          - Addresses in cyan.
          - Each byte is displayed individually with special colors for 0x00 and 0xCC.
          - Printable ASCII bytes are highlighted in light cyan.
          - The ASCII representation is shown in light gray.
        """
        imgui.begin_child("HexDumpChild", imgui.ImVec2(0, 0))
        data = self.memory_data
        bytes_per_line = 16

        for offset in range(0, len(data), bytes_per_line):
            chunk = data[offset:offset+bytes_per_line]
            line_addr = f"{offset:08X}:"
            imgui.text_colored((0.0, 0.75, 1.0, 1.0), line_addr)
            imgui.same_line()
            for i, byte in enumerate(chunk):
                if byte == 0x00:
                    color = (0.7, 0.5, 0.5, 0.8)
                elif byte == 0xCC:
                    color = (0.914, 0.306, 0.467, 0.8)
                elif 0x20 <= byte <= 0x7E:
                    color = (0.5, 1, 1, 0.8)
                else:
                    color = (1.0, 1.0, 1.0, 1.0)
                imgui.text_colored(color, f"{byte:02X} ")
                if i < len(chunk) - 1:
                    imgui.same_line()
            imgui.same_line()
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            imgui.text_colored((0.7, 0.7, 0.7, 1.0), ascii_str)
        imgui.end_child()

    def _get_hex_dump(self) -> str:
        """
        Constructs the hex dump as a single string.
        
        Returns:
            The complete hex dump with addresses and ASCII representation.
        """
        lines: List[str] = []
        data = self.memory_data
        bytes_per_line = 16

        for offset in range(0, len(data), bytes_per_line):
            chunk = data[offset:offset+bytes_per_line]
            line_addr = f"{offset:08X}:"
            hex_bytes = [f"{b:02X}" for b in chunk]
            hex_str = " ".join(hex_bytes)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{line_addr}  {hex_str}  {ascii_str}")
        return "\n".join(lines)

    # --------------------------------------------------------------------------
    # Helpers to Draw Process and Memory Controls
    # --------------------------------------------------------------------------
    def _draw_process_management(self) -> None:
        """
        Draws the auto-complete widget for processes and the attach/detach/refresh buttons.
        """
        # Affiche l'auto-complétion pour la liste des processus.
        proc_input_focused = False
        if self.processes:
            self.selected_process_index, self.process_filter, proc_input_focused = \
                AutoCompleteHelper.auto_complete_combo(
                    "Processes##hex",
                    self.selected_process_index,
                    self.processes,
                    self.process_filter,
                    "Type to select Process ..."
                )

        # Détermine la couleur de bordure en fonction de la session.
        border_color = (0.702, 0.349, 0.349, 1) if self.session else (1, 1, 1, 0.5)
        imgui.push_style_color(imgui.Col_.border, border_color)

        # Gestion des raccourcis (Ctrl+Enter dans le champ de l'input).
        io = imgui.get_io()
        is_ctrl_down = (io.key_mods & imgui.Key.mod_ctrl) != 0
        is_enter_pressed = imgui.is_key_pressed(imgui.Key.enter)
        if proc_input_focused and is_ctrl_down and is_enter_pressed:
            if not self.session:
                imgui.set_keyboard_focus_here(2)
                threading.Thread(target=self._attach, daemon=True).start()
            else:
                threading.Thread(target=self._detach, daemon=True).start()

        imgui.same_line()

        # Bouton Refresh
        imgui.push_style_color(imgui.Col_.button_active, (0, 0, 0, 0))
        imgui.push_style_color(imgui.Col_.button, (0, 0, 0, 0))
        imgui.push_style_var(imgui.StyleVar_.frame_border_size, 0)
        if imgui.button("\uf021" + "##Refresh Process List hex view"):
            self._load_process_list()
        if imgui.is_item_hovered():
            imgui.begin_tooltip()
            imgui.text("Refresh Process List")
            imgui.end_tooltip()
        imgui.same_line()

        # Bouton Attach / Detach
        if not self.session:
            if imgui.button("\uf0c1" + "##Attach hex view"):
                threading.Thread(target=self._attach, daemon=True).start()
            if imgui.is_item_hovered():
                imgui.begin_tooltip()
                imgui.text("Attach Process")
                imgui.end_tooltip()
        else:
            if imgui.button("\uf127" + "##Detach hex"):
                threading.Thread(target=self._detach, daemon=True).start()
            if imgui.is_item_hovered():
                imgui.begin_tooltip()
                imgui.text("Detach Process")
                imgui.end_tooltip()

        imgui.pop_style_color(2)  # pop button_active and button
        imgui.pop_style_var()     # pop frame_border_size
        imgui.pop_style_color()   # pop border color

    def _draw_memory_controls(self) -> None:
        """
        Draws the memory address input, the dynamic size input, and the read memory button.
        """
        io = imgui.get_io()

        avail_w, _ = imgui.get_content_region_avail()
        imgui.set_next_item_width(avail_w * 0.65)
        changed_addr, new_addr = imgui.input_text("##Address (hex)", self.address_str)
        self.address_str = new_addr

        def do_read() -> None:
            self.is_reading = True
            self._read_memory_frida(self.address_str, self.size_to_read)
            self.is_reading = False

        is_ctrl_down = (io.key_mods & imgui.Key.mod_ctrl) != 0
        is_enter_pressed = imgui.is_key_pressed(imgui.Key.enter)
        # Si le champ d'adresse a le focus et que Ctrl+Enter est pressé, déclenche la lecture
        if imgui.is_item_focused() and is_ctrl_down and is_enter_pressed:
            do_read()
            imgui.set_keyboard_focus_here(-1)

        imgui.same_line()
        imgui.set_next_item_width(avail_w * 0.3)
        changed_size, new_size = imgui.input_int("##Size to read hex view", self.size_to_read, 1, 16)
        if changed_size:
            self.size_to_read = max(0, new_size)
            threading.Thread(target=do_read, daemon=True).start()

        if imgui.button("Read Memory##hex"):
            threading.Thread(target=do_read, daemon=True).start()

        imgui.same_line()
        if self.is_reading:
            imgui.text_colored((1.0, 1.0, 0.0, 1.0), "Reading...")
        else:
            imgui.text_disabled("Idle")

    # --------------------------------------------------------------------------
    # Main GUI Rendering
    # --------------------------------------------------------------------------
    def draw_gui(self) -> None:
        """Renders the GUI for the hex viewer."""
        if not self.is_open:
            return

        opened, self.is_open = self.begin_ui_window("Memory Hex View")
        if not opened:
            imgui.end()
            self.end_window_ui()
            return
        
        if self.session:
            imgui.push_style_color(imgui.Col_.border, (0.702, 0.349, 0.349, 1))
        self._draw_process_management()
        if self.session:
            imgui.pop_style_color()

        imgui.separator()
        self._draw_memory_controls()
        imgui.separator()

        imgui.text(self.status_msg)
        imgui.separator()

        # Bouton pour copier le hex dump dans le presse-papiers.
        if imgui.button("Copy"):
            hex_dump_str = self._get_hex_dump()
            try:
                import pyperclip
                pyperclip.copy(hex_dump_str)
                self.status_msg = "Hex dump copied to clipboard."
            except ImportError:
                self.status_msg = "pyperclip not installed; cannot copy output."

        imgui.separator()
        imgui.push_style_var(imgui.StyleVar_.item_spacing, (4, 4))
        if self.memory_data:
            self._draw_hex_dump()
        else:
            imgui.text_disabled("No data")
        imgui.pop_style_var()

        imgui.end()
        self.end_window_ui()
