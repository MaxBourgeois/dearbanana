import base64
import threading
import logging
import frida

from typing import Any, Dict, List, Optional, Tuple, Union
from imgui_bundle import imgui

from commands.command_palette import AutoCompleteHelper
from ui_windows.fullscreenable_ui import FullscreenableUI

# Capstone for disassembly
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL
except ImportError:
    Cs = None

from pygments import lex as pyglex
from pygments.lexers import NasmLexer
from pygments.token import Token, Comment, Keyword, Name, Literal, Operator, Punctuation, Text

logger: logging.Logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# Helper: Build Frida Script
# ------------------------------------------------------------------------------
def _build_frida_script(addr_hex: str, size: int) -> str:
    """
    Builds the Frida script to read memory and return the bytes in base64.

    Parameters:
        addr_hex (str): The base address in hexadecimal (as a string).
        size (int): The number of bytes to read.

    Returns:
        str: The complete JavaScript code for the Frida script.
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
# Disassembly Viewer Class
# ------------------------------------------------------------------------------
class DisasViewerUI(FullscreenableUI):
    """
    Widget that attaches to a process, reads a block of memory, and displays the disassembled
    assembly code with syntax highlighting using Pygments.
    """

    def __init__(self, parent_app: Any) -> None:
        """
        Initializes a new Disassembly Viewer UI.

        Parameters:
            parent_app (Any): Reference to the parent application.
        """
        super().__init__()
        self.parent_app: Any = parent_app
        self.is_open: bool = True
        self.device: Optional[frida.Device] = None
        self.session: Optional[frida.Session] = None
        self.processes: List[str] = []
        self.process_map: Dict[int, int] = {}
        self.selected_process_index: int = 0
        self.process_filter: str = ""

        # Default memory address to read (as string)
        self.address_str: str = "0x7ffbc41a35a0"
        # Number of bytes to read
        self.size_to_read: int = 128
        # Data read from memory
        self.memory_data: bytes = b""
        # Status message for the UI
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
        """
        Loads the list of available processes from the local device.
        """
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
        """
        Attaches the Frida session to the selected process.
        """
        if self.session:
            self._detach()
        try:
            pid: int = self.process_map[self.selected_process_index]
            self.session = self.device.attach(pid)  # type: ignore
            self.status_msg = f"Attached to PID {pid}"
        except Exception as e:
            self.status_msg = f"Attach error: {e}"
            self.session = None

    def _detach(self) -> None:
        """
        Detaches the Frida session from the current process.
        """
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
        Reads memory via Frida and decodes the base64 result.

        Parameters:
            addr_hex (str): The address (as a hex string) to read from.
            size (int): The number of bytes to read.
        """
        if not self.session:
            self.status_msg = "Not attached to a process!"
            return

        # Validate/evaluate the hexadecimal address expression
        try:
            addr_eval: Any = eval(addr_hex)
        except Exception as e:
            self.status_msg = f"Address parsing error: {e}"
            return

        if not isinstance(addr_eval, int):
            self.status_msg = "Address expression did not evaluate to an integer."
            return

        frida_script: str = _build_frida_script(f"0x{addr_eval:x}", size)
        message_received = threading.Event()

        def on_message(message: Dict[str, Any], data: Any) -> None:
            payload: Dict[str, Any] = message.get("payload", {})
            msg_type: str = payload.get("type", "")
            if msg_type == "hexreader":
                b64_str: str = payload.get("base64", "")
                if b64_str:
                    try:
                        self.memory_data = base64.b64decode(b64_str)
                        self.status_msg = f"Read {len(self.memory_data)} bytes at 0x{addr_eval:X}"
                    except Exception as ex:
                        self.memory_data = b""
                        self.status_msg = f"Error decoding base64: {ex}"
                else:
                    self.memory_data = b""
                    self.status_msg = "Read 0 bytes (maybe invalid address?)"
            elif msg_type == "error":
                err: str = payload.get("stack", "Unknown error")
                self.status_msg = f"Frida script error: {err}"
            message_received.set()

        try:
            script = self.session.create_script(frida_script)
            script.on("message", on_message)
            script.load()
            # Wait up to 1 second for a response
            if not message_received.wait(timeout=1.0):
                self.status_msg = "Timeout reading memory."
            script.unload()
        except Exception as e:
            self.status_msg = f"Frida script error: {e}"

    # --------------------------------------------------------------------------
    # Disassembly + Syntax Highlighting
    # --------------------------------------------------------------------------
    def _draw_colored_disassembly(self) -> None:
        """
        Disassembles the memory data and displays the instructions with syntax coloring using Pygments.
        Each line is tokenized and displayed token by token.
        """
        if not Cs:
            imgui.text_colored((1.0, 0.5, 0.5, 1.0), "[Capstone not installed]")
            return
        if not pyglex or not NasmLexer:
            imgui.text_colored((1.0, 0.5, 0.5, 1.0), "[Pygments not installed]")
            return

        imgui.begin_child("AsmColorChild", imgui.ImVec2(0, 0))

        # Configure Capstone
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
        cs.syntax = CS_OPT_SYNTAX_INTEL

        try:
            base_addr: int = int(eval(self.address_str))
        except Exception:
            base_addr = 0

        instructions = cs.disasm(self.memory_data, base_addr)

        # Define token colors for Pygments tokens
        token_colors: Dict[Any, Tuple[float, float, float, float]] = {
            Keyword:        (0.0, 0.75, 1.0, 1.0),  # Keywords (mnemonics) in cyan
            Comment:        (0.5, 0.5, 0.5, 1.0),    # Comments in gray
            Name.Builtin:   (0.5, 1.0, 1.0, 1.0),    # Built-in names (e.g. registers) in light cyan
            Name:           (1.0, 1.0, 1.0, 1.0),    # General names in white
            Literal.Number: (0.914, 0.306, 0.467, 1.0),# Numbers in magenta
            Operator:       (1.0, 1.0, 1.0, 1.0),
            Punctuation:    (1.0, 1.0, 1.0, 1.0),
            Text:           (1.0, 1.0, 1.0, 1.0),
        }

        def get_color(tok_type: Any) -> Tuple[float, float, float, float]:
            """
            Returns the color associated with a Pygments token type.

            Parameters:
                tok_type (Any): The Pygments token type.

            Returns:
                Tuple[float, float, float, float]: The RGBA color.
            """
            for ttype, color in token_colors.items():
                if tok_type in ttype:
                    return color
            return (1.0, 1.0, 1.0, 1.0)

        for insn in instructions:
            address_str = f"0x{insn.address:x}:"
            imgui.text_colored((0.0, 0.75, 1.0, 0.7), address_str)
            imgui.same_line()

            line_text = f"{insn.mnemonic} {insn.op_str}"
            from pygments import lex
            tokens = list(lex(line_text, NasmLexer()))
            for i, (tok_type, tok_value) in enumerate(tokens):
                color = get_color(tok_type)
                imgui.text_colored(color, tok_value)
                if i < len(tokens) - 1:
                    imgui.same_line()

        imgui.end_child()

    # --------------------------------------------------------------------------
    # Process and Memory Controls Rendering
    # --------------------------------------------------------------------------
    def _draw_process_management(self) -> None:
        """
        Draws the controls for selecting a process, refreshing the list, and attaching/detaching.
        """
        proc_input_focused: bool = False
        if self.processes:
            (self.selected_process_index,
             self.process_filter,
             proc_input_focused) = AutoCompleteHelper.auto_complete_combo(
                label="Processes##asm",
                current_index=self.selected_process_index,
                items=self.processes,
                filter_str=self.process_filter,
                place_holder="Type to select Process ..."
            )

        # Border color changes based on whether attached or not.
        border_color: Tuple[float, float, float, float] = (0.702, 0.349, 0.349, 1) if self.session else (1, 1, 1, 0.5)
        imgui.push_style_color(imgui.Col_.border, border_color)

        io = imgui.get_io()
        is_ctrl_down: bool = (io.key_mods & imgui.Key.mod_ctrl) != 0
        is_enter_pressed: bool = imgui.is_key_pressed(imgui.Key.enter)
        if proc_input_focused and is_ctrl_down and is_enter_pressed:
            if not self.session:
                imgui.set_keyboard_focus_here(2)
                threading.Thread(target=self._attach, daemon=True).start()
            else:
                threading.Thread(target=self._detach, daemon=True).start()

        imgui.same_line()
        imgui.push_style_color(imgui.Col_.button_active, (0, 0, 0, 0))
        imgui.push_style_color(imgui.Col_.button, (0, 0, 0, 0))
        imgui.push_style_var(imgui.StyleVar_.frame_border_size, 0)
        if imgui.button("\uf021" + "##Refresh Process List asm"):
            self._load_process_list()
        if imgui.is_item_hovered():
            imgui.begin_tooltip()
            imgui.text("Refresh Process List")
            imgui.end_tooltip()
        imgui.same_line()

        if not self.session:
            if imgui.button("\uf0c1" + "##Attach asm"):
                threading.Thread(target=self._attach, daemon=True).start()
            if imgui.is_item_hovered():
                imgui.begin_tooltip()
                imgui.text("Attach Process")
                imgui.end_tooltip()
        else:
            if imgui.button("\uf127" + "##Detach asm"):
                threading.Thread(target=self._detach, daemon=True).start()
            if imgui.is_item_hovered():
                imgui.begin_tooltip()
                imgui.text("Detach Process")
                imgui.end_tooltip()

        imgui.pop_style_color(2)
        imgui.pop_style_var()
        imgui.pop_style_color()

    def _draw_memory_controls(self) -> None:
        """
        Draws the input for the memory address, size, and the read button.
        """
        io = imgui.get_io()
        avail_w, _ = imgui.get_content_region_avail()
        imgui.set_next_item_width(avail_w * 0.65)
        changed_addr, new_addr = imgui.input_text("##Address (hex)", self.address_str)
        if changed_addr:
            self.address_str = new_addr

        def do_read() -> None:
            self.is_reading = True
            self._read_memory_frida(self.address_str, self.size_to_read)
            self.is_reading = False

        is_ctrl_down: bool = (io.key_mods & imgui.Key.mod_ctrl) != 0
        is_enter_pressed: bool = imgui.is_key_pressed(imgui.Key.enter)
        if imgui.is_item_focused() and is_ctrl_down and is_enter_pressed:
            threading.Thread(target=do_read, daemon=True).start()
            imgui.set_keyboard_focus_here(-1)

        imgui.same_line()
        imgui.set_next_item_width(avail_w * 0.3)
        changed_size, new_size = imgui.input_int("##Size to read asm", self.size_to_read, 1, 16)
        if changed_size:
            self.size_to_read = max(0, new_size)
            threading.Thread(target=do_read, daemon=True).start()

        if imgui.button("Read Memory##asm"):
            threading.Thread(target=do_read, daemon=True).start()

        imgui.same_line()
        if self.is_reading:
            imgui.text_colored((1.0, 1.0, 0.0, 1.0), "Reading...")
        else:
            imgui.text_disabled("Idle")

    def _get_assembly_dump(self) -> str:
        """
        Returns a plain text dump of all disassembled instructions.

        Returns:
            str: The disassembly dump as a string.
        """
        if not Cs:
            return "[Capstone not installed]"
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
        cs.syntax = CS_OPT_SYNTAX_INTEL
        cs.skipdata = True
        cs.skip

        try:
            base_addr: int = int(eval(self.address_str))
        except Exception:
            base_addr = 0

        lines: List[str] = []
        for insn in cs.disasm(self.memory_data, base_addr, self.size_to_read):
            line: str = f"0x{insn.address:x}:  {insn.mnemonic} {insn.op_str}"
            lines.append(line)

        return "\n".join(lines)

    # --------------------------------------------------------------------------
    # Main GUI Rendering
    # --------------------------------------------------------------------------
    def draw_gui(self) -> None:
        """
        Renders the main window for the colored assembly view.
        """
        if not self.is_open:
            return

        opened, self.is_open = self.begin_ui_window("Memory Assembly View")
        if not opened:
            imgui.end()
            self.end_window_ui()
            return

        # Process management bar
        if self.session:
            imgui.push_style_color(imgui.Col_.border, (0.702, 0.349, 0.349, 1))
        self._draw_process_management()
        if self.session:
            imgui.pop_style_color()

        imgui.separator()
        self._draw_memory_controls()
        imgui.separator()

        # Display status message
        imgui.text(self.status_msg)
        imgui.separator()

        # "Copy" button: copy the assembly dump to clipboard
        if imgui.button("Copy"):
            asm_dump: str = self._get_assembly_dump()
            try:
                import pyperclip
                pyperclip.copy(asm_dump)
                self.status_msg = "Assembly code copied to clipboard."
            except ImportError:
                self.status_msg = "pyperclip not installed; cannot copy output."

        imgui.separator()
        imgui.push_style_var(imgui.StyleVar_.item_spacing, (4, 4))

        # If memory data is available, display the colored disassembly; otherwise, show "No data"
        if self.memory_data:
            self._draw_colored_disassembly()
        else:
            imgui.text_disabled("No data")

        imgui.pop_style_var()
        imgui.end()
        self.end_window_ui()
