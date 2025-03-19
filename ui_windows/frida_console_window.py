import time
import threading
import logging
import frida

from typing import (
    Callable,
    List,
    Tuple,
    Optional,
    Dict,
    Any,
    Union
)

from imgui_bundle import imgui, hello_imgui, imgui_color_text_edit
from utils import Utils
from loggers.logger_widgets import TextLogger
from commands.command_palette import AutoCompleteHelper
from ui_windows.fullscreenable_ui import FullscreenableUI

logger = logging.getLogger(__name__)
TextEditor = imgui_color_text_edit.TextEditor
    
###############################################################################
# FridaConsoleUI: Derived UI widget for a Frida Console.
###############################################################################

class FridaConsoleUI(FullscreenableUI):
    """
    A Frida console window for running JavaScript in an attached process and displaying results.

    Features:
      - Lists local processes via Frida and attaches/detaches to a selected process.
      - Provides a JavaScript editor to run code in the attached process context.
      - Displays logs in a separate panel.
      - Inherits fullscreen toggle functionality from BaseUI (Ctrl+F).
    """
    def __init__(self) -> None:
        super().__init__()
        self.device: Optional[frida.Device] = None
        self.session: Optional[frida.Session] = None
        self.processes: List[str] = []
        self.process_map: Dict[int, int] = {}
        self.selected_process_index: int = -1
        self.process_filter: str = ""
        self.console_editor: TextEditor = TextEditor()

        default_code = (
            """ 
// Example: Enumerate all modules of the attached process
var modules = Process.enumerateModulesSync();
modules.forEach(function(m, index) {
    //send(index + ': ' + m.name);
});
modules[3].enumerateExports().forEach(function(m, index) {
    send(index +  " : " + m.name);
});
            """
        )
        self.console_editor.set_palette(self.console_editor.get_dark_palette())
        self.console_editor.set_text(default_code)
        try:
            self.console_editor.set_language_definition(TextEditor.LanguageDefinition.javascript())
        except Exception:
            pass
        self.console_editor.set_show_whitespaces(False)

        self.logger: TextLogger = TextLogger()

        try:
            self.device = frida.get_local_device()
        except Exception as e:
            self.logger.add_log(f"Local device error: {e}", "ERROR")

        self._load_process_list()

    # --------------------------------------------------------------------------
    # Process Management Methods
    # --------------------------------------------------------------------------
    def _load_process_list(self) -> None:
        """
        Enumerate available processes from the local Frida device and store them.
        Logs any error.
        """
        if not self.device:
            self.logger.add_log("No local device available.", "ERROR")
            return
        try:
            procs = self.device.enumerate_processes()
            self.processes = [f"{p.name} ({p.pid})" for p in procs]
            self.process_map = {i: p.pid for i, p in enumerate(procs)}
            self.logger.add_log(f"{len(self.processes)} processes retrieved.")
        except Exception as e:
            self.logger.add_log(f"Error listing processes: {e}", "ERROR")

    def _attach(self) -> None:
        """
        Attach to the process specified by the currently selected index.
        If already attached, detach first.
        """
        if self.session:
            self._detach()
        try:
            pid = self.process_map[self.selected_process_index]
            self.session = self.device.attach(pid)
            self.logger.add_log(f"Attached to PID {pid}", "DEBUG")
        except Exception as e:
            self.logger.add_log(f"Attach error: {e}", "ERROR")
            self.session = None

    def _detach(self) -> None:
        """
        Detach from the current Frida session if any.
        """
        if not self.session:
            return
        try:
            self.session.detach()
            self.logger.add_log("Session detached.", "DEBUG")
        except Exception as e:
            self.logger.add_log(f"Detach error: {e}", "ERROR")
        finally:
            self.session = None

    def _run_js_script(self) -> None:
        """
        Run the JavaScript code from the editor in the attached process.
        Logs any errors or messages returned by the script.
        """
        if not self.session:
            self.logger.add_log("No attached session!", "ERROR")
            return

        code: str = self.console_editor.get_text()

        def on_message(message: Dict[str, Any], data: Any) -> None:
            msg_type: str = message.get("type", "")
            if msg_type == "send":
                self.logger.add_log(str(message["payload"]), "INFO")
            elif msg_type == "error":
                err_text: str = message.get("stack", "Unknown error")
                self.logger.add_log(err_text, "ERROR")

        try:
            script = self.session.create_script(code)
            script.on("message", on_message)
            script.load()
            time.sleep(0.2)
        except Exception as e:
            self.logger.add_log(f"Script execution error: {e}", "ERROR")

    # --------------------------------------------------------------------------
    # UI Drawing Helpers
    # --------------------------------------------------------------------------
    def _draw_process_management(self) -> None:
        """
        Draws the controls for process selection, refresh, and attach/detach.
        Uses AutoCompleteHelper for the process combo box.
        """
        # Set border color: red when attached, white (with some transparency) otherwise.
        if self.session:
            imgui.push_style_color(imgui.Col_.border, (0.702, 0.349, 0.349, 1))
        proc_input_focused: bool = False
        if self.processes:
            self.selected_process_index, self.process_filter, proc_input_focused = \
                AutoCompleteHelper.auto_complete_combo(
                    label="Processes##asm",
                    current_index=self.selected_process_index,
                    items=self.processes,
                    filter_str=self.process_filter,
                    place_holder="Type to select Process..."
                )
        if self.session:
            imgui.pop_style_color()   # pop border color

        # Keyboard shortcut (Ctrl+Enter) to attach/detach
        io = imgui.get_io()
        is_ctrl_down = (io.key_mods & imgui.Key.mod_ctrl) != 0
        is_enter_pressed = imgui.is_key_pressed(imgui.Key.enter)
        if proc_input_focused and is_ctrl_down and is_enter_pressed:
            if not self.session:
                imgui.set_keyboard_focus_here(1)
                threading.Thread(target=self._attach, daemon=True).start()
            else:
                threading.Thread(target=self._detach, daemon=True).start()
        imgui.same_line()

        # Refresh button
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

        # Attach/Detach button
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

        imgui.pop_style_color(2)  # pop button_active & button
        imgui.pop_style_var()     # pop frame_border_size

    def _draw_code_editor(self) -> None:
        """
        Draws the JavaScript code editor, auto-resizing it based on the content height.
        """
        avail_w, _ = imgui.get_content_region_avail()
        code_size = imgui.calc_text_size(self.console_editor.get_text())
        editor_height = code_size.y
        self.console_editor.render("JS Code Editor", a_size=(avail_w, editor_height))

    def _draw_run_js_button(self) -> None:
        """
        Draws the "Run JS" button that executes the JavaScript in a separate thread.
        """
        if imgui.button("Run JS"):
            threading.Thread(target=self._run_js_script, daemon=True).start()

    # --------------------------------------------------------------------------
    # Main GUI Rendering
    # --------------------------------------------------------------------------
    def draw_gui(self) -> None:
        """
        Main method to render the Frida Console UI.
        This includes:
          - Fullscreen toggling and docking state update (via BaseUI).
          - Process management controls.
          - JS code editor and execution button.
          - Logging panel.
        """
        if not self.is_open:
            return

        # Use the convenience method from BaseUI for window management.
        opened, self.is_open = self.begin_ui_window("Frida Console")
        if not opened:
            imgui.end()
            self.end_window_ui()
            return
        
        imgui.text("Frida console")
        self._draw_process_management()
        imgui.separator()
        self._draw_code_editor()
        imgui.spacing()
        self._draw_run_js_button()
        imgui.separator()
        self.logger.draw()
        imgui.end()
        self.end_window_ui()          
