import os
import re
import time
import threading
import logging
import frida
import json
from typing import Any, Dict, Optional, List

from imgui_bundle import imgui

from utils import Utils
from logger_widgets import TextLogger, TableLogEntry
from global_logs_window import GlobalHooksLogUI

logger: logging.Logger = logging.getLogger(__name__)


class FridaHook:
    """
    Manages the Frida hook functionality: process attachment, script injection, and handling script messages.
    """

    def __init__(
        self,
        pid: int,
        process_display: str,
        module: str,
        function: str,
        parent_ui_window: Any,
        custom_js_code: Optional[str] = None
    ) -> None:
        """
        Initializes a new FridaHook.

        Parameters:
            pid (int): The process ID to hook.
            process_display (str): A string formatted as "ProcessName (pid)" for logs and display.
            module (str): The module name (e.g. "kernel32.dll").
            function (str): The function name (e.g. "CreateFileW").
            parent_ui_window (Any): Reference to the HookWindowUI.
            custom_js_code (Optional[str]): Optional custom JavaScript code for hooking.
        """
        self.pid: int = pid
        self.process_display: str = process_display
        self.module: str = module
        self.function: str = function
        self.parent_ui_window: Any = parent_ui_window
        self.session: Optional[frida.Session] = None
        self.script: Optional[frida.Script] = None
        self.custom_js_code: Optional[str] = custom_js_code

    @staticmethod
    def default_js_code_for(module: str, function: str) -> str:
        """
        Generates the default JavaScript code for hooking based on the module and function.

        Parameters:
            module (str): The module name.
            function (str): The function name.

        Returns:
            str: The combined JavaScript code with inserted signatures and replacements.
        """
        script_dir: str = "frida_scripts"
        # Select the appropriate script based on module and function
        if module.lower() == "kernel32.dll" and function.lower() in ["createfilew", "readfile", "writefile"]:
            main_script: str = Utils.read_script_contents(os.path.join(script_dir, "hook_script_sig.js"))
        else:
            main_script: str = Utils.read_script_contents(os.path.join(script_dir, "hook_script.js"))
        # Insert the "function_signatures" code if needed
        signatures_code: str = Utils.read_script_contents(os.path.join(script_dir, "function_signatures.js"))
        combined_script: str = main_script.replace("//@@SIGNATURES@@", signatures_code)
        combined_script = combined_script.replace("%%MODULE%%", module)
        combined_script = combined_script.replace("%%FUNCTION%%", function)
        return combined_script

    def _handle_script_message(self, message: Dict[str, Any], data: Any) -> None:
        """
        Callback for Frida when the script sends a message or encounters an error.

        Parameters:
            message (Dict[str, Any]): The message dictionary from Frida.
            data (Any): Additional data (if any) accompanying the message.
        """
        msg_type: str = message.get("type", "")
        if msg_type == "send":
            payload: str = message["payload"]
            try:
                data_json: Dict[str, Any] = json.loads(payload)
                # Insert HookID, Address, Function if not provided by the script
                if "HookID" not in data_json:
                    data_json["HookID"] = self.parent_ui_window.id
                if "Address" not in data_json:
                    data_json["Address"] = self.parent_ui_window.address
                if "Function" not in data_json:
                    data_json["Function"] = self.function

                # Increment trigger count if this is a 'call' event on the expected function
                if data_json.get("EventType", "").lower() == "call":
                    if data_json["Function"].strip() == self.function.strip():
                        self.parent_ui_window.trigger_count += 1

                # Log the event into the table logger of the global hooks log window
                self.parent_ui_window.parent_main_app.global_hooks_log_window.table_logger.log_entries.append(
                    TableLogEntry(
                        event_type    = data_json.get("EventType", "info"),
                        process_str   = data_json.get("Process", self.process_display),
                        function_name = data_json.get("Function", ""),
                        arguments     = data_json.get("Args", ""),
                        return_value  = data_json.get("Return", ""),
                        timestamp     = data_json.get("Time", Utils.current_time_millis()),
                        hook_id       = data_json.get("HookID", 0),
                        address       = data_json.get("Address", ""),
                        level         = data_json.get("Level", "INFO")
                    )
                )

                # Log a local summary message
                summary: str = f"[{data_json.get('EventType','?')}] {data_json.get('Args','NoArgs')}"
                self.parent_ui_window.add_text_log_line(summary, data_json.get("Level", "INFO"))

            except json.JSONDecodeError:
                # If the message is not JSON, check if it matches a typical call pattern and increment trigger_count if so.
                m = re.search(r'\[\+\] Appel de\s+(.+?)\s*\(', payload)
                if m and m.group(1).strip() == self.function.strip():
                    self.parent_ui_window.trigger_count += 1
                # Log the raw text message
                self.parent_ui_window.add_text_log_line(payload)

        elif msg_type == "error":
            err_msg: str = "Error: " + message.get("stack", "")
            self.parent_ui_window.add_text_log_line(err_msg, level="ERROR")

    def start(self) -> bool:
        """
        Attaches Frida to the specified process and loads the JavaScript hook (custom or default).

        Returns:
            bool: True if the hook started successfully, False otherwise.
        """
        if self.pid <= 0:
            self.parent_ui_window.add_text_log_line(
                f"Invalid PID for process {self.process_display}", "ERROR"
            )
            return False

        try:
            self.session = frida.attach(self.pid)
        except Exception as e:
            self.parent_ui_window.add_text_log_line(f"Attach error: {e}", "ERROR")
            return False

        # Load the script (custom if provided, otherwise default)
        code: str = self.custom_js_code if self.custom_js_code else self.default_js_code_for(self.module, self.function)
        try:
            self.script = self.session.create_script(code)
            self.script.on("message", self._handle_script_message)
            self.script.load()
            self.parent_ui_window.add_text_log_line("Hook started successfully.")
            return True
        except Exception as e:
            self.parent_ui_window.add_text_log_line(f"Script load error: {e}", "ERROR")
            return False

    def stop(self) -> None:
        """
        Unloads the JavaScript hook script and detaches the Frida session.
        """
        if self.script:
            try:
                self.script.unload()
            except Exception as e:
                self.parent_ui_window.add_text_log_line(f"Error unloading script: {e}", "ERROR")
        if self.session:
            try:
                self.session.detach()
            except Exception as e:
                self.parent_ui_window.add_text_log_line(f"Error detaching session: {e}", "ERROR")
        self.script = None
        self.session = None
        self.parent_ui_window.add_text_log_line("Hook stopped.")


class HookWindowUI:
    """
    The ImGui window associated with a hook (displayed as a row in the Hooks Management).
    """

    def __init__(
        self,
        hook_id: int,
        pid: int,
        process_name: str,
        module: str,
        function: str,
        address: str,
        font: Optional[Any] = None,
        parent_main_app: Optional[Any] = None,
        js_code: Optional[str] = None,
    ) -> None:
        """
        Initializes a new HookWindowUI.

        Parameters:
            hook_id (int): Unique hook ID.
            pid (int): Process ID.
            process_name (str): Short process name, e.g. "notepad.exe".
            module (str): Module name, e.g. "kernel32.dll".
            function (str): Function name, e.g. "CreateFileW".
            address (str): Optional hook address (or empty string).
            font (Optional[Any]): Custom font (if any).
            parent_main_app (Optional[Any]): Reference to the main application.
            js_code (Optional[str]): Optional custom JavaScript code; if None, a default is generated.
        """
        self.id: int = hook_id
        self.pid: int = pid
        self.process_name: str = process_name
        # Display string for the process (e.g., "notepad.exe (1234)")
        self.process_display: str = f"{process_name} ({pid})" if pid > 0 else process_name
        self.module: str = module
        self.function: str = function
        self.address: str = address
        self.font: Optional[Any] = font
        self.parent_main_app: Optional[Any] = parent_main_app

        # Window title for the hook window
        self.window_title: str = f"{self.function}" if address else function
        self.is_open: bool = True
        self.show_script_editor: bool = False
        self.trigger_count: int = 0

        # Local text logger for this hook
        self.text_logger: TextLogger = TextLogger()

        from imgui_bundle import imgui_color_text_edit
        TextEditor = imgui_color_text_edit.TextEditor

        # Generate default JS code if not provided
        if js_code is None:
            js_code = FridaHook.default_js_code_for(self.module, self.function)
        self.js_code: str = js_code

        self.editor: Any = TextEditor()
        self.editor.set_text(self.js_code)
        self.editor.set_palette(TextEditor.get_dark_palette())
        try:
            self.editor.set_language_definition(TextEditor.LanguageDefinition.javascript())
        except Exception:
            self.editor.set_language_definition(TextEditor.LanguageDefinition.c_plus_plus())
        self.editor.set_show_whitespaces(False)

        self.hook_started: bool = False
        # Create a FridaHook instance with the current parameters
        self.frida_hook: FridaHook = FridaHook(
            pid=self.pid,
            process_display=self.process_display,
            module=self.module,
            function=self.function,
            parent_ui_window=self,
            custom_js_code=self.js_code
        )
        self.has_been_docked: bool = False
        self.forward_logs_to_global: bool = True
        self.forward_logs_to_local: bool = True
        self.dock_id: int = -1

    def add_text_log_line(self, text: str, level: str = "INFO") -> None:
        """
        Adds a log line to both local and (if enabled) global logs.

        Parameters:
            text (str): The log message.
            level (str): The log level (default is "INFO").
        """
        if self.forward_logs_to_local:
            self.text_logger.add_log(text, level)
        if self.forward_logs_to_global and self.parent_main_app:
            self.parent_main_app.add_log_to_global(
                text, self.process_display, self.id, self.address, self.function
            )

    def _start_hooking(self) -> None:
        """
        Starts the hook if it is not already running.
        """
        if self.hook_started:
            self.text_logger.add_log("Hook is already running.", "WARNING")
            return
        self.trigger_count = 0
        ok: bool = self.frida_hook.start()
        if ok:
            self.hook_started = True

    def _stop_hooking(self) -> None:
        """
        Stops the hook if it is running.
        """
        if self.hook_started:
            self.frida_hook.stop()
            self.hook_started = False

    def reconnect_hook(self) -> bool:
        """
        Stops and then restarts the hook (useful for reattaching).

        Returns:
            bool: True if reconnection was successful, False otherwise.
        """
        self.frida_hook.stop()
        success: bool = self.frida_hook.start()
        if success:
            self.text_logger.add_log(f"Hook reconnected to {self.process_display}.", "DEBUG")
            self.hook_started = True
        else:
            self.text_logger.add_log("Failed to reconnect hook", "ERROR")
            self.hook_started = False
        return success

    def _reload_script(self) -> None:
        """
        Unloads then reloads the JavaScript script from the editor.
        """
        self.frida_hook.stop()
        self.js_code = self.editor.get_text()
        self.frida_hook.custom_js_code = self.js_code
        self.trigger_count = 0
        if self.frida_hook.start():
            self.text_logger.add_log("Script reloaded successfully.", "DEBUG")
            self.hook_started = True
        else:
            self.text_logger.add_log("Error reloading script.", "ERROR")
            self.hook_started = False

    def _draw_hook_settings(self) -> None:
        """
        Draws the read-only fields ("Process", "Library", "Function") along with the Start/Stop/Edit buttons.
        """
        avail_w, _ = imgui.get_content_region_avail()
        third: float = avail_w / 3 - ((imgui.get_style().item_spacing.x / 4) * 3)

        # Process (read-only)
        imgui.set_next_item_width(third)
        imgui.input_text_with_hint("##Process", "Process", self.process_display, imgui.InputTextFlags_.read_only)

        imgui.same_line()
        imgui.set_next_item_width(third)
        imgui.input_text_with_hint("##Library", "Library", self.module, imgui.InputTextFlags_.read_only)

        imgui.same_line()
        imgui.set_next_item_width(third)
        imgui.input_text_with_hint("##Function", "Function", self.function, imgui.InputTextFlags_.read_only)

        if imgui.button("Start Hook"):
            threading.Thread(target=self._start_hooking, daemon=True).start()
        imgui.same_line()
        if imgui.button("Stop Hook"):
            threading.Thread(target=self._stop_hooking, daemon=True).start()
        imgui.same_line()
        if imgui.button("Edit Script"):
            self.show_script_editor = True
            self.editor.set_text(self.js_code)
            imgui.open_popup("Script Editor")
        imgui.same_line()
        if imgui.button("Duplicate Hook"):
            self.parent_main_app.palette_manager.open_duplicate_hook_chain(self)

        imgui.same_line()
        imgui.text(f"Triggers: {self.trigger_count}")

        imgui.same_line()
        changed, is_local_logging = imgui.checkbox("Local log##checkForward", self.forward_logs_to_local)
        if changed:
            self.forward_logs_to_local = is_local_logging
        imgui.same_line()
        changed, is_global_logging = imgui.checkbox("Global log##checkForward", self.forward_logs_to_global)
        if changed:
            self.forward_logs_to_global = is_global_logging

    def _draw_script_editor(self) -> None:
        """
        Draws the JavaScript editor popup for modifying the hook script.
        """
        if not self.show_script_editor:
            return

        w, h = imgui.get_main_viewport().size
        win_w, win_h = (w * 0.8, h * 0.8)

        Utils.draw_overlay(overlay_name="Script Editor")

        imgui.push_style_var(imgui.StyleVar_.window_padding, (10, 10))
        imgui.push_style_var(imgui.StyleVar_.item_spacing, (10, 10))

        modal_opened, is_open = imgui.begin(
            "Script Editor:" + self.function,
            self.show_script_editor,
            imgui.WindowFlags_.no_title_bar | imgui.WindowFlags_.no_move
        )
        if modal_opened:
            imgui.push_style_var(imgui.StyleVar_.child_rounding, 5)
            imgui.set_window_size((win_w, win_h), cond=imgui.Cond_.always)
            imgui.set_window_pos((w / 2 - win_w / 2, h / 2 - win_h / 2), cond=imgui.Cond_.always)

            av_w, av_h = imgui.get_content_region_avail()
            self.editor.render("JS Frida Script", a_size=(av_w, av_h - 60))

            imgui.new_line()
            io = imgui.get_io()
            # Close popup on ESC key
            if imgui.is_key_pressed(imgui.Key.escape, False):
                imgui.close_current_popup()
                is_open = False
            # Reload script on Ctrl+Enter
            if (io.key_mods & imgui.Key.mod_ctrl) and imgui.is_key_pressed(imgui.Key.enter, False):
                threading.Thread(target=self._reload_script, daemon=True).start()

            if imgui.button("Apply"):
                threading.Thread(target=self._reload_script, daemon=True).start()

            imgui.same_line()
            if imgui.button("Close"):
                imgui.close_current_popup()
                is_open = False

            imgui.pop_style_var(1)
            imgui.end()

        imgui.pop_style_var(2)
        self.show_script_editor = is_open

    def draw(self) -> None:
        """
        Draws the main ImGui window for this hook.
        """
        if not self.is_open:
            return
        if not self.has_been_docked:
            self.dock_id = imgui.get_id("HookWindowDock")
            imgui.set_next_window_dock_id(self.dock_id, imgui.Cond_.always)
            self.has_been_docked = True

        # Choose colors based on hook state (running or not)
        if self.hook_started:
            col_inactive: tuple = (0.231, 0.647, 0.361, 0.6)
            col_active: tuple = (0.231, 0.647, 0.361, 0.85)
            col_collapsed: tuple = (0.231, 0.647, 0.361, 0.6)
        else:
            col_inactive = (0.702, 0.349, 0.349, 0.75)
            col_active = (0.702, 0.349, 0.349, 1)
            col_collapsed = (0.702, 0.349, 0.349, 0.75)

        imgui.push_style_color(imgui.Col_.title_bg, col_inactive)
        imgui.push_style_color(imgui.Col_.title_bg_active, col_active)
        imgui.push_style_color(imgui.Col_.title_bg_collapsed, col_collapsed)
        imgui.push_style_color(imgui.Col_.tab, col_inactive)
        imgui.push_style_color(imgui.Col_.tab_selected, col_active)
        imgui.push_style_color(imgui.Col_.tab_hovered, col_active)
        imgui.push_style_color(imgui.Col_.tab_dimmed, col_collapsed)
        imgui.push_style_color(imgui.Col_.tab_dimmed_selected, col_active)

        opened, self.is_open = imgui.begin(self.window_title, self.is_open)
        if opened:
            if self.font:
                imgui.push_font(self.font)
            self._draw_hook_settings()
            imgui.separator()
            self._draw_script_editor()
            # Draw the local log text
            self.text_logger.draw()
            if self.font:
                imgui.pop_font()
        imgui.end()
        imgui.pop_style_color(8)
