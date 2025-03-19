"""
Module: text_logger.py

This module provides two types of loggers:
    - TextLogger: A text-based logger with colorization, token filtering, and auto-scrolling.
    - TableLogger: A table-based logger for displaying structured log entries (hooked calls).
    
It also defines the TableLogEntry class which represents an individual entry in the table logger.
"""

import re
import logging
import uuid
from typing import (
    Callable,
    List,
    Tuple,
    Optional,
    Dict,
    Any,
    Union,
)

from imgui_bundle import imgui
from utils import Utils

logger: logging.Logger = logging.getLogger(__name__)

# Type alias for a colored text segment: (text, RGBA color)
ColoredSegment = Tuple[str, Tuple[float, float, float, float]]
# Type alias for a log entry used in TextLogger: (list of colored segments, log level)
LogEntry = Tuple[List[ColoredSegment], str]


class TextLogger:
    """
    TextLogger with colorization, token filtering, and auto-scroll functionality.
    
    Attributes:
        logs (List[LogEntry]): List of log entries.
        auto_scroll (bool): Whether auto-scroll is enabled.
        filter_text (str): Text used to filter logs (tokens separated by spaces).
        filter_level (str): Log level filter (e.g. "ALL", "INFO", etc.).
        levels (List[str]): Available log levels.
        _uuid (uuid.UUID): Unique identifier for ImGui widget identification.
    """

    def __init__(self) -> None:
        self.logs: List[LogEntry] = []
        self.auto_scroll: bool = True
        self.filter_text: str = ""
        self.filter_level: str = "ALL"
        self.levels: List[str] = ["ALL", "INFO", "DEBUG", "WARNING", "ERROR"]
        self._uuid: uuid.UUID = uuid.uuid4()

    def _parse_log_line(self, text: str) -> List[ColoredSegment]:
        """
        Parses a log line and returns a list of colored text segments.
        
        Args:
            text (str): The log line text.
        
        Returns:
            List[ColoredSegment]: A list of tuples containing text segments and their RGBA color.
        """
        lighter = [0.3, 0.2, 0.2, 0]

        # Define a color palette as a dictionary for clarity
        color_palette = {
            'red':    [0.7, 0.35, 0.35, 1.0],
            'green':  [0.35, 0.7, 0.35, 1.0],
            'blue':   [0.35, 0.55, 0.7, 1.0],
            'yellow': [0.7, 0.55, 0.35, 1.0],
            'purple': [0.55, 0.4, 0.55, 1.0],
            'cyan':   [0.25, 0.55, 0.55, 1.0],
            'magenta':[0.75, 0.25, 0.75, 1.0],
        }

        def addition(couple):
            a, b = couple
            res = a + b
            if a < 0.5:
                return a
            if a + b < 1.0:
                return res
            else:
                return 1.0

        # Adjust each color by adding the 'lighter' value
        for key, color in color_palette.items():
            new_color = tuple(map(addition, zip(color, lighter)))
            color_palette[key] = new_color

        segments: List[ColoredSegment] = []
        if text.startswith("Hooking de"):
            segments.append((text, tuple(color_palette['red'])))
        elif text.startswith("[+] Appel de "):
            # Regex: match "[+] Appel de " then capture function name until "(" is encountered.
            m = re.match(r'^(\[\+\] Appel de )(.+?)(\()$', text)
            if m:
                segments.append((m.group(1), tuple(color_palette['green'])))  # "[+] Appel de " part
                segments.append((m.group(2), tuple(color_palette['red'])))    # function name part
                segments.append((m.group(3), tuple(color_palette['green'])))  # the "(" character
            else:
                segments.append((text, tuple(color_palette['green'])))
        elif text.startswith("[-] Retour de "):
            # Regex: match "[-] Retour de ", capture function name until " = ", then capture the rest.
            m = re.match(r'^(\[\-\] Retour de )(.+?)( = )(.*)$', text)
            if m:
                segments.append((m.group(1), tuple(color_palette['yellow'])))  # "[-] Retour de " part
                segments.append((m.group(2), tuple(color_palette['red'])))     # function name part
                segments.append((m.group(3), tuple(color_palette['yellow'])))  # " = " part
                segments.append((m.group(4), tuple(color_palette['blue'])))    # return value part
            else:
                segments.append((text, tuple(color_palette['yellow'])))
        elif text.startswith("    "):
            # Regex: match four spaces, then an identifier, then " ( ... ) = " and the remainder.
            m = re.match(r'^( {4})(\S+)( \((.*?)\) = )(.*)$', text)
            if m:
                segments.append((m.group(1), tuple(color_palette['cyan'])))      # leading spaces
                segments.append((m.group(2), tuple(color_palette['magenta'])))   # identifier
                segments.append((m.group(3), tuple(color_palette['cyan'])))      # " ( ... ) = " part
                segments.append((m.group(5), tuple(color_palette['purple'])))    # remaining text
            else:
                segments.append((text, tuple(color_palette['purple'])))
        elif text.startswith(")"):
            segments.append((text, tuple(color_palette['green'])))
        elif text.startswith("    Buffer"):
            segments.append((text, tuple(color_palette['blue'])))
        elif text.startswith("0x"):
            segments.append((text, tuple(color_palette['green'])))
        elif text.startswith("Erreur") or text.startswith("Error"):
            segments.append((text, tuple(color_palette['red'])))
        else:
            segments.append((text, (1.0, 1.0, 1.0, 1)))
        return segments



    def _matches_filter(self, full_text: str) -> bool:
        """
        Checks if the provided full_text matches the current filter tokens.
        
        Args:
            full_text (str): The text to check against the filter.
        
        Returns:
            bool: True if all filter tokens are present (case-insensitive) or if no filter is set.
        """
        if not self.filter_text:
            return True
        tokens: List[str] = self.filter_text.lower().split()
        return all(token in full_text.lower() for token in tokens)

    def add_log(self, text: str, level: str = "INFO") -> None:
        """
        Adds a log entry after parsing and colorizing the text.
        
        Args:
            text (str): The log message.
            level (str, optional): The log level (default is "INFO").
        """
        segments: List[ColoredSegment] = self._parse_log_line(text)
        if segments:
            self.logs.append((segments, level))

    def clear_logs(self) -> None:
        """
        Clears all log entries.
        """
        self.logs.clear()

    def copy_logs_to_clipboard(self) -> None:
        """
        Copies the filtered logs to the clipboard.
        
        TODO: Duplicate with code in draw.
        """
        try:
            import pyperclip
        except ImportError:
            return

        filtered_texts: List[str] = []
        for segments, lvl in self.logs:
            if self.filter_level != "ALL" and lvl != self.filter_level:
                continue
            full_text: str = "".join(s for s, _ in segments)
            if self.filter_text:
                tokens: List[str] = self.filter_text.lower().split()
                # The log is displayed only if all tokens are present.
                if not all(token in full_text.lower() for token in tokens):
                    continue
            filtered_texts.append(full_text)
        if filtered_texts:
            pyperclip.copy("\n".join(filtered_texts))

    def save_logs_to_file(self, filename: str) -> None:
        """
        Saves the filtered logs to a file.
        
        Args:
            filename (str): The file name to save the logs to.
        """
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("Time,EventType,Process,Function,Return,Args,HookID,Level\n")
                for segments, lvl in self.logs:
                    if self.filter_level != "ALL" and lvl != self.filter_level:
                        continue
                    full_text: str = "".join(s for s, _ in segments)
                    if self.filter_text:
                        tokens: List[str] = self.filter_text.lower().split()
                        # The log is displayed only if all tokens are present.
                        if not all(token in full_text.lower() for token in tokens):
                            continue
                    f.write(f"[{lvl}] {full_text}\n")
        except Exception as e:
            logger.error(f"Error saving logs: {e}")

    def draw(self) -> None:
        """
        Renders the TextLogger UI using ImGui.
        This includes the filter input, log display, and action buttons.
        """
        imgui.set_next_item_width(-215)
        # Input field for filter text.
        _, self.filter_text = imgui.input_text_with_hint("##Text Filter", "Type text to filter logs", self.filter_text)
        imgui.same_line()
        imgui.set_next_item_width(200)
        
        if imgui.begin_combo("##Level", self.filter_level):
            for lvl in self.levels:
                sel, _ = imgui.selectable(lvl, self.filter_level == lvl)
                if sel:
                    self.filter_level = lvl
            imgui.end_combo()

        avail_w, avail_h = imgui.get_content_region_avail()
        if avail_h < 300:
            avail_h = 300

        imgui.push_style_color(imgui.Col_.child_bg, (0, 0, 0, 0.5))
        imgui.push_style_var(imgui.StyleVar_.child_rounding, 5)
        imgui.begin_child("TextLoggerChild", (avail_w, avail_h - 40)) # space before button at the end
        imgui.dummy((10, 10))
        imgui.indent(10)
        
        for segments, lvl in self.logs:
            if self.filter_level != "ALL" and lvl != self.filter_level:
                continue
            full_text: str = "".join(s for s, _ in segments)
            if self.filter_text:
                if not self._matches_filter(full_text):
                    continue

            first_segment: bool = True
            for seg_text, seg_color in segments:
                if not first_segment:
                    imgui.same_line()
                imgui.text_colored(seg_color, seg_text)
                first_segment = False

        # Manage scrolling behavior.
        if imgui.get_io().mouse_wheel != 0:
            self.auto_scroll = False

        if self.auto_scroll:
            imgui.set_scroll_here_y(1.0)

        imgui.end_child()
        imgui.pop_style_color()
        imgui.pop_style_var()

        imgui.push_id(str(self._uuid))
        if imgui.button("Clear"):
            self.clear_logs()
        imgui.same_line()
        if imgui.button("Copy"):
            self.copy_logs_to_clipboard()
        imgui.same_line()
        if imgui.button("Save"):
            self.save_logs_to_file("logs_frida.txt")

        imgui.same_line()
        _, self.auto_scroll = imgui.checkbox("Auto-scroll", self.auto_scroll)
        imgui.pop_id()


class TableLogEntry:
    """
    Represents a log entry for the global logs table.

    Args:
        event_type (str): The event type (e.g., "call", "ret", "info", etc.).
        process_str (str): The associated process string.
        function_name (str): The name of the function.
        arguments (str): Log arguments.
        return_value (str): The return value.
        timestamp (str): The timestamp.
        hook_id (int): The hook identifier.
        address (str, optional): The associated address (default is an empty string).
        level (str, optional): The log level (default is "INFO").
    """

    def __init__(
        self,
        event_type: str,
        process_str: str,
        function_name: str,
        arguments: str,
        return_value: str,
        timestamp: str,
        hook_id: int,
        address: str = "",
        level: str = "INFO",
    ) -> None:
        self.event_type: str = event_type
        self.process_str: str = process_str
        self.function_name: str = function_name
        self.arguments: str = arguments
        self.return_value: str = return_value
        self.timestamp: str = timestamp
        self.hook_id: int = hook_id
        self.address: str = address
        self.level: str = level

        if self.address is None:
            self.address = ""


class TableLogger:
    """
    A table-based logger that displays a structured history of hooked calls.
    
    Attributes:
        log_entries (List[TableLogEntry]): List of table log entries.
        filter_text (str): Text used to filter logs (tokens separated by spaces).
        filter_level (str): Log level filter.
        levels (List[str]): Available log levels.
        auto_scroll (bool): Whether auto-scroll is enabled.
        main_app (Optional[Any]): Reference to the main application (used to retrieve hook colors).
    """

    def __init__(self, main_app: Optional[Any] = None) -> None:
        self.log_entries: List[TableLogEntry] = []
        self.filter_text: str = ""
        self.filter_level: str = "ALL"
        self.levels: List[str] = ["ALL", "INFO", "DEBUG", "WARNING", "ERROR"]
        self.auto_scroll: bool = True
        self.main_app: Optional[Any] = main_app

    def _matches_filter(self, text: str) -> bool:
        """
        Checks if the provided text matches the current filter tokens.
        
        Args:
            text (str): The text to check.
        
        Returns:
            bool: True if all filter tokens are present (case-insensitive) or if no filter is set.
        """
        if not self.filter_text:
            return True
        tokens: List[str] = self.filter_text.lower().split()
        return all(token in text.lower() for token in tokens)

    def add_log_line(
        self,
        text: str,
        process_str: str = "",
        hook_id: int = 0,
        timestamp: str = "",
        address: str = "",
        funcname: str = "",
        level: str = "INFO",
    ) -> None:
        """
        Adds a log line to the table logger.
        
        The method handles different log types: call logs, return logs, argument logs, and info logs.
        
        Args:
            text (str): The log text.
            process_str (str, optional): Associated process string.
            hook_id (int, optional): Hook identifier.
            timestamp (str, optional): Timestamp (if empty, it is generated).
            address (str, optional): Associated address.
            funcname (str, optional): Function name.
            level (str, optional): Log level (default "INFO").
        """
        if not timestamp:
            timestamp = Utils.current_time_millis()

        if text.strip() in [")", "),"]:
            return

        call_match = re.match(r'^\[\+\] Appel de ([^\(]+)\($', text)
        ret_match = re.match(r'^\[\-\] Retour de ([^=]+)\s*=\s*(.*)$', text)

        if call_match:
            entry = TableLogEntry("call", process_str, funcname, "", "", timestamp, hook_id, address, level)
            self.log_entries.append(entry)
            return

        if ret_match:
            ret_val: str = ret_match.group(2).strip()
            entry = TableLogEntry("ret", process_str, funcname, "", ret_val, timestamp, hook_id, address, level)
            self.log_entries.append(entry)
            return

        if text.startswith("    "):
            if self.log_entries:
                last_entry: TableLogEntry = self.log_entries[-1]
                if last_entry.event_type == "call" and last_entry.hook_id == hook_id:
                    if last_entry.arguments:
                        last_entry.arguments += "\n" + text.strip()
                    else:
                        last_entry.arguments = text.strip()
                    return
            entry = TableLogEntry("args", process_str, funcname, text.strip(), "", timestamp, hook_id, address, level)
            self.log_entries.append(entry)
        else:
            entry = TableLogEntry("info", process_str, funcname, text.strip(), "", timestamp, hook_id, address, level)
            self.log_entries.append(entry)

    def clear_logs(self) -> None:
        """
        Clears all table log entries.
        """
        self.log_entries.clear()

    def copy_logs_to_clipboard(self) -> None:
        """
        Copies the filtered table logs to the clipboard in CSV format.
        """
        try:
            import pyperclip
        except ImportError:
            return
        lines: List[str] = []
        for entry in self.log_entries:
            row_text: str = (
                f"{entry.timestamp} {entry.event_type} {entry.process_str} "
                f"{entry.function_name} {entry.return_value} {entry.arguments} {entry.address}"
            )
            if self.filter_text:
                tokens: List[str] = self.filter_text.lower().split()
                if not all(token in row_text.lower() for token in tokens):
                    continue
            if self.filter_level != "ALL" and entry.level != self.filter_level:
                continue
            safe_args: str = entry.arguments.replace("\n", " ").replace("'", "\\'")
            safe_return_value: str = entry.return_value.replace("\n", " ").replace("'", "\\'")
            line: str = f"{entry.timestamp}, {entry.event_type}, {entry.process_str}, {entry.function_name}, \"{safe_return_value}\", \"{safe_args}\", {entry.hook_id}, {entry.level}"

            lines.append(line)
        pyperclip.copy("\n".join(lines))

    def save_logs_to_file(self, filename: str = "logs_global_table.csv") -> None:
        """
        Saves the filtered table logs to a CSV file.
        
        Args:
            filename (str, optional): The file name to save to. Defaults to "logs_global_table.csv".
        """
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("Time,EventType,Process,Function,Return,Args,HookID,Level\n")
                for entry in self.log_entries:
                    row_text: str = (
                        f"{entry.timestamp} {entry.event_type} {entry.process_str} "
                        f"{entry.function_name} {entry.return_value} {entry.arguments} {entry.address}"
                    )
                    if self.filter_text:
                        tokens: List[str] = self.filter_text.lower().split()
                        if not all(token in row_text.lower() for token in tokens):
                            continue
                    if self.filter_level != "ALL" and entry.level != self.filter_level:
                        continue
                    safe_args: str = entry.arguments.replace("\n", " ").replace("'", "\\'")
                    safe_return_value: str = entry.return_value.replace("\n", " ").replace("'", "\\'")
                    line: str = f"{entry.timestamp}, {entry.event_type}, {entry.process_str}, {entry.function_name}, \"{safe_return_value}\", \"{safe_args}\", {entry.hook_id}, {entry.level}\n"

                    f.write(line)
        except Exception as ex:
            logger.error(f"Error saving CSV logs: {ex}")

    def _menu_copy_cell(self, value: str, unique_id: str) -> None:
        imgui.push_style_var(imgui.StyleVar_.window_padding, (0, 0))
        imgui.push_style_var(imgui.StyleVar_.item_spacing, (0, 0))
        imgui.push_style_color(imgui.Col_.window_bg, (1,0,0,1))
        imgui.push_style_color(imgui.Col_.frame_bg, (1,0,0,1))
        imgui.push_style_color(imgui.Col_.popup_bg, (1,0,0,1))
        if imgui.begin_popup_context_item("CopyCell_" + unique_id):
            is_open = True
            imgui.dummy((100,10))
            if imgui.selectable("Copy", is_open):
                try:
                    import pyperclip
                    pyperclip.copy(value)
                except ImportError:
                    pass
            imgui.dummy((100,10))

            imgui.end_popup()
        imgui.pop_style_var(2)
        imgui.pop_style_color(3)

    def draw(self) -> None:
        """
        Renders the TableLogger UI using ImGui.
        Displays the filter inputs, action buttons, and the log table.
        """
        imgui.set_next_item_width(-205)
        _, self.filter_text = imgui.input_text_with_hint("##Text Filter", "Type text to filter logs", self.filter_text)
        imgui.same_line()
        imgui.set_next_item_width(200)
        if imgui.begin_combo("##Level", self.filter_level):
            for lvl in self.levels:
                sel, _ = imgui.selectable(lvl, self.filter_level == lvl)
                if sel:
                    self.filter_level = lvl
            imgui.end_combo()

        avail_w, avail_h = imgui.get_content_region_avail()
        if avail_h < 100:
            avail_h = 300

        imgui.begin_child("TableLoggerChild", (avail_w, avail_h - 40))
        table_flags = (imgui.TableFlags_.borders |
                    imgui.TableFlags_.row_bg |
                    imgui.TableFlags_.resizable |
                    imgui.TableFlags_.highlight_hovered_column |
                    imgui.TableFlags_.scroll_x | imgui.TableFlags_.scroll_y)
        if imgui.begin_table("TableLog", 7, table_flags, (avail_w, avail_h - 40)):
            imgui.table_setup_column("Time")
            imgui.table_setup_column("Type")
            imgui.table_setup_column("Process")
            imgui.table_setup_column("Func")
            imgui.table_setup_column("Address")
            imgui.table_setup_column("Return")
            imgui.table_setup_column("Args")
            imgui.table_setup_scroll_freeze(6, 1)
            imgui.table_headers_row()

            for i, entry in enumerate(self.log_entries):
                try :
                    row_text = ", ".join([
                        entry.timestamp,
                        entry.event_type,
                        entry.process_str,
                        entry.function_name,
                        entry.return_value,
                        entry.arguments,
                        entry.address
                    ])
                except Exception:
                    print("Error happend in TableLogger.draw(), probably a value is None")
                    print(Exception)
                    imgui.end_table()
                    imgui.end_child()
                    return
                
                # Appliquer les filtres
                if self.filter_text:
                    tokens = self.filter_text.lower().split()
                    if not all(token in row_text.lower() for token in tokens):
                        continue
                if self.filter_level != "ALL" and entry.level != self.filter_level:
                    continue

                imgui.table_next_row()

                # Colonne Time
                imgui.table_set_column_index(0)
                imgui.text(entry.timestamp)
                self._menu_copy_cell(entry.timestamp, f"{i}_time")

                # Colonne Type
                imgui.table_set_column_index(1)
                if entry.event_type == "call":
                    event_color = (0.0, 1.0, 0.0, 1.0)
                elif entry.event_type == "ret":
                    event_color = (1.0, 0.0, 0.0, 1.0)
                else:
                    event_color = (1.0, 1.0, 1.0, 1.0)
                imgui.text_colored(event_color, entry.event_type)
                self._menu_copy_cell(entry.event_type, f"{i}_type")

                # Colonne Process
                imgui.table_set_column_index(2)
                imgui.text(entry.process_str)
                self._menu_copy_cell(entry.process_str, f"{i}_process")

                # Colonne Function
                imgui.table_set_column_index(3)
                hook_color = (1.0, 1.0, 1.0, 1.0)
                if self.main_app is not None:
                    hook_color = self.main_app.get_hook_color(entry.hook_id) or hook_color
                imgui.text_colored(hook_color, entry.function_name)
                self._menu_copy_cell(entry.function_name, f"{i}_func")

                # Colonne Address
                imgui.table_set_column_index(4)
                display_address = entry.address if entry.address != "INFO" else ""
                if self.main_app is not None:
                    hook_color = self.main_app.get_hook_color(entry.hook_id) or hook_color
                imgui.text_colored(hook_color, display_address)
                self._menu_copy_cell(display_address, f"{i}_address")

                # Colonne Return
                imgui.table_set_column_index(5)
                imgui.text(entry.return_value)
                self._menu_copy_cell(entry.return_value, f"{i}_return")

                # Colonne Args
                imgui.table_set_column_index(6)
                imgui.text(entry.arguments)
                self._menu_copy_cell(entry.arguments, f"{i}_args")

            imgui.end_table()

            if imgui.get_io().mouse_wheel != 0:
                self.auto_scroll = False
            if self.auto_scroll:
                imgui.set_scroll_here_y(1.0)

        imgui.end_child()

        if imgui.button("Clear##table"):
            self.clear_logs()
        imgui.same_line()
        if imgui.button("Copy##table"):
            self.copy_logs_to_clipboard()
        imgui.same_line()
        if imgui.button("Save##table"):
            self.save_logs_to_file("logs_global_table.csv")
        imgui.same_line()
        _, self.auto_scroll = imgui.checkbox("Auto-scroll##table", self.auto_scroll)

