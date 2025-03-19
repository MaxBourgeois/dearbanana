import json
import logging
from typing import Dict, Any, List

from hooking_window import HookWindowUI
from logger_widgets import TableLogEntry
from constants import DEFAULT_PROJECT_FILE

logger = logging.getLogger(__name__)

class ProjectManager:
    """Manages saving and loading project data."""

    def __init__(self, hook_manager, global_log_window):
        self.hook_manager = hook_manager
        self.global_log_window = global_log_window

    def save_project(self, filename: str = DEFAULT_PROJECT_FILE) -> None:
        """
        Saves the current project configuration to a JSON file.

        Args:
            filename (str, optional): The filename to save to (default "project.json").
        """
        project_data: Dict[str, Any] = {"hooks": [], "global_logs": []}

        for hook in self.hook_manager.hook_windows:
            hook_data: Dict[str, Any] = {
                "id": hook.id,
                "pid": hook.pid,
                "process_name": hook.process_name,
                "module": hook.module,
                "function": hook.function,
                "address": hook.address,
                "hook_started": hook.hook_started,
                "trigger_count": hook.trigger_count,
                # script custom actuel
                "js_code": hook.js_code,
                "logs": hook.text_logger.logs,
                "forward_logs_global": hook.forward_logs_to_global,
                "forward_logs_local": hook.forward_logs_to_local,
            }
            project_data["hooks"].append(hook_data)

        # Global logs
        for entry in self.global_log_window.table_logger.log_entries:
            entry_data: Dict[str, Any] = {
                "timestamp": entry.timestamp,
                "event_type": entry.event_type,
                "process_str": entry.process_str,
                "function_name": entry.function_name,
                "return_value": entry.return_value,
                "arguments": entry.arguments,
                "hook_id": entry.hook_id,
                "address": entry.address,
                "level": entry.level,
            }
            project_data["global_logs"].append(entry_data)

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(project_data, f, indent=4)
            logger.info(f"Project saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving project: {e}")

    def load_project(self, filename: str = DEFAULT_PROJECT_FILE) -> None:
        """
        Loads the project configuration from a JSON file.

        Args:
            filename (str, optional): The filename to load from (default "project.json").
        """
        try:
            with open(filename, "r", encoding="utf-8") as f:
                project_data: Dict[str, Any] = json.load(f)
        except Exception as e:
            logger.error(f"Error loading project: {e}")
            return

        # Clear current project data
        self.hook_manager.hook_windows.clear()
        self.hook_manager.hook_colors.clear()
        self.hook_manager.next_hook_id = 1

        # Load hooks
        for hook_data in project_data.get("hooks", []):
            pid: int = hook_data.get("pid", 0)
            process_name: str = hook_data.get("process_name", "")
            module: str = hook_data.get("module", "")
            function: str = hook_data.get("function", "")
            address: str = hook_data.get("address", "")
            js_code: str = hook_data.get("js_code", "")

            new_hook = HookWindowUI(
                hook_id=self.hook_manager.next_hook_id,
                pid=pid,
                process_name=process_name,
                module=module,
                function=function,
                address=address,
                font=self.hook_manager.parent_main_app.font,
                parent_main_app=self.hook_manager.parent_main_app,
                js_code=js_code
            )

            new_hook.text_logger.logs = hook_data.get("logs", [])
            new_hook.trigger_count = hook_data.get("trigger_count", 0)

            new_hook.forward_logs_to_global = hook_data.get("forward_logs_global", True)
            new_hook.forward_logs_to_local = hook_data.get("forward_logs_local", True)

            if hook_data.get("hook_started", False):
                new_hook._start_hooking()

            self.hook_manager.hook_windows.append(new_hook)
            self.hook_manager.hook_colors[self.hook_manager.next_hook_id] = (
                self.hook_manager.parent_main_app._next_auto_color()
            )
            self.hook_manager.next_hook_id += 1

        self.global_log_window.table_logger.log_entries.clear()
        for entry in project_data.get("global_logs", []):
            new_entry = TableLogEntry(
                event_type=entry.get("event_type", ""),
                process_str=entry.get("process_str", ""),
                function_name=entry.get("function_name", ""),
                arguments=entry.get("arguments", ""),
                return_value=entry.get("return_value", ""),
                timestamp=entry.get("timestamp", ""),
                hook_id=entry.get("hook_id", 0),
                address=entry.get("address", ""),
                level=entry.get("level", "INFO"),
            )
            self.global_log_window.table_logger.log_entries.append(new_entry)

        logger.info(f"Project loaded from {filename}")
