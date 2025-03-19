import re
import logging
from typing import List, Dict, Optional, Any, Tuple

from ui_windows.hooking_window import HookWindowUI
from e2e_tests.tests_add_hooks import set_editor_to_inject_for_test

logger: logging.Logger = logging.getLogger(__name__)


class HookWindowManager:
    """
    Manages the creation, storage, and retrieval of HookWindowUI instances.
    The new methods no longer perform fragile parsing and utilize the frida_handler.process_list.
    """

    def __init__(self, parent_main_app: Any) -> None:
        """
        Initializes a new HookWindowManager.

        Parameters:
            parent_main_app (Any): Reference to the main application.
        """
        self.parent_main_app: Any = parent_main_app
        self.hook_windows: List[HookWindowUI] = []
        self.hook_colors: Dict[int, List[float]] = {}
        self.next_hook_id: int = 1

    def _maybe_resolve_process(self, process_str: Optional[str]) -> Tuple[int, str]:
        """
        Attempts to extract a PID and process name from the provided string.

        - If process_str is None, the currently selected process is used.
        - Otherwise, the function tries to parse a string formatted as "Name (PID)",
          or compares the provided name with entries in the process_list.

        Parameters:
            process_str (Optional[str]): The process string.

        Returns:
            Tuple[int, str]: A tuple (pid, process_name). If resolution fails, returns (0, "").
        """
        # If process_str is None, use the currently selected process from the app.
        if process_str is None:
            index: int = self.parent_main_app.selected_process_index
            if 0 <= index < len(self.parent_main_app.frida_handler.process_list):
                pinfo = self.parent_main_app.frida_handler.process_list[index]
                return (pinfo.pid, pinfo.name)
            else:
                # No valid process selected
                return (0, "")

        # Process_str is provided; try parsing "ProcessName (1234)" or just "ProcessName"
        match = re.match(r'^(.*)\((\d+)\)\s*$', process_str.strip())
        if match:
            base_name: str = match.group(1).strip()
            pid: int = int(match.group(2))
            return (pid, base_name)
        else:
            lowerp: str = process_str.strip().lower()
            for pinfo in self.parent_main_app.frida_handler.process_list:
                if pinfo.name.lower() == lowerp:
                    return (pinfo.pid, pinfo.name)
            # No match found; return PID 0 with the trimmed process_str.
            return (0, process_str.strip())

    def _create_hook_internal(
        self,
        pid: int,
        process_name: str,
        module: str,
        function: str,
        address: str
    ) -> Optional[HookWindowUI]:
        """
        Creates the HookWindowUI instance, adds it to the list, and returns the instance.

        Parameters:
            pid (int): The process ID.
            process_name (str): The process name.
            module (str): The module name.
            function (str): The function name.
            address (str): The memory address (if any).

        Returns:
            Optional[HookWindowUI]: The created HookWindowUI instance, or None if creation fails.
        """
        # If pid is 0, consider it a failure.
        if pid == 0:
            self.parent_main_app.status_message = f"Process '{process_name}' not found."
            return None

        hw: HookWindowUI = HookWindowUI(
            hook_id=self.next_hook_id,
            pid=pid,
            process_name=process_name,
            module=module,
            function=function,
            address=address,
            font=self.parent_main_app.font,
            parent_main_app=self.parent_main_app
        )
        hw.window_title = f"{function} #{self.next_hook_id}"
        self.hook_windows.append(hw)

        # Assign an auto-generated color.
        self.hook_colors[self.next_hook_id] = self.parent_main_app._next_auto_color()
        self.next_hook_id += 1

        set_editor_to_inject_for_test(hw.editor)
        return hw

    def create_hook(
        self,
        process: Optional[str] = None,
        module: Optional[str] = None,
        function: Optional[str] = None,
        address: str = ""
    ) -> Optional[HookWindowUI]:
        """
        Creates a new hook by resolving the process (using process_str) and, if necessary,
        the module and function via the selected indices.

        Parameters:
            process (Optional[str], optional): The process string. Defaults to None.
            module (Optional[str], optional): The module name. Defaults to None.
            function (Optional[str], optional): The function name. Defaults to None.
            address (str, optional): The memory address. Defaults to "".

        Returns:
            Optional[HookWindowUI]: The created HookWindowUI instance, or None if creation fails.
        """
        # Resolve process
        pid, proc_name = self._maybe_resolve_process(process)
        if not proc_name:
            proc_name = ""  # Fallback

        # Resolve module if None
        if module is None:
            selected_mod_idx: int = self.parent_main_app.selected_module_index
            if selected_mod_idx in self.parent_main_app.frida_handler.module_map:
                mod_entry = self.parent_main_app.frida_handler.module_map[selected_mod_idx]
                module = mod_entry["name"]
            else:
                module = ""

        # Resolve function if None
        if function is None:
            selected_fun_idx: int = self.parent_main_app.selected_function_index
            func_entry = self.parent_main_app.frida_handler.function_map.get(selected_fun_idx, {})
            function = func_entry.get("name", "")

        # Create the HookWindowUI instance
        hw: Optional[HookWindowUI] = self._create_hook_internal(pid, proc_name, module, function, address)
        return hw

    def get_hook_by_id(self, hook_id: int) -> Optional[HookWindowUI]:
        """
        Retrieves a HookWindowUI instance by its hook ID.

        Parameters:
            hook_id (int): The hook identifier.

        Returns:
            Optional[HookWindowUI]: The matching HookWindowUI instance, or None if not found.
        """
        for hook in self.hook_windows:
            if hook.id == hook_id:
                return hook
        return None

    def remove_hook(self, hook_id: int) -> None:
        """
        Removes the hook with the specified ID.

        Parameters:
            hook_id (int): The hook identifier to remove.
        """
        hook: Optional[HookWindowUI] = self.get_hook_by_id(hook_id)
        if hook:
            self.hook_windows.remove(hook)
            self.hook_colors.pop(hook_id, None)

    def get_hook_color(self, hook_id: int) -> Optional[List[float]]:
        """
        Retrieves the color assigned to the hook with the specified ID.

        Parameters:
            hook_id (int): The hook identifier.

        Returns:
            Optional[List[float]]: The RGBA color of the hook, or None if not found.
        """
        return self.hook_colors.get(hook_id)
