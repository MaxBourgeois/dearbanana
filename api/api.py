from typing import Any, Dict, List, Optional
from app import FridaHookManagerApp
from ui_windows.hook_window_manager import HookWindowManager

class HookNotFoundError(Exception):
    pass

class FridaError(Exception):
    pass

class FridaHookManagerAPI:
    """
    A simplified interface for manipulating the FridaHookManagerApp.
    """

    def __init__(self, app: FridaHookManagerApp) -> None:
        self.app: FridaHookManagerApp = app

    def _resolve_process(self, process_str: str) -> str:
        import re
        self.app.frida_handler.fetch_processes()

        pid_match = re.search(r'^(.*)\((\d+)\)\s*$', process_str.strip())
        if pid_match:
            return f"{pid_match.group(1).strip()} ({pid_match.group(2)})"

        want_lower = process_str.lower()
        for pinfo in self.app.frida_handler.process_list:
            if pinfo.name.lower() == want_lower:
                return f"{pinfo.name} ({pinfo.pid})"

        return process_str

    def add_hook(
        self,
        process: str,
        module: str,
        function: str,
        js_code: Optional[str] = None,
        address: Optional[str] = None
    ) -> Any:
        """
        Adds a new hook with the specified details.
        The 'process' param can be either "Notepad.exe" or "Notepad.exe (1234)".

        Returns the HookWindowUI object.
        """
        process_resolved = self._resolve_process(process)

        if address is None:
            addr = self.get_function_address(process_name=process_resolved.split('(')[0].strip(),
                                             pid=None,
                                             module_name=module,
                                             function_name=function)
            if addr:
                address = addr

        hook = self.app.hook_manager.create_hook(process_resolved, module, function, address or "")
        if not hook:
            return None

        if js_code is not None:
            hook.js_code = js_code

        return hook

    def get_hook_details(self, hook_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieves detailed information about a hook by its ID.
        """
        hook = self.app.hook_manager.get_hook_by_id(hook_id)
        if hook:
            return {
                "id": hook.id,
                "process": hook.process,
                "module": hook.module,
                "function": hook.function,
                "hook_started": hook.hook_started,
                "trigger_count": hook.trigger_count,
                "js_code": hook.js_code,
                "logs": hook.text_logger.logs,
                "address": hook.address
            }
        return None

    def modify_hook(
        self,
        hook_id: int,
        js_code: Optional[str] = None,
        process: Optional[str] = None,
        module: Optional[str] = None,
        function: Optional[str] = None,
        address: Optional[str] = None
    ) -> bool:
        """
        Modifies the properties of an existing hook.
        """
        hook = self.app.hook_manager.get_hook_by_id(hook_id)
        if not hook:
            return False

        if js_code is not None:
            hook.js_code = js_code
        if process is not None:
            hook.process = self._resolve_process(process)
        if module is not None:
            hook.module = module
        if function is not None:
            hook.function = function
        if address is not None:
            hook.address = address
        return True

    def start_hook(self, hook_id: int) -> bool:
        """
        Starts the hook with the specified ID.
        """
        hook = self.app.hook_manager.get_hook_by_id(hook_id)
        if not hook:
            raise HookNotFoundError(f"Hook with ID {hook_id} not found.")
        try:
            hook._start_hooking()
        except Exception as e:
            raise FridaError(f"Error starting hook {hook_id}: {e}") from e
        return True

    def stop_hook(self, hook_id: int) -> bool:
        """
        Stops the hook with the specified ID.
        """
        hook = self.app.hook_manager.get_hook_by_id(hook_id)
        if not hook:
            raise HookNotFoundError(f"Hook with ID {hook_id} not found.")
        try:
            hook._stop_hooking()
        except Exception as e:
            raise FridaError(f"Error stopping hook {hook_id}: {e}") from e
        return True

    def remove_hook(self, hook_id: int) -> bool:
        """
        Remove a hook.
        """
        hook = self.app.hook_manager.get_hook_by_id(hook_id)
        if hook:
            self.app.hook_manager.remove_hook(hook_id)
            return True
        return False

    def list_hooks(self) -> List[Dict[str, Any]]:
        """
        Returns a list of all currently active hooks with their details.
        """
        hooks: List[Dict[str, Any]] = []
        for hook in self.app.hook_manager.hook_windows:
            hooks.append({
                "id": hook.id,
                "process": hook.process,
                "module": hook.module,
                "function": hook.function,
                "hook_started": hook.hook_started,
                "trigger_count": hook.trigger_count,
                "js_code": hook.js_code,
            })
        return hooks

    def save_project(self, filename: str = "project.json") -> None:
        """
        Saves the current project state to a JSON file.
        """
        self.app.save_project(filename)

    def load_project(self, filename: str = "project.json") -> None:
        """
        Loads a project state from a JSON file.
        """
        self.app.load_project(filename)

    def get_global_logs(self) -> List[Dict[str, Any]]:
        """
        Retrieves the global logs from the application.
        """
        logs: List[Dict[str, Any]] = []
        for entry in self.app.global_hooks_log_window.table_logger.log_entries:
            logs.append({
                "timestamp": entry.timestamp,
                "event_type": entry.event_type,
                "process_str": entry.process_str,
                "function_name": entry.function_name,
                "return_value": entry.return_value,
                "arguments": entry.arguments,
                "hook_id": entry.hook_id,
                "address": entry.address,
                "level": entry.level,
            })
        return logs

    def get_processes(self) -> List[str]:
        """
        Returns the list of all running processes (strings "Name (pid)").
        """
        return self.app.processes

    def get_process_details(self, index: int) -> Any:
        """
        Return the process details for a given index in frida_handler.process_list.
        """
        if 0 <= index < len(self.app.frida_handler.process_list):
            return self.app.frida_handler.process_list[index]
        return None

    def get_modules(self, selected_process_index: int) -> List[str]:
        """
        Returns the modules list of a process (by index).
        """
        return self.app.frida_handler.fetch_modules(selected_process_index)

    def get_module_details(self, index: int) -> Any:
        """
        Return the module details for a given index in self.app.frida_handler.module_map.
        """
        if 0 <= index < len(self.app.frida_handler.module_map):
            return self.app.frida_handler.module_map[index]
        return None

    def get_functions(self, selected_process_index: int, selected_module_index: int) -> List[str]:
        """
        Returns the function list of a module.
        """
        return self.app.frida_handler.fetch_functions(selected_process_index, selected_module_index)

    def get_function_details(self, index: int) -> Any:
        """
        Return the function details for a given index in self.app.frida_handler.function_map.
        """
        if 0 <= index < len(self.app.frida_handler.function_map):
            return self.app.frida_handler.function_map[index]
        return None

    def refresh_process_list(self) -> None:
        """
        Refreshes the list of running processes.
        """
        self.app._load_process_list()

    def _run_gui(self, app):
        from imgui_bundle import imgui, hello_imgui, immapp
        params = hello_imgui.RunnerParams()
        params.callbacks.show_gui = app.draw_gui
        params.callbacks.load_additional_fonts = app.load_font
        immapp.run(params)

    def run_gui(self):
        import threading
        gui_thread = threading.Thread(target=self._run_gui, args=[self.app], daemon=True)
        gui_thread.start()

    # Additional helpers

    def get_process_by_name(self, process_name: Optional[str] = None, pid: Optional[int] = None) -> Optional[str]:
        """
        Returns "Notepad.exe (1234)" for the given process name or pid, if found,
        or None otherwise.
        """
        self.app.frida_handler.fetch_processes()  # refresh
        if pid is not None:
            for pinfo in self.app.frida_handler.process_list:
                if pinfo.pid == pid:
                    return f"{pinfo.name} ({pinfo.pid})"
            return None

        if process_name is not None:
            want_lower = process_name.lower()
            for pinfo in self.app.frida_handler.process_list:
                if pinfo.name.lower() == want_lower:
                    return f"{pinfo.name} ({pinfo.pid})"
            return None

        return None

    def get_modules_by_process_name(self, process_name: Optional[str] = None, pid: Optional[int] = None) -> List[str]:
        """
        Returns the list of modules for a process identified by name or pid,
        or [] if not found.
        """
        self.app.frida_handler.fetch_processes()
        process_index = None

        if pid is not None:
            for i, pinfo in enumerate(self.app.frida_handler.process_list):
                if pinfo.pid == pid:
                    process_index = i
                    break

        elif process_name is not None:
            want_lower = process_name.lower()
            for i, pinfo in enumerate(self.app.frida_handler.process_list):
                if pinfo.name.lower() == want_lower:
                    process_index = i
                    break

        if process_index is None:
            return []

        return self.app.frida_handler.fetch_modules(process_index)

    def get_functions_by_process_and_module(
        self,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        module_name: str = ""
    ) -> List[Dict[str, Any]]:
        """
        Return a list of {name, address} for all functions in `module_name`,
        in process identified by name or pid. 
        """
        self.app.frida_handler.fetch_processes()
        process_index = None

        if pid is not None:
            for i, pinfo in enumerate(self.app.frida_handler.process_list):
                if pinfo.pid == pid:
                    process_index = i
                    break

        elif process_name is not None:
            want_lower = process_name.lower()
            for i, pinfo in enumerate(self.app.frida_handler.process_list):
                if pinfo.name.lower() == want_lower:
                    process_index = i
                    break

        if process_index is None:
            return []

        self.app.frida_handler.fetch_modules(process_index)

        module_index = None
        for i, mod_obj in self.app.frida_handler.module_map.items():
            if mod_obj["name"].lower() == module_name.lower():
                module_index = i
                break
        if module_index is None:
            return []

        self.app.frida_handler.fetch_functions(process_index, module_index)
        results = []
        for i, func_data in self.app.frida_handler.function_map.items():
            results.append({
                "name": func_data["name"],
                "address": func_data["address"]
            })
        return results

    def get_function_address(
        self,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        module_name: str = "",
        function_name: str = ""
    ) -> Optional[str]:
        """
        Return the address of a function (by name) in a module, in a process identified by name or pid,
        or None if not found.
        """
        self.app.frida_handler.fetch_processes()
        process_index = None

        if pid is not None:
            for i, pinfo in enumerate(self.app.frida_handler.process_list):
                if pinfo.pid == pid:
                    process_index = i
                    break

        elif process_name is not None:
            want_lower = process_name.lower()
            for i, pinfo in enumerate(self.app.frida_handler.process_list):
                if pinfo.name.lower() == want_lower:
                    process_index = i
                    break

        if process_index is None:
            return None

        self.app.frida_handler.fetch_modules(process_index)

        module_index = None
        for i, mod_obj in self.app.frida_handler.module_map.items():
            if mod_obj["name"].lower() == module_name.lower():
                module_index = i
                break
        if module_index is None:
            return None

        self.app.frida_handler.fetch_functions(process_index, module_index)

        for i, func_data in self.app.frida_handler.function_map.items():
            if func_data["name"].lower() == function_name.lower():
                return func_data["address"]

        return None
