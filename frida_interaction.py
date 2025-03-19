import frida
from typing import List, Dict, Any, Optional
import logging

logger: logging.Logger = logging.getLogger(__name__)


class ProcessInfo:
    """
    Represents a Frida process, including its PID, name, and the frida.Process object.
    """

    def __init__(self, pid: int, name: str, frida_process: Any) -> None:
        """
        Initializes a new ProcessInfo.

        Parameters:
            pid (int): The process ID.
            name (str): The process name.
            frida_process (Any): The frida.Process object.
        """
        self.pid: int = pid
        self.name: str = name
        self.frida_process: Any = frida_process


class FridaHandler:
    """
    Handles Frida interactions such as fetching processes, modules, and functions.
    """

    def __init__(self) -> None:
        """
        Initializes a new FridaHandler.
        """
        # We no longer store a process_map based on indices; instead, we use a list of ProcessInfo.
        self.process_list: List[ProcessInfo] = []
        # These maps remain useful for modules and functions.
        self.module_map: Dict[int, Any] = {}
        self.function_map: Dict[int, Any] = {}

    def _execute_script(self, pid: int, script_code: str) -> Any:
        """
        Executes a Frida script on the process with the specified PID.

        Parameters:
            pid (int): Process ID.
            script_code (str): The JavaScript code to execute.

        Returns:
            Any: The result of the script execution.
        """
        device = frida.get_local_device()
        session = device.attach(pid)
        result: Any = None

        def on_message(message: Dict[str, Any], data: Any) -> None:
            nonlocal result
            if message["type"] == "send":
                payload = message["payload"]
                # Handle the case where the script may return multiple structures.
                if result is None:
                    result = payload
                else:
                    if isinstance(result, list) and isinstance(payload, list):
                        result.extend(payload)
                    elif isinstance(result, list):
                        result.append(payload)
                    else:
                        result = payload

        script = session.create_script(script_code)
        script.on("message", on_message)
        script.load()
        import time
        time.sleep(0.2)
        script.unload()
        session.detach()
        return result

    def fetch_processes(self) -> List[str]:
        """
        Fetches the list of processes from the local device,
        stores the result in self.process_list, and returns a list
        of display strings formatted as "Name (PID)" for the UI.

        Returns:
            List[str]: A list of process display strings.
        """
        try:
            device = frida.get_local_device()
            procs = device.enumerate_processes()

            # Clear the previous list and populate with new ProcessInfo objects.
            self.process_list.clear()
            for p in procs:
                # p is a frida.Process object.
                info = ProcessInfo(pid=p.pid, name=p.name, frida_process=p)
                self.process_list.append(info)

            # Return display strings for the UI.
            return [f"{info.name} ({info.pid})" for info in self.process_list]

        except Exception as e:
            logger.error(f"Error loading processes: {e}")
            # On error, reset the process list.
            self.process_list = []
            return []

    def fetch_modules(self, selected_process_index: int) -> List[str]:
        """
        Returns the list of modules for the process selected by index in self.process_list.

        Parameters:
            selected_process_index (int): The index of the selected process.

        Returns:
            List[str]: A list of module names.
        """
        # Check that the index is valid.
        if not (0 <= selected_process_index < len(self.process_list)):
            logger.error("No process selected or invalid index.")
            return []

        try:
            pid_obj = self.process_list[selected_process_index]  # ProcessInfo
            pid = pid_obj.pid

            result = self._execute_script(pid, "send(Process.enumerateModulesSync());")
            if result is None:
                return []

            modules = [mod["name"] for mod in result]
            # Store the result in self.module_map for later use.
            self.module_map = {i: mod for i, mod in enumerate(result)}
            return modules

        except Exception as e:
            logger.error(f"Error loading modules: {e}")
            return []

    def fetch_functions(self, selected_process_index: int, selected_module_index: int) -> List[str]:
        """
        Returns the list of functions for a module (by index) of a process (by index).

        Parameters:
            selected_process_index (int): The index of the selected process.
            selected_module_index (int): The index of the selected module in self.module_map.

        Returns:
            List[str]: A list of function names.
        """
        # Check that the module index is valid.
        if selected_module_index not in self.module_map:
            logger.error("No module selected or invalid index.")
            return []

        try:
            # Retrieve the correct PID.
            if not (0 <= selected_process_index < len(self.process_list)):
                logger.error("Process index out of range.")
                return []

            pid_obj = self.process_list[selected_process_index]  # ProcessInfo
            pid = pid_obj.pid

            lib_name: str = self.module_map[selected_module_index]["name"]

            script_code: str = f"""
    var exports = Module.enumerateExports("{lib_name}");
    send(exports);
    """
            result = self._execute_script(pid, script_code) or []
            funcs: List[str] = []
            self.function_map = {}

            for i, it in enumerate(result):
                if it["type"] == "function":
                    funcs.append(it["name"])
                    self.function_map[i] = {
                        "name": it["name"],
                        "address": it["address"],
                    }

            return funcs

        except Exception as e:
            logger.error(f"Error loading functions: {e}")
            return []
