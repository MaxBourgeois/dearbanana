import time
import threading
import logging
import json
import frida
import ctypes
import sys

from typing import List, Dict, Optional, Any, Callable, Tuple

from imgui_bundle import imgui, hello_imgui

from utils import Utils
from command_palette import Command, CommandPalette
from logger_widgets import TableLogEntry
from global_logs_window import GlobalHooksLogUI
from frida_console_window import FridaConsoleUI
from hexviewer_window import HexViewerUI
from disasviewer_window import DisasViewerUI
from hooking_window import HookWindowUI
from themes import ALL_THEMES, ALL_THEMES_NAMES

from hook_window_manager import HookWindowManager
from project_manager import ProjectManager
from frida_interaction import FridaHandler  # modified version with ProcessInfo, etc.
from command_palettes_manager import PaletteManager

# Tests (for development/testing purposes)
from tests_add_hooks import test_command_palette_sequence, set_editor_to_inject_for_test

logger: logging.Logger = logging.getLogger(__name__)


class FridaHookManagerApp:
    """
    Main application that manages the window, menus, command palettes, process attachments,
    console, and other UI elements.
    """

    def __init__(self) -> None:
        """
        Initializes a new instance of the FridaHookManagerApp.
        """
        # HookWindowManager & ProjectManager
        self.hook_manager: HookWindowManager = HookWindowManager(self)
        self.project_manager: ProjectManager = ProjectManager(
            hook_manager=self.hook_manager,
            global_log_window=None
        )

        # Font object (if loaded)
        self.font: Optional[Any] = None

        # FridaHandler instance and storage for processes, modules, and functions
        self.frida_handler: FridaHandler = FridaHandler()

        # 'processes' is a list of strings "Name (PID)" for the UI
        self.processes: List[str] = []
        self.modules: List[str] = []
        self.functions: List[str] = []
        # 'module_map' and 'function_map' may eventually reference frida_handler.module_map/function_map,
        # but we keep them local if needed.
        self.module_map: Dict[int, Any] = {}
        self.function_map: Dict[int, Any] = {}

        self.selected_process_index: int = 0
        self.selected_module_index: int = 0
        self.selected_function_index: int = 0
        self.status_message: str = ""

        # UI toggles
        self.show_hooks_management: bool = True
        self.show_frida_console: bool = True
        self.show_global_hooks_log: bool = True
        self.show_id_stack_tool_window: bool = False

        # Palette manager for additional command chains
        self.palette_manager: PaletteManager = PaletteManager(self)

        # Persistent command palette
        self.command_palette: CommandPalette = CommandPalette(
            title="Command Palette",
            ephemeral=False
        )
        self._initialize_commands()

        # Initial process list load
        self._load_process_list()

        # Other UI elements
        self.console_window: FridaConsoleUI = FridaConsoleUI()
        self.global_hooks_log_window: GlobalHooksLogUI = GlobalHooksLogUI(main_app=self)
        self.project_manager.global_log_window = self.global_hooks_log_window
        self.hex_viewer: HexViewerUI = HexViewerUI(self)
        self.disas_viewer: DisasViewerUI = DisasViewerUI(self)

        # Theme index
        self.current_theme_index: int = 5

        # Custom window states
        self.window_is_maximized_state: bool = True
        self.is_dragging: bool = False
        self.drag_offset: Tuple[float, float] = (0, 0)
        self.current_window_pos: Tuple[float, float] = (0, 0)

        # Color palette for auto-assignment
        self.auto_color_palette: List[List[float]] = [
            [0.7, 0.35, 0.35, 1.0],
            [0.35, 0.7, 0.35, 1.0],
            [0.35, 0.55, 0.7, 1.0],
            [0.7, 0.55, 0.35, 1.0],
            [0.55, 0.4, 0.55, 1.0],
            [0.25, 0.55, 0.55, 1.0],
            [0.75, 0.25, 0.75, 1.0],
        ]
        self.auto_color_index: int = 0

    def _next_auto_color(self) -> List[float]:
        """
        Retrieves the next auto-assigned color.
        """
        color: List[float] = self.auto_color_palette[self.auto_color_index % len(self.auto_color_palette)]
        self.auto_color_index += 1
        return color

    def load_font(self) -> None:
        """
        Loads the 'consola.ttf' font if available.
        """
        try:
            self.font = hello_imgui.load_font_ttf_with_font_awesome_icons("consola.ttf", 16)
            Utils.console_head_font = hello_imgui.load_font_ttf_with_font_awesome_icons("consola.ttf", 24)
        except Exception as e:
            logger.error(f"Failed to load font consola.ttf: {e}")

    def _initialize_commands(self) -> None:
        """
        Initializes commands for the command palette.
        """
        def open_hook() -> None:
            self.palette_manager.open_hook_chain()

        def open_toggle_window() -> None:
            self.palette_manager.open_toggle_window_chain()

        def open_toggle_hook() -> None:
            self.palette_manager.open_toggle_hook_chain()

        def save_project_cmd() -> None:
            self.save_project("project.json")

        def load_project_cmd() -> None:
            self.load_project()

        def refresh_process_list() -> None:
            self._load_process_list()

        def debug_ui() -> None:
            imgui.debug_start_item_picker()

        def change_theme() -> None:
            self.palette_manager.open_change_theme_chain()

        def open_tests() -> None:
            self.palette_manager.open_tests_chain()

        self.command_palette.add_command(Command("Add function hook", open_hook))
        self.command_palette.add_command(Command("Toggle Window", open_toggle_window))
        self.command_palette.add_command(Command("Toggle Hook", open_toggle_hook))
        self.command_palette.add_command(Command("Save Project", save_project_cmd))
        self.command_palette.add_command(Command("Load Project", load_project_cmd))
        self.command_palette.add_command(Command("Refresh process list", refresh_process_list))
        self.command_palette.add_command(Command("Debug UI", debug_ui))
        self.command_palette.add_command(Command("Change Theme", change_theme))
        self.command_palette.add_command(Command("Tests", open_tests))

    def _load_process_list(self) -> None:
        """
        Loads the list of processes from frida_handler.
        Stores the result in self.processes (for the UI) and updates self.status_message.
        """
        try:
            # fetch_processes() returns a list of strings "Name (PID)" and fills
            # self.frida_handler.process_list with ProcessInfo objects.
            self.processes = self.frida_handler.fetch_processes()
            self.status_message = f"{len(self.processes)} processes loaded."
        except Exception as e:
            self.processes = []
            self.status_message = f"Error loading processes: {e}"

    def _load_modules_list(self) -> None:
        """
        Loads the list of modules for the selected process.
        Stores the list in self.modules and updates self.module_map.
        """
        try:
            self.modules = self.frida_handler.fetch_modules(self.selected_process_index)
            self.module_map = self.frida_handler.module_map
            self.status_message = f"{len(self.modules)} modules loaded."
            self.selected_module_index = 0
        except Exception as e:
            self.modules = []
            self.module_map = {}
            self.status_message = f"Error loading modules: {e}"
            self.selected_module_index = 0

    def _load_functions_list(self) -> None:
        """
        Loads the list of functions for the selected module in the selected process.
        Updates self.functions and self.function_map.
        """
        try:
            self.functions = self.frida_handler.fetch_functions(
                self.selected_process_index,
                self.selected_module_index
            )
            self.function_map = self.frida_handler.function_map

            if self.selected_function_index >= len(self.functions):
                self.selected_function_index = 0

            self.status_message = f"{len(self.functions)} functions found."
        except Exception as e:
            self.functions = []
            self.function_map = {}
            self.status_message = f"Error loading functions: {e}"
            self.selected_function_index = 0

    def save_project(self, filename: str = "project.json") -> None:
        """
        Saves the current project to the specified file.

        Parameters:
            filename (str): The file name to save the project.
        """
        self.project_manager.save_project(filename)

    def load_project(self, filename: str = "project.json") -> None:
        """
        Loads a project from the specified file.

        Parameters:
            filename (str): The file name from which to load the project.
        """
        self.project_manager.load_project(filename)

    def add_log_to_global(self, text: str, process_str: str, hook_id: int,
                          address: str = "", funcname: str = "") -> None:
        """
        Adds a log entry to the global log window.

        Parameters:
            text (str): The log message.
            process_str (str): The process string.
            hook_id (int): The hook identifier.
            address (str, optional): The memory address related to the log.
            funcname (str, optional): The function name related to the log.
        """
        self.global_hooks_log_window.add_line(text, process_str, hook_id, address, funcname)

    def get_hook_color(self, hook_id: int) -> Optional[List[float]]:
        """
        Retrieves the color associated with a hook from the HookWindowManager.

        Parameters:
            hook_id (int): The hook identifier.

        Returns:
            Optional[List[float]]: The RGBA color of the hook, or None if not found.
        """
        return self.hook_manager.get_hook_color(hook_id)

    def _handle_shortcuts(self) -> None:
        """
        Handles keyboard shortcuts.
        """
        io = imgui.get_io()
        is_ctrl_down: bool = (io.key_mods & imgui.Key.mod_ctrl) != 0
        is_p_pressed: bool = imgui.is_key_pressed(imgui.Key.p)
        if is_ctrl_down and is_p_pressed:
            if not self.command_palette.is_open:
                self.command_palette.open()
            else:
                self.command_palette.close()

    def _draw_hooks_management_window(self) -> None:
        """
        Draws the Hooks Management window.
        """
        opened, self.show_hooks_management = imgui.begin("Hooks Management", self.show_hooks_management)
        if opened:
            imgui.text("Active Hooks:")
            imgui.begin_child("HooksChild")

            table_flags: int = (
                imgui.TableFlags_.borders
                | imgui.TableFlags_.row_bg
                | imgui.TableFlags_.resizable
                | imgui.TableFlags_.scroll_x
                | imgui.TableFlags_.scroll_y
                | imgui.TableFlags_.sizing_stretch_prop
            )
            if imgui.begin_table("HookTable", 8, table_flags):
                imgui.table_setup_scroll_freeze(0, 1)
                imgui.table_setup_column("ID", imgui.TableColumnFlags_.width_fixed, 40)
                imgui.table_setup_column("Active", imgui.TableColumnFlags_.width_fixed, 55)
                imgui.table_setup_column("Process")
                imgui.table_setup_column("Module")
                imgui.table_setup_column("Function")
                imgui.table_setup_column("Triggers", imgui.TableColumnFlags_.width_fixed, 60)
                imgui.table_setup_column("Color", imgui.TableColumnFlags_.width_fixed, 80)
                imgui.table_setup_column("Focus", imgui.TableColumnFlags_.width_fixed, 60)
                imgui.table_headers_row()

                alive_hook_windows: List[HookWindowUI] = []

                for hw in self.hook_manager.hook_windows:
                    imgui.table_next_row()

                    # Column: ID
                    imgui.table_set_column_index(0)
                    imgui.text(str(hw.id))

                    # Column: Active (checkbox)
                    imgui.table_set_column_index(1)
                    active_value: bool = hw.hook_started
                    changed, new_val = imgui.checkbox(f"##active_{hw.id}", active_value)
                    if changed:
                        if new_val:
                            threading.Thread(target=hw._start_hooking, daemon=True).start()
                        else:
                            threading.Thread(target=hw._stop_hooking, daemon=True).start()

                    # Column: Process
                    imgui.table_set_column_index(2)
                    imgui.text(hw.process_display)

                    # Column: Module
                    imgui.table_set_column_index(3)
                    imgui.text(hw.module)

                    # Column: Function (colored)
                    imgui.table_set_column_index(4)
                    hook_color: List[float] = self.hook_manager.hook_colors.get(hw.id, [1.0, 1.0, 1.0, 1.0])
                    imgui.text_colored(hook_color, hw.function)

                    # Column: Triggers
                    imgui.table_set_column_index(5)
                    imgui.text(str(hw.trigger_count))

                    # Column: Color (editable)
                    imgui.table_set_column_index(6)
                    current_color: List[float] = self.hook_manager.hook_colors.get(hw.id, [1.0, 1.0, 1.0, 1.0])
                    color_changed, new_color = imgui.color_edit4(
                        f"##color_{hw.id}",
                        current_color,
                        flags=imgui.ColorEditFlags_.no_inputs
                    )
                    if color_changed:
                        self.hook_manager.hook_colors[hw.id] = new_color

                    # Column: Focus
                    imgui.table_set_column_index(7)
                    if imgui.small_button(f"Focus##{hw.id}"):
                        imgui.set_window_focus(hw.window_title)

                    if hw.is_open:
                        alive_hook_windows.append(hw)

                self.hook_manager.hook_windows = alive_hook_windows
                imgui.end_table()
            imgui.end_child()
        imgui.end()

    def _win32_set_window_center(self, win_w: int, win_h: int) -> None:
        """
        Centers the application window on the primary monitor (Windows-specific).

        Parameters:
            win_w (int): The target window width.
            win_h (int): The target window height.
        """
        if sys.platform.startswith("win"):
            user32 = ctypes.windll.user32

            def get_window_handle(window_title: str) -> int:
                FindWindow = ctypes.windll.user32.FindWindowW
                hwnd = FindWindow(None, window_title)
                if not hwnd:
                    raise RuntimeError(f"Window '{window_title}' not found.")
                return hwnd

            SWP_NOSIZE: int = 0x0001
            SWP_NOZORDER: int = 0x0004
            x: int = int(imgui.get_platform_io().monitors[0].work_size.x / 2 - win_w / 2)
            y: int = int(imgui.get_platform_io().monitors[0].work_size.y / 2 - win_h / 2)
            user32.SetWindowPos(get_window_handle("0xDearBanana"), 0, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER)
    
    def _win32_set_window_pos(self, x: int, y: int) -> None:
        """
        Sets the application window position (Windows-specific).

        Parameters:
            x (int): The target x-coordinate.
            y (int): The target y-coordinate.
        """
        if sys.platform.startswith("win"):
            user32 = ctypes.windll.user32

            def get_window_handle(window_title: str) -> int:
                FindWindow = ctypes.windll.user32.FindWindowW
                hwnd = FindWindow(None, window_title)
                if not hwnd:
                    raise RuntimeError(f"Window '{window_title}' not found.")
                return hwnd

            SWP_NOSIZE: int = 0x0001
            SWP_NOZORDER: int = 0x0004
            user32.SetWindowPos(get_window_handle("0xDearBanana"), 0, int(x), int(y), 0, 0, SWP_NOSIZE | SWP_NOZORDER)

    def _toggle_maximize(self) -> None:
        """
        Toggles the application window between maximized and normal sizes.
        """
        if sys.platform.startswith("win"):
            io = imgui.get_io()
            if self.window_is_maximized_state:
                win_w: int = 1280
                win_h: int = 800
                hello_imgui.change_window_size((win_w, win_h))
                self.window_is_maximized_state = False
                self._win32_set_window_center(win_w, win_h)
            else:
                win_w: int = int(imgui.get_platform_io().monitors[0].work_size.x)
                win_h: int = int(imgui.get_platform_io().monitors[0].work_size.y)
                hello_imgui.change_window_size((win_w, win_h))
                self.window_is_maximized_state = True
                self._win32_set_window_center(win_w, win_h)

    def _toggle_close(self) -> None:
        """
        Closes the application.
        """
        hello_imgui.get_runner_params().app_shall_exit = True

    def _setup_dockspace(self) -> None:
        """
        Sets up the main dockspace and custom title bar.
        """
        io = imgui.get_io()

        Utils.draw_overlay((0.1, 0.1, 0.1, 0.9), overlay_name="main")

        # Custom title bar
        imgui.set_next_window_viewport(imgui.get_main_viewport().id_)
        self.current_window_pos = (imgui.get_main_viewport().pos.x, imgui.get_main_viewport().pos.y)
        imgui.set_next_window_pos(self.current_window_pos, cond=imgui.Cond_.always)
        imgui.set_next_window_size((io.display_size.x, 30), cond=imgui.Cond_.always)
        imgui.push_style_var(imgui.StyleVar_.window_border_size, 0)
        imgui.push_style_var(imgui.StyleVar_.window_padding, (0, 0))
        imgui.push_style_var(imgui.StyleVar_.window_rounding, 0)
        imgui.push_style_color(imgui.Col_.window_bg, imgui.get_style().color_(imgui.Col_.title_bg))
        title_flags: int = (
            imgui.WindowFlags_.no_resize
            | imgui.WindowFlags_.no_move
            | imgui.WindowFlags_.no_collapse
            | imgui.WindowFlags_.no_decoration
            | imgui.WindowFlags_.no_docking
            | imgui.WindowFlags_.no_title_bar
            | imgui.WindowFlags_.no_nav
        )

        opened_title, _ = imgui.begin("TitleWindow", True, title_flags)
        if opened_title:
            io.config_viewports_no_decoration = True
            io.config_viewports_no_task_bar_icon = True

            # Banana image
            win_size = imgui.get_window_size()
            banana_w: float = 552 / 25
            banana_h: float = 408 / 25
            try:
                self.banana_texture_id = hello_imgui.im_texture_id_from_asset("banane_jaune.png")
                imgui.set_cursor_pos((banana_w / 2, (win_size.y - banana_h) / 2))
                imgui.image(self.banana_texture_id, imgui.ImVec2(banana_w, banana_h), tint_col=(1, 1, 1, 0.5))
            except Exception:
                pass

            title: str = "0xDearBanana"
            win_size = imgui.get_window_size()
            text_size = imgui.calc_text_size(title)
            imgui.set_cursor_pos(((win_size.x - text_size.x) / 2, (win_size.y - text_size.y) / 2))
            imgui.text(title)

            if imgui.is_item_hovered():
                imgui.set_mouse_cursor(imgui.MouseCursor_.hand)

            if not self.is_dragging and imgui.is_item_hovered() and imgui.is_mouse_clicked(0):
                mouse_pos = imgui.get_mouse_pos()
                self.drag_offset = (mouse_pos.x - self.current_window_pos[0], mouse_pos.y - self.current_window_pos[1])
                self.is_dragging = True

            if self.is_dragging:
                if not imgui.is_mouse_down(0):
                    self.is_dragging = False
                else:
                    new_mouse = imgui.get_mouse_pos()
                    new_window_pos = (new_mouse.x - self.drag_offset[0], new_mouse.y - self.drag_offset[1])
                    self._win32_set_window_pos(new_window_pos[0], new_window_pos[1])
                    self.current_window_pos = new_window_pos

            imgui.push_style_var(imgui.StyleVar_.window_padding, (0, 0))
            imgui.push_style_var(imgui.StyleVar_.item_inner_spacing, (0, 0))
            imgui.push_style_var(imgui.StyleVar_.indent_spacing, 0)
            imgui.same_line()
            imgui.dummy((win_size.x / 2 - text_size.x / 2 - text_size.y * 5, 0))
            imgui.same_line()
            imgui.push_style_var(imgui.StyleVar_.frame_border_size, 0)
            imgui.push_style_color(imgui.Col_.button_hovered, (0.992, 0.733, 0.173, 1))

            if imgui.button("##maximize", (text_size.y, text_size.y)):
                self._toggle_maximize()
            imgui.pop_style_color()
            imgui.same_line()
            imgui.push_style_color(imgui.Col_.button_hovered, (1, 0.373, 0.341, 1))

            if imgui.button("##close", (text_size.y, text_size.y)):
                self._toggle_close()

            imgui.pop_style_color()
            imgui.pop_style_var(4)
        imgui.end()
        imgui.pop_style_var(3)
        imgui.pop_style_color()

        # Banana background image
        vp_width: float = io.display_size[0]
        vp_height: float = io.display_size[1]
        banana_w_bg: int = 800
        banana_h_bg: int = 800
        center_x: float = (vp_width - banana_w_bg) / 2
        center_y: float = (vp_height - banana_h_bg) / 2
        try:
            self.banana_texture_id = hello_imgui.im_texture_id_from_asset("banane_jaune_rayons.png")
            imgui.set_cursor_pos((center_x, center_y))
            imgui.image(self.banana_texture_id, imgui.ImVec2(banana_w_bg, banana_h_bg), tint_col=(1, 1, 1, 0.2))
        except Exception:
            pass

        dockspace_flags: int = (
            imgui.WindowFlags_.no_move
            | imgui.WindowFlags_.no_resize
            | imgui.WindowFlags_.no_collapse
            | imgui.WindowFlags_.no_nav
            | imgui.WindowFlags_.no_title_bar
        )
        margin_top: int = 40
        margin_bottom: int = 10
        win_width: float = io.display_size.x - 20
        win_height: float = io.display_size.y - margin_top - margin_bottom

        imgui.set_next_window_viewport(imgui.get_main_viewport().id_)
        imgui.set_next_window_size((win_width, win_height), cond=imgui.Cond_.always)
        imgui.set_next_window_pos(
            (
                ((io.display_size.x - win_width) / 2) + imgui.get_main_viewport().pos.x,
                margin_top + imgui.get_main_viewport().pos.y,
            ),
            cond=imgui.Cond_.always
        )

        imgui.push_style_var(imgui.StyleVar_.window_rounding, 5)
        imgui.push_style_var(imgui.StyleVar_.window_border_size, 1)
        imgui.push_style_var(imgui.StyleVar_.docking_separator_size, 1)
        imgui.push_style_var(imgui.StyleVar_.window_padding, (3, 3))
        imgui.push_style_var(imgui.StyleVar_.item_inner_spacing, (10, 10))
        imgui.push_style_var(imgui.StyleVar_.alpha, 1)

        imgui.push_style_color(imgui.Col_.window_bg, (0, 0, 0, 0))

        opened_ds, _ = imgui.begin("MyDockSpace", True, dockspace_flags)
        if opened_ds:
            dockspace_id = imgui.get_id("MyDockspace")
            imgui.dock_space(
                dockspace_id,
                (0, 0),
                imgui.DockNodeFlags_.passthru_central_node
                | imgui.DockNodeFlags_.auto_hide_tab_bar
            )
        imgui.end()
        imgui.pop_style_var(6)
        imgui.pop_style_color()

    def draw_main_border(self) -> None:
        """
        Draws a border around the main window.
        """
        draw_list = imgui.get_foreground_draw_list()
        io = imgui.get_io()
        width, height = io.display_size.x, io.display_size.y
        border_color: int = imgui.get_color_u32((1.0, 1.0, 1.0, 0.1))
        border_thickness: int = 1
        draw_list.add_rect(
            (imgui.get_main_viewport().pos.x, imgui.get_main_viewport().pos.y),
            (width + imgui.get_main_viewport().pos.x, height + imgui.get_main_viewport().pos.y),
            border_color,
            0.0,
            0,
            border_thickness
        )

    def _draw_palettes(self) -> None:
        """
        Draws the command palette and the palette manager.
        """
        self.command_palette.draw()
        self.palette_manager.draw()

    def draw_gui(self) -> None:
        """
        Main method called each frame to render the GUI.
        """
        self.draw_main_border()
        self._handle_shortcuts()
        self._draw_palettes()
        self._setup_dockspace()

        # Frida console
        if self.show_frida_console:
            self.console_window.is_open = True
            self.console_window.draw_gui()
        else:
            self.console_window.is_open = False

        # Global log window
        if self.show_global_hooks_log:
            self.global_hooks_log_window.is_open = True
            self.global_hooks_log_window.draw_gui()
        else:
            self.global_hooks_log_window.is_open = False

        # Tool window (ID stack)
        if self.show_id_stack_tool_window:
            imgui.show_id_stack_tool_window()

        # HookWindowUI windows
        for hw in self.hook_manager.hook_windows:
            hw.draw()

        # Hex and Disassembly viewers
        self.hex_viewer.draw_gui()
        self.disas_viewer.draw_gui()

        # Hooks Management window
        if self.show_hooks_management:
            imgui.set_next_window_dock_id(imgui.get_id("MyDockspace"), imgui.Cond_.first_use_ever)
            self._draw_hooks_management_window()
