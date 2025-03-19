# ui_palettes.py
from typing import List, Optional, Any, Callable
from command_palette import CommandPalette
from constants import HookChainStep, WindowToggleOption
from themes import ALL_THEMES, ALL_THEMES_NAMES
import logging, sys
from imgui_bundle import hello_imgui, imgui
import tests_add_hooks
import threading

logger: logging.Logger = logging.getLogger(__name__)

class PaletteManager:
    """Manages the creation, storage, and retrieval of CommandPalette instances."""

    def __init__(self, parent_main_app) -> None:
        self.parent_main_app = parent_main_app
        self.hook_chain_palettes: List[Optional[CommandPalette]] = [None, None, None]
        self.toggle_window_palette: Optional[CommandPalette] = None
        self.toggle_hook_palette: Optional[CommandPalette] = None
        self.theme_palette: Optional[CommandPalette] = None
        self.test_palette: Optional[CommandPalette] = None
        self.duplicate_hook_palette: Optional[CommandPalette] = None

    def create_chain_palette(
        self,
        title: str,
        items: List[str],
        callback: Callable[[int], None],
        cancel_callback: Callable[[], None],
    ) -> CommandPalette:
        """
        Creates a CommandPalette for a chain step, AND OPENS IT.
        """
        palette = CommandPalette.for_items(
            items=items,
            callback=callback,
            cancel_callback=cancel_callback,
            title=title,
        )
        # IMPORTANT: open the ephemeral palette so it actually appears
        palette.open()
        return palette

    # --------------------------------------------------------------------------
    # Hook chain (3-step)
    # --------------------------------------------------------------------------
    def open_hook_chain(self) -> None:
        """Open a hook chain (process → module → function)."""
        self.hook_chain_palettes[HookChainStep.PROCESS.value] = self.create_chain_palette(
            "Select Process",
            self.parent_main_app.processes,
            self.on_process_selected,
            self.cancel_hook_chain,
        )

    def on_process_selected(self, index: int) -> None:
        self.parent_main_app.selected_process_index = index
        self.parent_main_app._load_modules_list()

        self.hook_chain_palettes[HookChainStep.MODULE.value] = self.create_chain_palette(
            "Select Module",
            self.parent_main_app.modules,
            self.on_module_selected,
            self.cancel_hook_chain,
        )
        # We can discard the previous step's palette
        self.hook_chain_palettes[HookChainStep.PROCESS.value] = None

    def on_module_selected(self, index: int) -> None:
        self.parent_main_app.selected_module_index = index
        self.parent_main_app._load_functions_list()

        self.hook_chain_palettes[HookChainStep.FUNCTION.value] = self.create_chain_palette(
            "Select Function",
            self.parent_main_app.functions,
            self.on_function_selected,
            self.cancel_hook_chain,
        )
        self.hook_chain_palettes[HookChainStep.MODULE.value] = None

    def on_function_selected(self, index: int) -> None:
        self.parent_main_app.selected_function_index = index
        # Build data from the chosen function
        selected_process = (
            self.parent_main_app.processes[self.parent_main_app.selected_process_index]
            if self.parent_main_app.processes
            else ""
        )
        selected_module = (
            self.parent_main_app.modules[self.parent_main_app.selected_module_index]
            if self.parent_main_app.modules
            else ""
        )
        func_info = self.parent_main_app.frida_handler.function_map.get(index, {})
        selected_function = func_info.get("name", "")
        address = func_info.get("address", "")

        # Actually create the hook
        self.parent_main_app.hook_manager.create_hook(
            selected_process, selected_module, selected_function, address
        )

        # Done; close the final ephemeral palette
        self.hook_chain_palettes[HookChainStep.FUNCTION.value] = None

    def cancel_hook_chain(self) -> None:
        """
        If user hits Escape or closes the ephemeral palette,
        remove them all and reset indexes.
        """
        for i in range(len(HookChainStep)):
            self.hook_chain_palettes[i] = None
        self.parent_main_app.selected_process_index = 0
        self.parent_main_app.selected_module_index = 0
        self.parent_main_app.selected_function_index = 0

    # --------------------------------------------------------------------------
    # Toggle window chain
    # --------------------------------------------------------------------------
    def open_toggle_window_chain(self) -> None:
        window_names = []

        for w in WindowToggleOption:
            name = w.name
            if w == WindowToggleOption.HOOKS_MANAGEMENT:
                is_open = self.parent_main_app.show_hooks_management
            elif w == WindowToggleOption.FRIDA_CONSOLE:
                is_open = self.parent_main_app.show_frida_console
            elif w == WindowToggleOption.GLOBAL_HOOKS_LOG:
                is_open = self.parent_main_app.show_global_hooks_log
            elif w == WindowToggleOption.WIDGET_INSPECTOR:
                is_open = self.parent_main_app.show_id_stack_tool_window
            else:
                is_open = False

            # Construire le label avec statut
            status = "Active" if is_open else "Inactive"
            label = f"{name} [{status}]"
            window_names.append(label)

        # Créer la palette en lui passant la liste des labels
        self.toggle_window_palette = self.create_chain_palette(
            title="Toggle Window",
            items=window_names,
            callback=self.on_toggle_window_selected,
            cancel_callback=self.cancel_toggle_window_chain,
        )


    def on_toggle_window_selected(self, index: int) -> None:
        if index == WindowToggleOption.HOOKS_MANAGEMENT.value:
            self.parent_main_app.show_hooks_management = not self.parent_main_app.show_hooks_management
        elif index == WindowToggleOption.FRIDA_CONSOLE.value:
            self.parent_main_app.show_frida_console = not self.parent_main_app.show_frida_console
        elif index == WindowToggleOption.GLOBAL_HOOKS_LOG.value:
            self.parent_main_app.show_global_hooks_log = not self.parent_main_app.show_global_hooks_log
        elif index == WindowToggleOption.WIDGET_INSPECTOR.value:
            self.parent_main_app.show_id_stack_tool_window = not self.parent_main_app.show_id_stack_tool_window

        self.toggle_window_palette = None

    def cancel_toggle_window_chain(self) -> None:
        self.toggle_window_palette = None

    # --------------------------------------------------------------------------
    # Toggle hook chain
    # --------------------------------------------------------------------------
    def open_toggle_hook_chain(self) -> None:
        hook_names: List[str] = [
            f"Hook {hw.id} - {hw.function} [{'Active' if hw.hook_started else 'Inactive'}]"
            for hw in self.parent_main_app.hook_manager.hook_windows
        ]
        self.toggle_hook_palette = self.create_chain_palette(
            "Toggle Hook",
            hook_names,
            self.on_toggle_hook_selected,
            self.cancel_toggle_hook_chain,
        )

    def on_toggle_hook_selected(self, index: int) -> None:
        if 0 <= index < len(self.parent_main_app.hook_manager.hook_windows):
            hook = self.parent_main_app.hook_manager.hook_windows[index]
            if hook.hook_started:
                threading.Thread(target=hook._stop_hooking, daemon=True).start()
            else:
                threading.Thread(target=hook._start_hooking, daemon=True).start()
        self.toggle_hook_palette = None

    def cancel_toggle_hook_chain(self) -> None:
        self.toggle_hook_palette = None

    # --------------------------------------------------------------------------
    # Change theme chain
    # --------------------------------------------------------------------------
    def open_change_theme_chain(self) -> None:
        self.theme_palette = self.create_chain_palette(
            "Select Theme",
            ALL_THEMES_NAMES,
            self.on_theme_selected,
            self.cancel_theme_selection
        )

    def on_theme_selected(self, index: int) -> None:
        self.parent_main_app.current_theme_index = index
        hello_imgui.apply_theme(ALL_THEMES[index])
        import main
        main.style()
        self.theme_palette = None

    def cancel_theme_selection(self) -> None:
        self.theme_palette = None

    # --------------------------------------------------------------------------
    # Tests chain
    # --------------------------------------------------------------------------
    def open_tests_chain(self) -> None:
        self.test_palette = self.create_chain_palette(
            "Select Test", ["Test add hook"], self.on_test_selected, self.cancel_test_chain
        )

    def on_test_selected(self, index: int) -> None:
        if index == 0:
            engine = hello_imgui.get_imgui_test_engine()
            engine.ui_stack_tool_open = True
            test = imgui.test_engine.register_test(engine, "Custom Tests", "Command Palette Sequence")
            test.test_func = tests_add_hooks.test_command_palette_sequence
            imgui.test_engine.queue_test(engine, test)
        self.test_palette = None

    def cancel_test_chain(self) -> None:
        self.test_palette = None

    # --------------------------------------------------------------------------
    # Duplicate hook from button clicked
    # --------------------------------------------------------------------------
    def open_duplicate_hook_chain(self, source_hook_window: Any) -> None:
        """
        Ouvre une palette pour choisir le process sur lequel dupliquer un hook existant.
        """
        processes = self.parent_main_app.processes  # liste de strings du type "notepad.exe (1234)"
        if not processes:
            # Par sécurité, on recharge la liste des process si nécessaire
            self.parent_main_app._load_processes_list()
            processes = self.parent_main_app.processes

        self.duplicate_hook_palette = self.create_chain_palette(
            title=f"Duplicate '{source_hook_window.function}' Hook - Select Process",
            items=processes,
            callback=lambda idx: self.on_duplicate_process_selected(idx, source_hook_window),
            cancel_callback=self.cancel_duplicate_hook
        )

    def on_duplicate_process_selected(self, index: int, source_hook_window: Any) -> None:
        process_str = self.parent_main_app.processes[index]  # ex: "notepad.exe (1234)"
        
        # Extraire le PID si le format est "xxx.exe (PID)"
        # sinon, fallback si c'est pas du tout ce format
        pid = 0
        process_name = process_str
        import re
        m = re.search(r"(.*)\s*\((\d+)\)", process_str)
        if m:
            process_name = m.group(1).strip()
            pid = int(m.group(2))

        # Créer un hook (même module, function, address et code JS)
        hw = self.parent_main_app.hook_manager.create_hook(
            process=process_name,
            module=source_hook_window.module,
            function=source_hook_window.function,
            address=source_hook_window.address
        )
        hw.js_code = source_hook_window.js_code
        hw.editor.set_text(hw.js_code) # TODO hacky
        hw._reload_script()

        # Fermer la palette
        self.duplicate_hook_palette = None

    def cancel_duplicate_hook(self) -> None:
        """
        Si l'utilisateur annule la sélection en fermant ou en pressant ESC,
        on referme la palette de duplication
        """
        self.duplicate_hook_palette = None

    # --------------------------------------------------------------------------
    # Actual drawing of ephemeral palettes each frame
    # --------------------------------------------------------------------------
    def draw_ephemeral_palettes(self) -> None:
        """Draw the ephemeral chain palettes if open."""
        # Each step gets its own index in self.hook_chain_palettes
        self._draw_chain_palette(
            self.hook_chain_palettes, HookChainStep.PROCESS.value, "Select Process"
        )
        self._draw_chain_palette(
            self.hook_chain_palettes, HookChainStep.MODULE.value, "Select Module"
        )
        self._draw_chain_palette(
            self.hook_chain_palettes, HookChainStep.FUNCTION.value, "Select Function"
        )

        # Single ephemeral palettes for toggles, theme, tests
        self._draw_chain_palette(self.toggle_window_palette, None, "Toggle Window")
        self._draw_chain_palette(self.toggle_hook_palette, None, "Toggle Hook")
        self._draw_chain_palette(self.theme_palette, None, "Select Theme")
        self._draw_chain_palette(self.test_palette, None, "Select Test")

        self._draw_chain_palette(self.duplicate_hook_palette, None, "Duplicate Hook - Select Process")

    def draw(self) -> None:
        """Called each frame to draw ephemeral palettes."""
        self.draw_ephemeral_palettes()

    def _draw_chain_palette(self, chain_palettes: Any, chain_step: Optional[int], title: str) -> None:
        """Draw a single ephemeral palette if it's open."""
        palette: Optional[CommandPalette] = None
        if isinstance(chain_palettes, list) and chain_step is not None:
            palette = chain_palettes[chain_step]
        elif isinstance(chain_palettes, CommandPalette):
            palette = chain_palettes

        if palette and palette.is_open:
            palette.draw()
