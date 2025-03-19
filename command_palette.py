import logging
from typing import Callable, List, Optional, Tuple

from imgui_bundle import imgui, hello_imgui
from utils import Utils

import constants

logger = logging.getLogger(__name__)


class AutoCompleteHelper:
    """
    Provides a single-widget auto-completion control.
    
    This widget displays a text input (for searching/filtering) and, if matching items exist,
    a combo box for selection. When exactly one matching item remains, it is auto-selected.
    
    TODO: Consider extracting this class into its own file.
    """

    @staticmethod
    def auto_complete_combo(
        label: str,
        current_index: int,
        items: List[str],
        filter_str: str,
        place_holder: str = "Type to filter..."
    ) -> Tuple[int, str, bool]:
        """
        Renders a text input with auto-completion and an optional combo box.
        
        Args:
            label (str): A unique base label ID for ImGui.
            current_index (int): Index of the currently selected item in `items`, or -1 if none.
            items (List[str]): Full list of selectable strings.
            filter_str (str): Text input by the user for filtering `items`.
            place_holder (str): Hint text shown in the input when `filter_str` is empty.
        
        Returns:
            Tuple[int, str, bool]:
                - new_index (int): Updated index of the selected item (if any).
                - new_filter (str): Updated text (either the search filter or the selected item).
                - has_focus (bool): True if the text field currently has focus.
        """
        # 1) Occupy the entire width for this widget.
        avail_w, _ = imgui.get_content_region_avail()
        imgui.set_next_item_width(avail_w)

        # 2) Draw a text input (search field) with a hint.
        changed, typed_text = imgui.input_text_with_hint(
            f"##{label}",
            place_holder,
            filter_str
        )
        if changed:
            # If the user typed or erased text, update filter_str and reset current_index.
            filter_str = typed_text
            current_index = -1

        # Check if the text input is currently focused.
        has_focus: bool = imgui.is_item_focused()

        # 3) Filter the list of items based on the typed text (case-insensitive).
        filter_lower: str = filter_str.lower()
        filtered: List[Tuple[int, str]] = [
            (i, txt) for i, txt in enumerate(items) if filter_lower in txt.lower()
        ]

        # 4) If no items match the filter, return the current state (no combo will be shown).
        if not filtered:
            return current_index, filter_str, has_focus

        # 5) Auto-select if exactly one item remains.
        if len(filtered) == 1:
            only_idx, only_text = filtered[0]
            current_index = only_idx
            filter_str = only_text  # Overwrite the search text with the sole matching item.

        # 6) Prepare the text for the combo's preview (collapsed label).
        #     If filter_str is empty, use "Select..." as a hint.
        combo_preview: str = filter_str if filter_str else "Select..."

        # 7) Draw the combo box. If the user clicks it, the list of filtered items is shown.
        if imgui.begin_combo(f"##{label}_combo", combo_preview):
            for orig_idx, suggestion in filtered:
                # Mark the item as selected if it matches the current index.
                is_selected: bool = (orig_idx == current_index)
                # Build a unique ID for each item so that ImGui can differentiate them.
                unique_id: str = f"{suggestion}##{label}_{orig_idx}"

                # Draw a selectable item. (Note: imgui.selectable returns a tuple.)
                _, selectable = imgui.selectable(unique_id, is_selected)
                if selectable:
                    # User clicked this item: update current_index and change input text.
                    current_index = orig_idx
                    filter_str = suggestion

                # If the item is selected, set it as the default focused item.
                if is_selected:
                    imgui.set_item_default_focus()

            imgui.end_combo()

        # 8) Return the updated state.
        return current_index, filter_str, has_focus


class Command:
    """
    Represents a command with a name and a callback function.
    """
    def __init__(self, name: str, callback: Callable[[], None]) -> None:
        self.name: str = name
        self.callback: Callable[[], None] = callback


filtered_index: int = 0


class CommandPalette:
    """
    Manages a list of commands (or labels) and provides a palette-style window for filtering
    and selecting an item.
    
    Usage Modes:
      - Persistent (formerly CommandManager):
            palette = CommandPalette()
            palette.add_command(Command("Say Hello", do_hello))
            palette.open()    # to display the palette
            palette.draw()    # call every frame in the ImGui loop

      - Ephemeral (formerly ItemPalette):
            palette = CommandPalette.for_items(
                items=["Apple", "Banana", "Cherry"],
                callback=lambda idx: print(f"Selected item = {idx}"),
                cancel_callback=lambda: print("Canceled"),
                title="Select Fruit"
            )
            palette.open()
            palette.draw()    # call every frame
    """

    def __init__(self, title: str = "Command Palette", ephemeral: bool = False, on_close: Optional[Callable[[], None]] = None) -> None:
        # Window title.
        self.title: str = title

        # List of Command objects.
        self.commands: List[Command] = []

        # State for the ImGui window.
        self.search_query: str = ""
        self.is_open: bool = False
        self.just_opened: bool = False

        # Indicates whether this palette is ephemeral.
        self.ephemeral: bool = ephemeral

        # Callback invoked when closing without a selection (for ephemeral palettes).
        self.on_close: Optional[Callable[[], None]] = on_close

        # Automatic selection management.
        self.selected: bool = False

    @staticmethod
    def for_items(
        items: List[str],
        callback: Callable[[int], None],
        cancel_callback: Optional[Callable[[], None]] = None,
        title: str = "Select Item"
    ) -> "CommandPalette":
        """
        Creates an ephemeral CommandPalette from a list of strings.
        Each item becomes a Command whose callback calls `callback(index)`.
        
        Args:
            items (List[str]): List of item labels.
            callback (Callable[[int], None]): Function that receives the selected item's index.
            cancel_callback (Optional[Callable[[], None]]): Function to call if the palette is canceled.
            title (str): Title of the palette window.
        
        Returns:
            CommandPalette: The constructed ephemeral command palette.
        """
        palette: CommandPalette = CommandPalette(title=title, ephemeral=True, on_close=cancel_callback)
        for i, label in enumerate(items):
            # Use a lambda to capture the current index.
            palette.commands.append(Command(label, lambda i=i: callback(i)))
        return palette

    def add_command(self, cmd: Command) -> None:
        """
        Adds a command to the palette (only used in persistent mode).
        
        Args:
            cmd (Command): The command to add.
        """
        self.commands.append(cmd)

    def open(self) -> None:
        """
        Opens the palette (for both persistent and ephemeral modes).
        """
        self.is_open = True
        self.just_opened = True
        # Reset selection state.
        self.selected = False

    def close(self) -> None:
        """
        Closes the palette and, if necessary, triggers the cancel callback (for ephemeral palettes).
        """
        global filtered_index
        self.is_open = False
        self.just_opened = False
        self.search_query = ""
        filtered_index = 0
        if self.ephemeral and not self.selected and self.on_close:
            self.on_close()

    def draw(self) -> None:
        """
        Renders the palette window using ImGui.
        """
        if not self.is_open:
            return

        global filtered_index

        io = imgui.get_io()

        # --- Background overlay ---
        Utils.draw_overlay(overlay_name="palette")

        # --- Fixed Position and Size ---
        avail_w, avail_h = io.display_size
        size_w, size_h = (400, 200)
        # Fixed position (modifiable): centered horizontally and offset vertically.
        fixed_position: Tuple[float, float] = (
            avail_w / 2 - size_w / 2, 
            avail_h / 2 - size_h / 2 - avail_h / 4
        )
        fixed_size: Tuple[int, int] = (size_w, size_h)
        imgui.set_next_window_pos(imgui.ImVec2(fixed_position) + imgui.get_main_viewport().pos, cond=imgui.Cond_.always)
        imgui.set_next_window_size(fixed_size, cond=imgui.Cond_.always)

        # --- Apply window padding ---
        window_padding: Tuple[int, int] = (12, 12)
        imgui.push_style_var(imgui.StyleVar_.window_padding, window_padding)
        imgui.push_style_var(imgui.StyleVar_.item_spacing, (0, 16))
        imgui.push_style_color(imgui.Col_.border, (1, 1, 1, 0.35))

        # --- Window flags ---
        flags = (
            imgui.WindowFlags_.no_scrollbar |
            imgui.WindowFlags_.no_decoration |
            imgui.WindowFlags_.no_resize |
            imgui.WindowFlags_.no_move |
            imgui.WindowFlags_.no_title_bar |
            imgui.WindowFlags_.no_scroll_with_mouse
        )

        # --- Begin window ---
        opened, self.is_open = imgui.begin(self.title, self.is_open, flags)
        if opened:
            if self.just_opened:
                self.just_opened = False
                imgui.set_keyboard_focus_here()

            # Close the palette if ESC is pressed.
            if imgui.is_key_pressed(imgui.Key.escape, False):
                self.close()
                imgui.end()
                imgui.pop_style_var(2)  # Pop window_padding & item_spacing.
                imgui.pop_style_color()
                return

            # Calculate window boundaries (min and max positions).
            win_pos_min = imgui.get_window_pos() + imgui.get_main_viewport().pos
            win_pos_max = imgui.get_window_size() + imgui.get_main_viewport().pos
            min_x, min_y = win_pos_min
            max_x, max_y = (win_pos_min[0] + win_pos_max[0], win_pos_min[1] + win_pos_max[1])

            # If a mouse click occurs outside the window, close the palette.
            if imgui.is_mouse_clicked(0):
                mouse_x, mouse_y = imgui.get_mouse_pos()
                clicked_outside: bool = not (min_x <= mouse_x <= max_x and min_y <= mouse_y <= max_y)
                if clicked_outside:
                    self.is_open = False

            old_query: str = self.search_query
            input_flags = imgui.InputTextFlags_.enter_returns_true

            # --- Apply specific padding and border color for the input field ---
            input_padding: Tuple[int, int] = (16, 10)
            imgui.push_style_var(imgui.StyleVar_.frame_padding, input_padding)
            imgui.push_style_color(imgui.Col_.border, (0.922, 0.271, 0.624, 0.6))
            imgui.push_font(Utils.console_head_font)

            imgui.set_next_item_width(-1)
            pressed_enter, new_query = imgui.input_text_with_hint("##CommandSearch", " > CMD", self.search_query, flags=input_flags)

            imgui.pop_font()
            imgui.pop_style_color()
            imgui.pop_style_var()  # End input field style.

            if new_query != old_query:
                self.search_query = new_query

            imgui.pop_style_var()  # Pop replaced item spacing.
            imgui.push_style_var(imgui.StyleVar_.item_spacing, (0, 2))
            imgui.begin_child("##selectablelist", window_flags=flags)

            # --- Filter commands based on search query ---
            tokens: List[str] = [t for t in self.search_query.lower().split() if t]
            filtered: List[Tuple[int, Command]] = []
            for i, cmd in enumerate(self.commands):
                if all(token in cmd.name.lower() for token in tokens):
                    filtered.append((i, cmd))

            # Fast selection: if only one item matches and fast mode is enabled.
            if len(filtered) == 1 and self.search_query.strip() and constants.PALETTE_FAST_MODE:
                self.selected = True
                _, only_cmd = filtered[0]
                only_cmd.callback()
                self.close()
                imgui.end_child()
                imgui.end()
                imgui.pop_style_color()  # Pop border color.
                imgui.pop_style_var(2)   # Pop window_padding & item_spacing.
                return

            # --- Keyboard navigation (arrow keys) and selection ---
            if filtered:
                if imgui.is_key_pressed(imgui.Key.down_arrow, True):
                    filtered_index = (filtered_index + 1) % len(filtered)
                if imgui.is_key_pressed(imgui.Key.up_arrow, True):
                    filtered_index = (filtered_index - 1) % len(filtered)
                if pressed_enter:
                    if filtered_index >= len(filtered):
                        filtered_index = 0
                    _, selected_cmd = filtered[filtered_index]
                    self.selected = True
                    selected_cmd.callback()
                    self.close()
                    imgui.end_child()
                    imgui.end()
                    imgui.pop_style_color()  # Pop border color.
                    imgui.pop_style_var(2)   # Pop window_padding & item_spacing.
                    return
                for idx, (_, cmd) in enumerate(filtered):
                    selected: bool = (idx == filtered_index)
                    clicked, _ = imgui.selectable(" " + cmd.name, selected)
                    if selected:
                        imgui.set_scroll_here_y()
                    if clicked:
                        self.selected = True
                        cmd.callback()
                        self.close()
                        imgui.end_child()
                        imgui.end()
                        imgui.pop_style_color()  # Pop border color.
                        imgui.pop_style_var(2)   # Pop window_padding & item_spacing.
                        return
            else:
                imgui.text("No matching items")

            imgui.end_child()
        imgui.end()
        imgui.pop_style_color()  # Pop border color.
        imgui.pop_style_var(2)   # Pop window_padding & item_spacing.
