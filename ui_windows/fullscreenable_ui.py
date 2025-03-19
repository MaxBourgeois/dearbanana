from imgui_bundle import imgui
from typing import Any, Dict, List, Optional, Union, Tuple

# 3 steps
# Add class parent
# Call parent constructor
# replace imgui.begin with self.begin_ui_window

class FullscreenableUI:
    """
    Base class providing common functionality for UI widgets:
      - Fullscreen toggling via Ctrl+F.
      - Automatic update of docking and focus state.
      - A convenience method 'begin_ui_window' to wrap imgui.begin().
    """
    def __init__(self) -> None:
        self.fullscreen: bool = False
        self.dockid: int = -1
        self.win_is_focused: bool = False
        self.is_open: bool = True
        self.style_pushed : bool = False
        self.place_holder_created: bool = False

    def _handle_fullscreen_shortcut(self) -> None:
        """
        Toggles fullscreen mode when Ctrl+F is pressed.
        Adjusts the next window's dock id, position and size.
        """
        io = imgui.get_io()
        is_ctrl_down = (io.key_mods & imgui.Key.mod_ctrl) != 0
        is_f_pressed = imgui.is_key_pressed(imgui.Key.f)

        if self.win_is_focused and not self.fullscreen and is_ctrl_down and is_f_pressed:
            if self.dockid > 0:
                imgui.set_next_window_dock_id(0, imgui.Cond_.always)
                imgui.set_next_window_pos(imgui.ImVec2(0, 0))
                imgui.set_next_window_size(io.display_size)
                self.fullscreen = True
        elif self.fullscreen and is_ctrl_down and is_f_pressed:
            if self.dockid > 0:
                imgui.set_next_window_dock_id(self.dockid, imgui.Cond_.always)
                self.fullscreen = False

    def _update_docking_focus_state(self) -> None:
        """
        Updates the docking and focus state of the window.
        """
        if imgui.is_window_docked():
            self.fullscreen = False
            self.dockid = imgui.get_window_dock_id()
        # else:
        #     self.fullscreen = True

        self.win_is_focused = imgui.is_window_focused(imgui.FocusedFlags_.child_windows)# or imgui.is_window_hovered(imgui.HoveredFlags_.child_windows)

    def begin_ui_window(self, title: str) -> Tuple[bool, bool]:
        """
        A convenience method that:
          - Handles fullscreen toggling.
          - Begins the window.
          - Updates docking and focus state.
        
        Args:
            title (str): The title of the window.
        
        Returns:
            (opened, window_focused): 'opened' is the boolean from imgui.begin,
                                        'window_focused' indicates if the window is focused.
        """
        self._handle_fullscreen_shortcut()
        if self.win_is_focused:
            imgui.push_style_color(imgui.Col_.window_bg, imgui.get_style_color_vec4(imgui.Col_.window_bg) + (0.01, 0.01, 0.01, 0))
            self.style_pushed = True

        opened, self.is_open = imgui.begin(title, self.is_open)
 
        if self.is_open:
            self._update_docking_focus_state()

        if self.win_is_focused:
            self.place_holder_created = True

        return opened, self.is_open
    
    def end_window_ui(self):
        if self.style_pushed:
            imgui.pop_style_color()
            self.style_pushed = False