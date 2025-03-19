# frida_hook_manager/utils.py

import os
import datetime
import logging

from typing import (
    Callable,
    List,
    Tuple,
    Optional,
    Dict,
    Any,
    Union
)

from imgui_bundle import imgui

logger = logging.getLogger(__name__)

_global_overlay = None
class Utils:
    """
    Utility functions (time, file reading, etc.).
    """
    console_head_font: Optional[Any] = None

    @staticmethod
    def current_time_millis() -> str:
        """
        Returns the current time in ISO format with milliseconds.
        """
        now = datetime.datetime.now()
        return now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

    @staticmethod
    def read_script_contents(path: str) -> str:
        """
        Reads the contents of a file or returns an error comment if not found or unreadable.
        """
        if not os.path.isfile(path):
            return f"// File not found: {path}"
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            return f"// Error reading {path}: {e}"

    @staticmethod
    def getBigConsolaFont() -> Optional[Any]:
        """
        Returns the consola_head_font typeface.
        """
        return Utils.console_head_font
    
    @staticmethod
    def draw_overlay(color = (0.1, 0.1, 0.1, 0.5), overlay_name = ""):
        io = imgui.get_io()
        # Create invisible full size frame
        imgui.set_next_window_pos((imgui.get_main_viewport().pos.x, imgui.get_main_viewport().pos.y), cond=imgui.Cond_.always)
        imgui.set_next_window_size((io.display_size.x, io.display_size.y), cond=imgui.Cond_.always)
        # Disabling interaction and decoration
        flags = (imgui.WindowFlags_.no_decoration |
                imgui.WindowFlags_.no_inputs |
                imgui.WindowFlags_.no_background
                #imgui.WindowFlags_.no_focus_on_appearing |
                #imgui.WindowFlags_.no_bring_to_front_on_focus
                )

        opened, _ = imgui.begin("##OverlayWindow" + "_" + overlay_name, True, flags)
        if opened:
            draw_list = imgui.get_window_draw_list()
            overlay_color = imgui.get_color_u32(color)
            draw_list.add_rect_filled((imgui.get_main_viewport().pos.x, imgui.get_main_viewport().pos.y),
                                      io.display_size + imgui.get_main_viewport().pos,
                                      overlay_color)
        imgui.end()
