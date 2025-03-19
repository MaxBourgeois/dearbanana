# frida_hook_manager/main.py

import logging
import sys
from imgui_bundle import imgui, immapp, hello_imgui
from app import FridaHookManagerApp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def style() -> None:
    style = imgui.get_style()
    
    style.alpha = 1.0
    style.disabled_alpha = 0.6
    style.window_padding = (10.0, 10.0)
    style.window_rounding = 10.0
    style.window_border_size = 1.0
    style.window_min_size = (32.0, 32.0)
    style.window_title_align = (0.0, 0.5)
    style.child_rounding = 3.0
    style.child_border_size = 1.0
    style.popup_rounding = 5.0
    style.popup_border_size = 0.0
    style.frame_padding = (10.0, 5.0)
    style.frame_rounding = 10.0
    style.frame_border_size = 1.0
    style.item_spacing = (10, 10.0)
    style.item_inner_spacing = (10.0, 10.0)
    style.cell_padding = (4.0, 4.0)
    style.indent_spacing = 21.0
    style.columns_min_spacing = 6.0
    style.scrollbar_size = 14.0
    style.scrollbar_rounding = 10.0
    style.grab_min_size = 10.0
    style.grab_rounding = 10.0
    
    style.button_text_align = (0.5, 0.5)
    style.selectable_text_align = (0.0, 0.0)

    style.popup_border_size = 1

    style.tab_rounding = 5.0
    style.tab_border_size = 1.0
    style.tab_min_width_for_close_button = 0.0
    style.tab_bar_overline_size = 0
    style.tab_bar_border_size = 0
    style.tab_border_size = 0

def main() -> None:
    """
    Main entry point of the application. Sets up the ImGui context,
    initializes the application, and starts the graphical loop.
    """
    imgui.create_context()
    app = FridaHookManagerApp()
    params = hello_imgui.RunnerParams()
    params.callbacks.show_gui = app.draw_gui
    params.app_window_params.window_geometry.window_size_state = hello_imgui.WindowSizeState.maximized
    params.app_window_params.window_title = "0xDearBanana"
    
    params.app_window_params.window_geometry.monitor_idx = 0  # 1 to show on second screen
    
    params.app_window_params.borderless = True
    params.app_window_params.borderless_closable = False
    params.app_window_params.borderless_movable = False
    params.app_window_params.borderless_resizable = True
    params.app_window_params.borderless_highlight_color = (0.2, 0.4, 1.0, 0)

    params.imgui_window_params.enable_viewports = True
    params.imgui_window_params.show_status_bar = False

    params.callbacks.setup_imgui_style = style
    params.callbacks.load_additional_fonts = app.load_font
    
    params.use_imgui_test_engine = True

    immapp.run(params)

if __name__ == "__main__":
    sys.exit(main())
