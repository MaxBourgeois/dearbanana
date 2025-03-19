# frida_hook_manager/themes.py
from imgui_bundle import hello_imgui, imgui, immapp

ALL_THEMES = [
    hello_imgui.ImGuiTheme_.darcula_darker,
    hello_imgui.ImGuiTheme_.darcula,
    hello_imgui.ImGuiTheme_.imgui_colors_classic,
    hello_imgui.ImGuiTheme_.imgui_colors_dark,
    hello_imgui.ImGuiTheme_.imgui_colors_light,
    hello_imgui.ImGuiTheme_.material_flat,
    hello_imgui.ImGuiTheme_.photoshop_style,
    hello_imgui.ImGuiTheme_.gray_variations,
    hello_imgui.ImGuiTheme_.gray_variations_darker,
    hello_imgui.ImGuiTheme_.microsoft_style,
    hello_imgui.ImGuiTheme_.cherry,
    hello_imgui.ImGuiTheme_.light_rounded,
    hello_imgui.ImGuiTheme_.so_dark_accent_blue,
    hello_imgui.ImGuiTheme_.so_dark_accent_yellow,
    hello_imgui.ImGuiTheme_.so_dark_accent_red,
    hello_imgui.ImGuiTheme_.black_is_black,
    hello_imgui.ImGuiTheme_.white_is_white,
]

ALL_THEMES_NAMES = [theme.name for theme in ALL_THEMES]
