# constants.py
from enum import Enum

class HookChainStep(Enum):
    PROCESS = 0
    MODULE = 1
    FUNCTION = 2

class WindowToggleOption(Enum):
    HOOKS_MANAGEMENT = 0
    FRIDA_CONSOLE = 1
    GLOBAL_HOOKS_LOG = 2
    WIDGET_INSPECTOR = 3

HOOKS_MANAGEMENT_WINDOW_TITLE = "Hooks Management"
DEFAULT_PROJECT_FILE = "project.json"
ADD_HOOK_COMMAND_NAME = "Add function hook"
TOGGLE_WINDOW_COMMAND_NAME = "Toggle Window"
TOGGLE_HOOK_COMMAND_NAME = "Toggle Hook"
SAVE_PROJECT_COMMAND_NAME = "Save Project"
LOAD_PROJECT_COMMAND_NAME = "Load Project"
REFRESH_PROCESS_COMMAND_NAME = "Refresh process list"
DEBUG_UI_COMMAND_NAME = "Debug UI"
CHANGE_THEME_COMMAND_NAME = "Change Theme"
TEST_COMMAND_NAME = "Tests"

PALETTE_FAST_MODE = False