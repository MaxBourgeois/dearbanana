# frida_hook_manager/ui_logs.py

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

from typing import Optional
from imgui_bundle import imgui
from loggers.logger_widgets import TableLogger

from ui_windows.fullscreenable_ui import FullscreenableUI

logger = logging.getLogger(__name__)


class GlobalHooksLogUI(FullscreenableUI):
    """
    Global window displaying hook logs (in table form).
    """
    def __init__(self, main_app: Optional[Any] = None) -> None:
        super().__init__()
        self.is_open: bool = True
        self.table_logger: TableLogger = TableLogger(main_app=main_app)

    def add_line(self, text: str, process_str: str, hook_id: int, address: str, funcname: str) -> None:
        self.table_logger.add_log_line(
            text,
            process_str=process_str,
            hook_id=hook_id,
            address=address,
            funcname=funcname
        )

    def draw_gui(self) -> None:
        if not self.is_open:
            return
        opened, self.is_open = self.begin_ui_window("Global Hooks Log")
        if opened:
            self.table_logger.draw()
        imgui.end()
        self.end_window_ui()
