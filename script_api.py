# script_api.py

import threading
from imgui_bundle import imgui, immapp, hello_imgui

from app import FridaHookManagerApp
from api.api import FridaHookManagerAPI

from IPython import embed




app = FridaHookManagerApp()
banana = FridaHookManagerAPI(app)

banana.run_gui()

hook_id = banana.add_hook("Notepad.exe", "KERNEL32.DLL", "CreateFileW", js_code='send("hello")').id
hook_id = banana.add_hook("Notepad.exe", "KERNEL32.DLL", "ReadFile", js_code='send("hello")').id
hook_id = banana.add_hook("Notepad.exe", "KERNEL32.DLL", "WriteFile", js_code='send("hello")').id

print(f"Hook créés !")

if banana.start_hook(hook_id):
    print("Hook successfully started !")
else:
    print("Hook startup error")

banana.save_project("my_project.json")

embed() # Run an interactive session with IPython