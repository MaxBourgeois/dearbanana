# script_api.py

import threading
from imgui_bundle import imgui, immapp, hello_imgui

from app import FridaHookManagerApp
from api import FridaHookManagerAPI

from IPython import embed


app = FridaHookManagerApp()
banana = FridaHookManagerAPI(app)

api.run_gui(app)

hook_id = banana.add_hook("Notepad.exe", "KERNEL32.DLL", "CreateFileW", js_code='send("coucou")').id
hook_id = banana.add_hook("Notepad.exe", "KERNEL32.DLL", "ReadFile", js_code='send("coucou")').id
hook_id = banana.add_hook("Notepad.exe", "KERNEL32.DLL", "WriteFile", js_code='send("coucou")').id

print(f"Hook créés !")

if banana.start_hook(hook_id):
    print("Hook démarré avec succès !")
else:
    print("Erreur lors du démarrage du hook")

banana.save_project("mon_projet.json")

embed() # Run an interactive session with IPython