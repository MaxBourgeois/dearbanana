#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

try:
    import pyperclip
except ImportError:
    print("Le module 'pyperclip' est requis pour copier dans le presse-papiers.")
    print("Installez-le avec : pip install pyperclip")
    sys.exit(1)


def main(directory: str) -> None:
    """
    Parcourt tous les fichiers .py d'un répertoire (et, par défaut, ses sous-répertoires),
    et copie leur contenu dans le presse-papiers avec un entête "nom_du_fichier.py :".
    """
    result_lines = []

    # for root, dirs, files in os.walk(directory):
    #     for filename in files:
    #         if filename.endswith(".py"):
    #             file_path = os.path.join(root, filename)
    #             try:
    #                 with open(file_path, "r", encoding="utf-8") as f:
    #                     content = f.read()
    #                 # Prépare l'en-tête + contenu
    #                 result_lines.append(f"{filename} :\n{content}\n")
    #             except Exception as e:
    #                 print(f"Impossible de lire {file_path} : {e}")

    for file in os.listdir(directory):
        if file.endswith(".py"):
            file_path = os.path.join(directory, file)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                # Prépare l'en-tête + contenu
                result_lines.append(f"{file} :\n{content}\n")
            except Exception as e:
                print(f"Impossible de lire {file_path} : {e}")

    # Concatène le tout dans une grande chaîne
    final_text = "\n".join(result_lines)

    # Copie dans le presse-papiers
    pyperclip.copy(final_text)
    print("Le contenu de tous les fichiers .py a été copié dans le presse-papiers !")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage : {sys.argv[0]} <repertoire>")
        sys.exit(1)

    directory_arg = sys.argv[1]
    if not os.path.isdir(directory_arg):
        print(f"Erreur : '{directory_arg}' n'est pas un répertoire valide.")
        sys.exit(1)

    main(directory_arg)
