#!/bin/sh
# Liga o Caminho Livre: servidor + robo agendado (1 ciclo por minuto).
cd "$(dirname "$0")" || exit 1
exec python3 servidor_caminho_livre.py
