#!/usr/bin/env python3
"""
Exemplo de OUTRO componente da CitizenTech consumindo o Caminho Livre via API.

Lê só o que é novo desde a última execução (checkpoint em arquivo) e imprime.
Troque o print por sua regra: abrir chamado, notificar secretaria, alimentar BI...

A API exige a chave do servidor (arquivo chave_api.txt ou variável CAMINHO_LIVRE_CHAVE).

Uso: python consumidor_exemplo.py [http://localhost:8000]
"""
import json
import os
import sys
import urllib.request
from pathlib import Path

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
CHECKPOINT = Path("consumidor_checkpoint.json")


def chave():
    if os.environ.get("CAMINHO_LIVRE_CHAVE"):
        return os.environ["CAMINHO_LIVRE_CHAVE"]
    arq = Path("chave_api.txt")
    return arq.read_text(encoding="utf-8").strip() if arq.exists() else ""


def main():
    desde = json.loads(CHECKPOINT.read_text())["desde_id"] if CHECKPOINT.exists() else 0
    novos = 0
    while True:
        url = f"{BASE}/api/v1/encaminhamentos?desde_id={desde}&limite=100"
        req = urllib.request.Request(url, headers={"X-API-Key": chave()})
        with urllib.request.urlopen(req, timeout=10) as r:
            pacote = json.load(r)
        if pacote["versao"].split(".")[0] != "1":
            raise SystemExit(f"contrato {pacote['versao']} incompatível (esperado 1.x)")
        if not pacote["itens"]:
            break
        for o in pacote["itens"]:
            print(f"[{o['protocolo']}] {o['categoria']} | prioridade {o['prioridade']['nivel']}"
                  f" | {o['local']['rua']} ({o['local']['referencia']})")
            novos += 1
        desde = pacote["proximo_id"]
        CHECKPOINT.write_text(json.dumps({"desde_id": desde}))  # só avança depois de processar
    print(f"{novos} ocorrência(s) nova(s). Checkpoint em id {desde}.")


if __name__ == "__main__":
    main()
