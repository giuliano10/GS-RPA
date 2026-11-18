#!/usr/bin/env python3
"""
Gera as evidências visuais do repositório (pasta assets/): liga o sistema numa pasta
temporária com dados de demonstração e tira capturas de tela reais com um navegador
automatizado.

Requisitos (opcionais, só para este script):
    pip install pillow playwright && playwright install chromium

Uso, a partir da raiz do repositório:
    python tests/capturar_telas.py [--porta 8766] [--saida assets]

As fotos usadas são ILUSTRAÇÕES geradas pelo script (marcadas "FOTO DE EXEMPLO"),
não fotos de pessoas ou de lugares reais.
"""
import argparse
import html
import http.client
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

from PIL import Image, ImageDraw
from playwright.sync_api import sync_playwright

RAIZ = Path(__file__).resolve().parent.parent
SRC = RAIZ / "src"


def foto_exemplo(caminho, tipo):
    """Ilustração simples de uma calçada com um obstáculo."""
    img = Image.new("RGB", (900, 600), (176, 176, 170))
    d = ImageDraw.Draw(img)
    for x in range(0, 900, 150):
        d.line([(x, 0), (x, 600)], fill=(150, 150, 145), width=3)
    for y in range(0, 600, 150):
        d.line([(0, y), (900, y)], fill=(150, 150, 145), width=3)
    if tipo == "buraco":
        d.ellipse([300, 230, 600, 420], fill=(60, 55, 50), outline=(35, 30, 28), width=8)
    elif tipo == "poste":
        d.rectangle([410, 60, 470, 560], fill=(70, 70, 75))
        d.ellipse([385, 30, 495, 110], fill=(90, 90, 95))
    else:  # desnível
        d.polygon([(0, 330), (900, 250), (900, 600), (0, 600)], fill=(150, 150, 145))
        d.line([(0, 330), (900, 250)], fill=(40, 40, 40), width=10)
    d.rectangle([20, 20, 330, 62], fill=(255, 255, 255))
    d.text((32, 33), "FOTO DE EXEMPLO (ilustração)", fill=(20, 20, 20))
    img.save(caminho, "JPEG", quality=85)


def req(porta, metodo, caminho, corpo=None, chave=None):
    c = http.client.HTTPConnection("127.0.0.1", porta, timeout=15)
    c.request(metodo, caminho, body=corpo, headers={"X-API-Key": chave} if chave else {})
    r = c.getresponse()
    dados = r.read()
    c.close()
    return r.status, json.loads(dados) if dados[:1] in (b"{", b"[") else dados


def envio(cat, rua, ref):
    return "/api/ocorrencias?" + urllib.parse.urlencode(
        dict(categoria=cat, rua=rua, referencia=ref, descricao="relato de demonstração", aceite="sim"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--porta", type=int, default=8766)
    ap.add_argument("--saida", default=str(RAIZ / "assets"))
    args = ap.parse_args()
    saida = Path(args.saida)
    saida.mkdir(parents=True, exist_ok=True)

    tmp = Path(tempfile.mkdtemp(prefix="cl_telas_"))
    for f in SRC.glob("*.py"):
        shutil.copy(f, tmp / f.name)
    shutil.copytree(SRC / "entrada", tmp / "entrada")
    for tipo in ("buraco", "poste", "desnivel"):
        foto_exemplo(tmp / f"foto_{tipo}.jpg", tipo)

    srv = subprocess.Popen([sys.executable, "servidor_caminho_livre.py", "--port", str(args.porta),
                            "--intervalo", "0.05"], cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(2)
        chave = (tmp / "chave_api.txt").read_text().strip()
        # dados de demonstração: relatos, CSV defeituoso e um registro com defeito (para alertas e erros)
        req(args.porta, "POST", envio("buraco", "R. Manoel Coelho", "em frente a padaria Pao Doce"),
            (tmp / "foto_buraco.jpg").read_bytes())
        req(args.porta, "POST", envio("poste", "Avenida Goiás", "Perto do ponto de ônibus"),
            (tmp / "foto_poste.jpg").read_bytes())
        (tmp / "entrada" / "ong_ruim.csv").write_text("nome,telefone\nexemplo,000\n")
        con = sqlite3.connect(tmp / "caminho_livre.db", timeout=30)
        con.execute("INSERT INTO ocorrencias(categoria,rua,referencia,criado_em,origem,reincidencias)"
                    " VALUES('obra','Rua Exemplo','Ref exemplo',datetime('now'),'teste',NULL)")
        con.commit()
        con.close()
        time.sleep(14)  # ciclos automáticos: importação, duplicidade, alertas e quarentena

        base = f"http://127.0.0.1:{args.porta}"
        with sync_playwright() as p:
            nav = p.chromium.launch()
            # bypass_csp: só o navegador de captura precisa avaliar scripts de espera; o servidor
            # continua enviando a política CSP (verificada em tests/test_integracao.py)
            ctx = nav.new_context(viewport={"width": 1000, "height": 900}, locale="pt-BR", bypass_csp=True)
            pg = ctx.new_page()

            pg.goto(base + "/")
            pg.screenshot(path=saida / "01_formulario_cidadao.png", full_page=True)

            pg.set_input_files("#foto", str(tmp / "foto_desnivel.jpg"))
            pg.select_option("#cat", "desnivel")
            pg.fill("#rua", "Rua Santo Antônio")
            pg.fill("#ref", "Esquina com a farmácia")
            pg.check("#aceite")
            pg.screenshot(path=saida / "02_formulario_preenchido.png", full_page=True)

            pg.click("button[type=submit]")
            pg.wait_for_function("document.getElementById('msg').textContent.includes('código')")
            pg.screenshot(path=saida / "03_relato_enviado_com_codigo.png", full_page=True)

            time.sleep(5)  # o robô agendado processa o relato sozinho
            pg.click("#consultar")
            pg.wait_for_function("document.getElementById('res').textContent.includes('Encaminhado')", timeout=15000)
            pg.screenshot(path=saida / "04_acompanhamento_andamento.png", full_page=True)

            pg.goto(base + "/painel")
            pg.screenshot(path=saida / "05_painel_exige_login.png", full_page=True)
            pg.fill("#chave", chave)
            pg.click("button[type=submit]")
            pg.wait_for_selector("#cards .c")
            pg.wait_for_function("document.querySelectorAll('#criticos tr').length > 0 && "
                                 "document.getElementById('integ').textContent.length > 12")
            time.sleep(1.5)
            pg.screenshot(path=saida / "06_painel_orgaos_publicos.png", full_page=True)

            # resultado dos testes (texto real de tests/evidencias) renderizado como imagem
            ev = RAIZ / "tests" / "evidencias" / "resultado_integracao.txt"
            if ev.exists():
                texto = html.escape(ev.read_text(encoding="utf-8"))
                pg.set_viewport_size({"width": 1100, "height": 600})
                pg.set_content(f"<body style='margin:0;background:#101418;color:#d7dde4'><pre style="
                               f"'font:13px/1.45 ui-monospace,Menlo,Consolas,monospace;padding:18px;margin:0'>"
                               f"{texto.replace('PASSOU', '<b style=color:#4cd964>PASSOU</b>').replace('FALHOU', '<b style=color:#ff5f56>FALHOU</b>')}</pre></body>")
                pg.screenshot(path=saida / "07_resultado_testes_integracao.png", full_page=True)
            nav.close()
    finally:
        srv.terminate()
        srv.wait(timeout=10)
    print("Capturas salvas em", saida)
    for f in sorted(saida.glob("*.png")):
        print(" -", f.name)


if __name__ == "__main__":
    main()
