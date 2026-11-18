#!/usr/bin/env python3
"""
Teste de integração ponta a ponta do Caminho Livre (só biblioteca padrão).

Liga o servidor de verdade numa pasta temporária (com o robô agendado) e confere, sem
nenhum clique, o fluxo completo: segurança, LGPD, importação de CSV, deduplicação entre
fontes, alertas, quarentena, trava de execução única, exclusão, retenção, auditoria
encadeada e verificação de integridade.

Uso, a partir da raiz do repositório:
    python tests/test_integracao.py [--porta 8765] [--saida PASTA]

--saida copia amostras de logs (sem dados sensíveis) para PASTA, para uso como evidência.
Termina com código 0 se tudo passou e 1 se algo falhou.
"""
import argparse
import http.client
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SRC = RAIZ / "src"
GPS = b"GPSLatitude=-23.6229;GPSLongitude=-46.5548"
resultados = []


def checar(nome, condicao, detalhe=""):
    resultados.append(bool(condicao))
    print(("PASSOU  " if condicao else "FALHOU  ") + nome + (f"  ->  {detalhe}" if detalhe else ""), flush=True)


def esperar(condicao, timeout=25, passo=0.4):
    fim = time.time() + timeout
    while time.time() < fim:
        try:
            r = condicao()
            if r:
                return r
        except Exception:  # noqa: BLE001
            pass
        time.sleep(passo)
    return None


def _seg(m, p):
    return bytes([0xFF, m]) + (len(p) + 2).to_bytes(2, "big") + p


def foto(n):
    """JPEG sintético com EXIF contendo 'GPS'; n muda o conteúdo (hash diferente)."""
    return (b"\xff\xd8" + _seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
            + _seg(0xE1, b"Exif\x00\x00" + GPS) + _seg(0xDB, b"\x00" + bytes(64))
            + _seg(0xDA, b"\x01\x01\x00\x00\x3f\x00") + bytes([n, n + 1, n + 2]) + b"\xff\xd9")


class Cliente:
    def __init__(self, porta):
        self.porta = porta

    def req(self, metodo, caminho, corpo=None, chave=None, cookie=None, form=None):
        h = {}
        if chave:
            h["X-API-Key"] = chave
        if cookie:
            h["Cookie"] = cookie
        if form is not None:
            corpo = urllib.parse.urlencode(form).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        c = http.client.HTTPConnection("127.0.0.1", self.porta, timeout=15)
        c.request(metodo, caminho, body=corpo if corpo is not None else (b"" if metodo == "POST" else None), headers=h)
        r = c.getresponse()
        dados = r.read()
        cab = dict(r.getheaders())
        c.close()
        try:
            j = json.loads(dados)
        except ValueError:
            j = None
        return r.status, cab, dados, j


def url_envio(cat, rua, ref, aceite=True):
    q = dict(categoria=cat, rua=rua, referencia=ref, descricao="relato de teste")
    if aceite:
        q["aceite"] = "sim"
    return "/api/ocorrencias?" + urllib.parse.urlencode(q)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--porta", type=int, default=8765)
    ap.add_argument("--saida", help="pasta para copiar amostras de logs sem dados sensíveis")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="cl_integ_"))
    for f in SRC.glob("*.py"):
        shutil.copy(f, tmp / f.name)
    shutil.copytree(SRC / "entrada", tmp / "entrada")
    print(f"Pasta temporária: {tmp}\nPorta: {args.porta}\n")

    api = Cliente(args.porta)
    srv = subprocess.Popen([sys.executable, "servidor_caminho_livre.py", "--port", str(args.porta),
                            "--intervalo", "0.05"], cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        checar("servidor sobe", esperar(lambda: api.req("GET", "/")[0] == 200, 10))
        chave = (tmp / "chave_api.txt").read_text().strip()
        resumo = lambda: api.req("GET", "/api/v1/resumo", chave=chave)[3]  # noqa: E731
        alertas = lambda: [a["tipo"] for a in api.req("GET", "/api/v1/alertas?limite=200", chave=chave)[3]["itens"]]  # noqa: E731

        print("\n== SEGURANÇA")
        for m, p in (("GET", "/api/v1/resumo"), ("GET", "/api/v1/integridade"), ("GET", "/uploads/x.jpg"), ("POST", "/api/robo")):
            checar(f"{m} {p} sem chave é negado", api.req(m, p)[0] == 401)
        s, h, d, _ = api.req("GET", "/painel")
        checar("painel sem login mostra a tela de login", s == 401 and b"Chave de acesso" in d)
        checar("login com chave errada é recusado", api.req("POST", "/login", form={"chave": "errada"})[0] == 401)
        s, h, d, _ = api.req("POST", "/login", form={"chave": chave})
        ck = h.get("Set-Cookie", "").split(";")[0]
        checar("login correto devolve cookie HttpOnly e SameSite=Strict",
               s == 303 and "HttpOnly" in h.get("Set-Cookie", "") and "SameSite=Strict" in h.get("Set-Cookie", ""))
        checar("painel abre com o cookie", api.req("GET", "/painel", cookie=ck)[0] == 200)
        checar("API aceita X-API-Key", api.req("GET", "/api/v1/resumo", chave=chave)[0] == 200)
        hh = api.req("GET", "/")[1]
        checar("cabeçalhos de segurança presentes e sem versão do Python",
               hh.get("X-Content-Type-Options") == "nosniff" and "Content-Security-Policy" in hh
               and "Python" not in hh.get("Server", ""))

        print("\n== AGENDADOR: o CSV da pasta entrada/ é importado sozinho (sem clique)")
        r = esperar(lambda: (lambda x: x if x["por_status"].get("encaminhada", 0) >= 3 else None)(resumo()), 25)
        checar("importou e processou o CSV automaticamente", r, r["por_status"] if r else "")
        ps = r["por_status"] if r else {}
        checar("3 encaminhadas, 2 duplicadas e 2 rejeitadas (regras de negócio)",
               (ps.get("encaminhada"), ps.get("duplicada"), ps.get("rejeitada")) == (3, 2, 2))
        checar("alerta de prioridade ALTA gerado (buraco relatado 3 vezes)", "prioridade_alta" in alertas())
        checar("batimento do robô registrado", resumo()["ultimo_ciclo"] is not None)

        print("\n== LGPD E ENVIO DO CIDADÃO")
        checar("envio sem aceitar o aviso de privacidade é recusado",
               api.req("POST", url_envio("poste", "Rua Nova 10", "Perto da praça", aceite=False), corpo=foto(1))[0] == 400)
        checar("arquivo que não é imagem é recusado",
               api.req("POST", url_envio("poste", "Rua Nova 10", "Perto da praça"), corpo=b"nao sou imagem")[0] == 400)
        s, _, _, j = api.req("POST", url_envio("buraco", "R. Manoel Coelho", "em frente a padaria Pao Doce"), corpo=foto(10))
        t_dup = j["token"]
        checar("envio válido gera código de acompanhamento", s == 201 and len(t_dup) == 10)
        t_poste = api.req("POST", url_envio("poste", "Rua Nova 10", "Perto da praça"), corpo=foto(20))[3]["token"]
        t_apagar = api.req("POST", url_envio("lixeira", "Rua Das Flores 5", "Ao lado da escola"), corpo=foto(30))[3]["token"]
        fotos = [p.read_bytes() for p in (tmp / "uploads").iterdir()]
        checar("fotos guardadas não contêm GPS/EXIF", fotos and all(GPS not in f for f in fotos), f"{len(fotos)} foto(s)")
        st = lambda t: api.req("GET", "/api/acompanhar/" + t)[3]  # noqa: E731
        checar("relato repetido (CSV + cidadão) vira duplicada",
               esperar(lambda: st(t_dup)["status"] == "duplicada"), "deduplicação entre fontes")
        checar("relato novo é encaminhado com protocolo",
               esperar(lambda: st(t_poste)["status"] == "encaminhada" and st(t_poste)["protocolo"]))

        print("\n== RESILIÊNCIA: nada falha em silêncio")
        (tmp / "entrada" / "ong_ruim.csv").write_text("nome,telefone\nAna,11999990000\n")
        con = sqlite3.connect(tmp / "caminho_livre.db", timeout=30)
        con.execute("INSERT INTO ocorrencias(categoria,rua,referencia,criado_em,origem,reincidencias)"
                    " VALUES('obra','Rua Teste','Ref teste',datetime('now'),'teste',NULL)")
        con.commit()
        con.close()
        a = esperar(lambda: (lambda x: x if "falha_importacao" in x and "ocorrencia_em_quarentena" in x else None)(alertas()), 30)
        checar("CSV defeituoso gera alerta de falha de importação", a and "falha_importacao" in a)
        checar("CSV defeituoso é movido para entrada/erro/", list((tmp / "entrada" / "erro").glob("*ong_ruim.csv")))
        checar("registro defeituoso vai para quarentena após 3 falhas (não trava a fila)",
               a and "ocorrencia_em_quarentena" in a and resumo()["por_status"].get("erro_permanente") == 1)
        checar("falha da execução gera alerta de falha do robô", "falha_robo" in alertas())
        ex = api.req("GET", "/api/v1/execucoes?limite=50", chave=chave)[3]
        checar("histórico traz data/hora, processados, sucessos, falhas e mensagem de erro",
               any(e["falhas"] and e["erros"] and e["inicio"] for e in ex["itens"]))
        checar("ciclos sem itens não poluem o histórico", ex["total"] <= 8, f"{ex['total']} execuções com itens")

        print("\n== TRAVA DE EXECUÇÃO ÚNICA")
        (tmp / "robo.lock").write_text("teste")
        s, _, _, j = api.req("POST", "/api/robo", chave=chave)
        checar("com outra execução em andamento a nova é ignorada (409)", s == 409 and j.get("pulada"))
        velho = time.time() - 1200
        os.utime(tmp / "robo.lock", (velho, velho))
        checar("trava abandonada é removida sozinha", esperar(lambda: not (tmp / "robo.lock").exists(), 10))

        print("\n== DIREITO DE EXCLUSÃO")
        antes = len(list((tmp / "uploads").iterdir()))
        s = api.req("POST", "/api/apagar?token=" + t_apagar)[0]
        checar("titular apaga o próprio relato com o código", s == 200)
        checar("a foto também é apagada", len(list((tmp / "uploads").iterdir())) == antes - 1)
        checar("relato apagado não é mais encontrado", api.req("GET", "/api/acompanhar/" + t_apagar)[0] == 404)

        print("\n== RETENÇÃO (90 dias)")
        (tmp / "uploads" / "velha.jpg").write_bytes(foto(99))
        con = sqlite3.connect(tmp / "caminho_livre.db", timeout=30)
        con.execute("INSERT INTO ocorrencias(categoria,rua,referencia,foto_path,criado_em,status)"
                    " VALUES('lixeira','Rua Velha','Ref','uploads/velha.jpg',datetime('now','-200 day'),'encaminhada')")
        con.commit()
        con.close()
        antigo = time.time() - 200 * 86400
        (tmp / "outbox" / "antigo.json").write_text("{}")
        os.utime(tmp / "outbox" / "antigo.json", (antigo, antigo))
        out = subprocess.run([sys.executable, "rpa_caminho_livre.py", "--limpar"], cwd=tmp, capture_output=True, text=True).stdout
        checar("dados, fotos e arquivos com mais de 90 dias são apagados",
               not (tmp / "uploads" / "velha.jpg").exists() and not (tmp / "outbox" / "antigo.json").exists(), out.strip())

        print("\n== INTEGRAÇÃO VERIFICÁVEL AO MVP")
        p = subprocess.run([sys.executable, "rpa_caminho_livre.py", "--verificar", "--url", f"http://127.0.0.1:{args.porta}",
                            "--chave", chave], cwd=tmp, capture_output=True, text=True)
        v = json.loads(p.stdout)
        checar("banco, arquivos de saída e API estão consistentes", p.returncode == 0 and v["consistente"],
               f"banco={v['encaminhadas_no_banco']} api={v['encaminhadas_na_api']} auditoria_integra={v['auditoria_integra']}")
        integ = api.req("GET", "/api/v1/integridade", chave=chave)[3]
        checar("endpoint /api/v1/integridade confirma", integ["consistente"])

        if args.saida:  # amostras de evidência (antes de adulterar a auditoria de propósito)
            dest = Path(args.saida)
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copy(tmp / "rpa.log", dest / "rpa_amostra.log")
            shutil.copy(tmp / "logs" / "execucoes.jsonl", dest / "execucoes_amostra.jsonl")
            (dest / "auditoria_amostra.json").write_text(json.dumps(
                api.req("GET", "/api/v1/auditoria?limite=500", chave=chave)[3], ensure_ascii=False, indent=2), encoding="utf-8")
            (dest / "verificacao_integridade.json").write_text(p.stdout, encoding="utf-8")

        print("\n== AUDITORIA ADULTERADA É DETECTADA")
        con = sqlite3.connect(tmp / "caminho_livre.db", timeout=30)
        alvo = con.execute("SELECT id FROM auditoria ORDER BY id LIMIT 1 OFFSET 2").fetchone()[0]
        con.execute("UPDATE auditoria SET detalhe='ADULTERADO' WHERE id=?", (alvo,))
        con.commit()
        con.close()
        p = subprocess.run([sys.executable, "rpa_caminho_livre.py", "--verificar"], cwd=tmp, capture_output=True, text=True)
        v = json.loads(p.stdout)
        checar("verificação acusa a divergência (código de saída 1)", p.returncode == 1 and not v["auditoria_integra"],
               f"primeira divergência no registro {v.get('auditoria_primeira_divergencia_id')}")

        print("\n== LIMITE DE REQUISIÇÕES")
        codigos = [api.req("POST", url_envio("buraco", "Rua X1", "ref x", aceite=False), corpo=b"")[0] for _ in range(25)]
        checar("após 20 envios por minuto o IP recebe 429", 429 in codigos, f"{codigos.count(429)} bloqueios")
    finally:
        srv.terminate()
        srv.wait(timeout=10)

    print("\n== LOGS SEM DADOS SENSÍVEIS")
    log = (tmp / "rpa.log").read_text(encoding="utf-8") + (tmp / "logs" / "execucoes.jsonl").read_text(encoding="utf-8")
    for termo in ("Manoel", "padaria", "Rua Teste", "Rua Nova", "Flores", "127.0.0.1", "GPSLat", "11999990000"):
        checar(f"o termo {termo!r} não aparece nos logs", termo not in log)
    for nome, t in (("código de acompanhamento 1", t_dup), ("código 2", t_poste), ("código 3", t_apagar)):
        checar(f"{nome} não aparece nos logs", t not in log)

    total, ok = len(resultados), sum(resultados)
    print(f"\nRESULTADO: {ok}/{total} verificações passaram")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
