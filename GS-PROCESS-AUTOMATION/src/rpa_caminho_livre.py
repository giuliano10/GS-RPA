#!/usr/bin/env python3
"""
Caminho Livre - RPA de triagem de ocorrências (ponta a ponta).

Ciclo (roda sozinho a cada 1 minuto quando o servidor está ligado, ou com --agendar):
  1. Importa fontes externas (CSVs em entrada/)
  2. Lê a fila (novas + reenvios) e valida cada ocorrência
  3. Detecta duplicidades (foto igual, ou mesma rua + referência parecida)
  4. Calcula prioridade, gera protocolo e gera alertas
  5. Encaminha o lote (retry), com trava de execução única e quarentena de itens defeituosos
  6. Registra logs, auditoria encadeada e histórico de execuções

Só usa a biblioteca padrão. O "MVP" é um SQLite (troque pelo banco real).
Comandos: --agendar, --seed, --importar, --limpar, --apagar, --reprocessar, --verificar
"""
import argparse
import csv
import difflib
import hashlib
import io
import json
import logging
import logging.handlers
import os
import re
import shutil
import sqlite3
import sys
import time
import unicodedata
import urllib.request
import uuid
from datetime import datetime, timedelta
from pathlib import Path

DB = "caminho_livre.db"
OUTBOX = Path("outbox")
SIMILARIDADE_RUA = 0.85
SIMILARIDADE_REFERENCIA = 0.60
JANELA_DUPLICIDADE_DIAS = 30
MAX_TENTATIVAS = 3
CONTRATO_VERSAO = "1.1"
CAMPOS_OBRIGATORIOS = ["categoria", "rua", "referencia", "foto_hash"]
PESOS = {"buraco": 5, "desnivel": 4, "obra": 4, "veiculo": 3,
         "poste": 3, "lixeira": 2, "outro": 1}

LOGS = Path("logs")
ENTRADA = Path("entrada")    # pasta-fonte: CSVs de outras origens (prefeitura, ONGs...)
ALERTAS = Path("alertas")    # alertas em arquivo (.jsonl)
UPLOADS = Path("uploads")    # fotos recebidas (sem metadados)
TRAVA = Path("robo.lock")    # garante uma execução por vez
TRAVA_VELHA_S = 600          # trava com mais de 10 min é considerada abandonada
INTERVALO_PADRAO_MIN = 1     # agendamento: de 1 em 1 minuto
RETENCAO_DIAS = 90           # LGPD: dados apagados depois de 90 dias
LIMITE_TENTATIVAS_ITEM = 3   # falhas de processamento antes da quarentena

# Padrões de dados que NUNCA devem aparecer em logs, auditoria ou mensagens de erro.
PADROES_SENSIVEIS = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[email]"),
    (re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"), "[cpf]"),
    (re.compile(r"\(?\b\d{2}\)?\s?9?\d{4}-?\d{4}\b"), "[telefone]"),
    (re.compile(r"-?\d{1,3}\.\d{4,}"), "[coordenada]"),
    (re.compile(r"\b[0-9a-fA-F]{32,64}\b"), "[hash]"),
    # caminhos de arquivo (2+ segmentos); rotas da própria API e "1/3" não entram
    (re.compile(r"(?<![\w.\-/])(?:[A-Za-z]:)?(?!/api/|/painel|/uploads/)(?:[\\/][\w.-]+){2,}"), "[caminho]"),
]


def sanitizar(texto, limite=200):
    """Remove e-mail, CPF, telefone, coordenadas, hashes e caminhos de arquivo."""
    t = str(texto)
    for padrao, subst in PADROES_SENSIVEIS:
        t = padrao.sub(subst, t)
    t = " ".join(t.split())
    return t if len(t) <= limite else t[:limite] + "..."


def descrever_erro(e):
    """Só o tipo do erro + mensagem sanitizada (nunca traceback nem dados do cidadão)."""
    return f"{type(e).__name__}: {sanitizar(e)}"


class FiltroSanitizador(logging.Filter):
    """Rede de segurança: sanitiza qualquer mensagem antes de ir para o log."""
    def filter(self, record):
        record.msg = sanitizar(record.getMessage(), 400)
        record.args = ()
        record.exc_info = None  # não grava traceback (pode conter dados)
        return True


_handlers = [logging.handlers.RotatingFileHandler(
    "rpa.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8"), logging.StreamHandler()]
for _h in _handlers:
    _h.addFilter(FiltroSanitizador())
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s | %(levelname)s | %(message)s",
                    handlers=_handlers)
log = logging.getLogger("rpa")


# ---------- banco ----------
COLUNAS_MIGRACAO = {
    "ocorrencias": {"foto_path": "TEXT", "rua": "TEXT", "referencia": "TEXT", "origem": "TEXT",
                    "id_externo": "TEXT", "tentativas": "INTEGER DEFAULT 0", "token": "TEXT"},
    "auditoria": {"hash": "TEXT"},
}


def conectar():
    con = sqlite3.connect(DB, timeout=30)  # espera, em vez de falhar, se outro processo gravar
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript("""
    CREATE TABLE IF NOT EXISTS ocorrencias(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        categoria TEXT, descricao TEXT, rua TEXT, referencia TEXT,
        foto_hash TEXT, foto_path TEXT, criado_em TEXT,
        status TEXT DEFAULT 'nova',
        protocolo TEXT, prioridade INTEGER, nivel TEXT,
        duplicata_de INTEGER, reincidencias INTEGER DEFAULT 0,
        motivo TEXT, origem TEXT DEFAULT 'cidadao', id_externo TEXT,
        tentativas INTEGER DEFAULT 0, token TEXT
    );
    CREATE TABLE IF NOT EXISTS execucoes(
        id TEXT PRIMARY KEY, inicio TEXT, fim TEXT, duracao_s REAL,
        processados INTEGER, sucessos INTEGER, falhas INTEGER,
        encaminhadas INTEGER, duplicadas INTEGER, rejeitadas INTEGER,
        erros_json TEXT
    );
    CREATE TABLE IF NOT EXISTS alertas(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, execucao TEXT, ocorrencia_id INTEGER, protocolo TEXT,
        tipo TEXT, nivel TEXT, mensagem TEXT,
        UNIQUE(ocorrencia_id, tipo)
    );
    CREATE TABLE IF NOT EXISTS auditoria(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, execucao TEXT, ocorrencia_id INTEGER,
        evento TEXT, detalhe TEXT, hash TEXT
    );
    CREATE TABLE IF NOT EXISTS heartbeat(
        id INTEGER PRIMARY KEY, ts TEXT, resultado TEXT
    );""")
    for tabela, colunas in COLUNAS_MIGRACAO.items():  # migra bancos de versões antigas
        existentes = [c["name"] for c in con.execute(f"PRAGMA table_info({tabela})")]
        for nome, tipo in colunas.items():
            if nome not in existentes:
                con.execute(f"ALTER TABLE {tabela} ADD COLUMN {nome} {tipo}")
    return con


def _hash_auditoria(anterior, ts, execucao, oid, evento, detalhe):
    texto = "|".join([anterior, str(ts), str(execucao), str(oid), str(evento), str(detalhe)])
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def audit(con, execucao, oid, evento, detalhe=""):
    """Grava evidência de auditoria encadeada: cada linha guarda o hash da anterior,
    então qualquer alteração ou remoção posterior é detectada por --verificar."""
    ts = datetime.now().isoformat(timespec="seconds")
    det = sanitizar(detalhe, 300)
    ultimo = con.execute("SELECT hash FROM auditoria WHERE hash IS NOT NULL "
                         "ORDER BY id DESC LIMIT 1").fetchone()
    h = _hash_auditoria(ultimo["hash"] if ultimo else "", ts, execucao, oid, evento, det)
    con.execute("INSERT INTO auditoria(ts,execucao,ocorrencia_id,evento,detalhe,hash)"
                " VALUES(?,?,?,?,?,?)", (ts, execucao, oid, evento, det, h))


def _batimento(con, resultado):
    """Marca que o robô está vivo (aparece no painel), sem poluir o histórico."""
    con.execute("INSERT OR REPLACE INTO heartbeat(id,ts,resultado) VALUES(1,?,?)",
                (datetime.now().isoformat(timespec="seconds"), resultado))


# ---------- regras ----------
ABREVIACOES = {"r": "rua", "av": "avenida", "al": "alameda", "tv": "travessa",
               "pca": "praca", "pc": "praca", "estr": "estrada"}


def normalizar(texto):
    """minúsculas, sem acento/pontuação e com abreviações expandidas."""
    t = unicodedata.normalize("NFKD", texto or "")
    t = "".join(c for c in t if not unicodedata.combining(c)).lower()
    palavras = re.sub(r"[^a-z0-9]+", " ", t).split()
    return " ".join(ABREVIACOES.get(p, p) for p in palavras)


def similaridade(a, b):
    return difflib.SequenceMatcher(None, normalizar(a), normalizar(b)).ratio()


def validar(o):
    obrig = CAMPOS_OBRIGATORIOS if (o["origem"] or "cidadao") == "cidadao" else \
        [c for c in CAMPOS_OBRIGATORIOS if c != "foto_hash"]  # fontes externas não têm foto
    faltando = [c for c in obrig if o[c] in (None, "")]
    if faltando:
        return f"campos obrigatórios ausentes: {', '.join(faltando)}"
    if o["foto_path"] and not Path(o["foto_path"]).is_file():
        return "arquivo da foto não encontrado"
    if o["categoria"] not in PESOS:
        return f"categoria inválida: {o['categoria']}"
    if len(normalizar(o["rua"])) < 3:
        return "rua inválida ou muito curta"
    if len(normalizar(o["referencia"])) < 3:
        return "ponto de referência inválido ou muito curto"
    return None


def achar_duplicata(con, o):
    """Duplicata = mesma categoria, nos últimos 30 dias, e (mesma foto OU
    mesma rua + ponto de referência parecido)."""
    limite = (datetime.now() - timedelta(days=JANELA_DUPLICIDADE_DIAS)).isoformat()
    candidatas = con.execute(
        "SELECT * FROM ocorrencias WHERE id<>? AND categoria=? AND criado_em>=?"
        " AND protocolo IS NOT NULL AND status NOT IN ('rejeitada','duplicada','resolvida')",
        (o["id"], o["categoria"], limite)).fetchall()
    for c in candidatas:
        mesma_foto = bool(o["foto_hash"]) and c["foto_hash"] == o["foto_hash"]
        mesmo_local = (similaridade(o["rua"], c["rua"]) >= SIMILARIDADE_RUA and
                       similaridade(o["referencia"], c["referencia"]) >= SIMILARIDADE_REFERENCIA)
        if mesma_foto or mesmo_local:
            return c
    return None


def calcular_prioridade(categoria, reincidencias):
    score = PESOS[categoria] + min(reincidencias, 5)
    nivel = "alta" if score >= 7 else "media" if score >= 4 else "baixa"
    return score, nivel


def gerar_protocolo():
    return f"CL-{datetime.now():%Y}-{uuid.uuid4().hex[:8].upper()}"


def encaminhar(registros, execucao="manual"):
    """Entrega o lote para o próximo componente da CitizenTech.
    Gera (1) um JSON por execução, com versão do contrato, gravado de forma
    atômica, e (2) o CSV diário para leitura humana/planilha."""
    OUTBOX.mkdir(exist_ok=True)
    pacote = {
        "versao": CONTRATO_VERSAO,
        "execucao": execucao,
        "gerado_em": datetime.now().isoformat(timespec="seconds"),
        "total": len(registros),
        "ocorrencias": [{
            "protocolo": r["protocolo"],
            "categoria": r["categoria"],
            "prioridade": {"nivel": r["nivel"], "pontos": r["prioridade"]},
            "local": {"rua": r["rua"], "referencia": r["referencia"]},
            "descricao": r["descricao"],
            "foto": {"arquivo": Path(r["foto_path"]).name if r["foto_path"] else None,
                     "hash": r["foto_hash"]},
            "reincidencias": r["reincidencias"],
            "criado_em": r["criado_em"],
            "origem": r["origem"] or "cidadao",
        } for r in registros],
    }
    destino = OUTBOX / f"encaminhamentos_{datetime.now():%Y%m%d_%H%M%S}_{execucao}.json"
    tmp = destino.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(pacote, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, destino)  # o consumidor nunca vê arquivo pela metade

    arq = OUTBOX / f"encaminhamentos_{datetime.now():%Y%m%d}.csv"
    novo = not arq.exists()
    with open(arq, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if novo:
            w.writerow(["protocolo", "categoria", "nivel", "rua", "referencia", "origem"])
        for r in registros:
            w.writerow([r["protocolo"], r["categoria"], r["nivel"],
                        r["rua"], r["referencia"], r["origem"] or "cidadao"])


def com_retry(fn, *args):
    for t in range(1, MAX_TENTATIVAS + 1):
        try:
            return fn(*args)
        except Exception as e:  # noqa: BLE001
            log.warning("encaminhamento: tentativa %d/%d falhou (%s)", t, MAX_TENTATIVAS,
                        descrever_erro(e))
            if t == MAX_TENTATIVAS:
                raise
            time.sleep(2 ** (t - 1))


# ---------- robô ----------
FALHAS_ALERTA = []  # falhas ao gravar alertas na execução atual (contam como falha da execução)


def criar_alerta(con, execucao, oid, protocolo, tipo, nivel, mensagem):
    """Grava o alerta na tabela e no arquivo alertas/alertas.jsonl.
    Um alerta por (ocorrência, tipo): não repete a cada execução.
    A mensagem leva o local (o órgão precisa dele); o LOG leva só ids."""
    cur = con.execute("INSERT OR IGNORE INTO alertas(ts,execucao,ocorrencia_id,protocolo,"
                      "tipo,nivel,mensagem) VALUES(?,?,?,?,?,?,?)",
                      (datetime.now().isoformat(timespec="seconds"), execucao, oid,
                       protocolo, tipo, nivel, mensagem))
    if not cur.rowcount:
        return False
    try:
        ALERTAS.mkdir(exist_ok=True)
        with open(ALERTAS / "alertas.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": datetime.now().isoformat(timespec="seconds"),
                                "execucao": execucao, "ocorrencia_id": oid,
                                "protocolo": protocolo, "tipo": tipo, "nivel": nivel,
                                "mensagem": mensagem}, ensure_ascii=False) + "\n")
    except OSError as e:
        msg = descrever_erro(e)
        log.error("Alerta gravado no banco, mas não no arquivo (%s)", msg)
        FALHAS_ALERTA.append(msg)  # não é falha silenciosa: entra no resumo da execução
    log.info("Alerta %s: ocorrência %s, protocolo %s", tipo, oid, protocolo)
    return True


def msg_alerta_alta(o, protocolo):
    return (f"Barreira de prioridade ALTA ({o['categoria']}) em {o['rua']} - "
            f"{o['referencia']}. Protocolo {protocolo}.")


COLUNAS_IMPORTACAO = ["categoria", "rua", "referencia"]  # opcionais: descricao, id_externo


def importar_csv(caminho, origem):
    """Segunda fonte de informação: importa ocorrências de um CSV externo
    (planilha da prefeitura, de uma ONG...) para a mesma fila do cidadão,
    marcando a origem. Linhas com id_externo já importado são ignoradas."""
    texto = Path(caminho).read_text(encoding="utf-8-sig")
    try:
        dialeto = csv.Sniffer().sniff(texto[:2000], delimiters=",;\t")
    except csv.Error:
        dialeto = csv.excel
    leitor = csv.DictReader(io.StringIO(texto), dialect=dialeto)
    cabecalho = [(c or "").strip().lower() for c in (leitor.fieldnames or [])]
    faltando = [c for c in COLUNAS_IMPORTACAO if c not in cabecalho]
    if faltando:
        raise ValueError(f"colunas ausentes no CSV: {', '.join(faltando)}")
    con = conectar()
    res = dict(lidas=0, importadas=0, ignoradas=0)
    for linha in leitor:
        l = {(k or "").strip().lower(): (v or "").strip() for k, v in linha.items() if k}
        res["lidas"] += 1
        ext = l.get("id_externo") or None
        if ext and con.execute("SELECT 1 FROM ocorrencias WHERE origem=? AND id_externo=?",
                               (origem, ext)).fetchone():
            res["ignoradas"] += 1
            continue
        con.execute("INSERT INTO ocorrencias(categoria,descricao,rua,referencia,criado_em,"
                    "origem,id_externo) VALUES(?,?,?,?,?,?,?)",
                    (normalizar(l.get("categoria", "")), l.get("descricao", ""),
                     l.get("rua", ""), l.get("referencia", ""),
                     datetime.now().isoformat(), origem, ext))
        res["importadas"] += 1
    con.commit()
    con.close()
    log.info("Importação da origem %s: lidas=%d importadas=%d ignoradas=%d", origem,
             res["lidas"], res["importadas"], res["ignoradas"])
    return res


def importar_pasta():
    """Importa todo CSV que aparecer em entrada/ e move o arquivo para
    entrada/processados/ (ou entrada/erro/, gerando alerta). Origem = texto antes
    do 1º '_' do nome do arquivo (prefeitura_novembro.csv -> origem 'prefeitura')."""
    ENTRADA.mkdir(exist_ok=True)
    total = dict(arquivos=0, importadas=0, erros=0)
    for arq in sorted(ENTRADA.glob("*.csv")):
        origem = re.sub(r"[^a-z0-9]", "", arq.stem.split("_")[0].lower()) or "externa"
        destino = ENTRADA / "processados"
        try:
            res = importar_csv(arq, origem)
            total["arquivos"] += 1
            total["importadas"] += res["importadas"]
        except Exception as e:  # noqa: BLE001
            msg = descrever_erro(e)
            log.error("Falha ao importar arquivo da pasta de entrada (%s)", msg)
            destino = ENTRADA / "erro"
            total["erros"] += 1
            con = conectar()  # falha de importação nunca fica só no log: vira alerta
            criar_alerta(con, "importacao", None, None, "falha_importacao", "media",
                         f"Falha ao importar um arquivo da pasta entrada/ ({msg}). "
                         "O arquivo foi movido para entrada/erro/ para revisão.")
            con.commit()
            con.close()
        destino.mkdir(exist_ok=True)
        shutil.move(str(arq), str(destino / f"{datetime.now():%Y%m%d_%H%M%S}_{arq.name}"))
    return total


def obter_trava():
    """Garante UMA execução por vez (painel x agendador x cron/Agendador de Tarefas)."""
    for _ in range(2):
        try:
            fd = os.open(TRAVA, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, f"{os.getpid()} {datetime.now().isoformat(timespec='seconds')}".encode())
            os.close(fd)
            return True
        except FileExistsError:
            try:
                idade = time.time() - TRAVA.stat().st_mtime
            except FileNotFoundError:
                continue
            if idade > TRAVA_VELHA_S:  # processo anterior provavelmente caiu
                log.warning("Trava antiga removida")
                try:
                    TRAVA.unlink()
                except FileNotFoundError:
                    pass
                continue
            return False
    return False


def liberar_trava():
    try:
        TRAVA.unlink()
    except FileNotFoundError:
        pass


def ciclo():
    """Um ciclo completo: busca fontes externas e processa a fila (uma execução por vez)."""
    if not obter_trava():
        log.warning("Ciclo ignorado: outra execução está em andamento")
        return dict(pulada=True, motivo="outra execução em andamento")
    try:
        entrada = importar_pasta()
        resumo = executar()
        resumo["importadas_da_pasta"] = entrada["importadas"]
        return resumo
    finally:
        liberar_trava()


def agendar(minutos=INTERVALO_PADRAO_MIN):
    """Roda o ciclo sozinho a cada N minutos (padrão: 1) e faz a limpeza de
    retenção (LGPD) uma vez por dia."""
    log.info("Agendador ligado: ciclo a cada %s minuto(s). Ctrl+C para parar.", minutos)
    ultima_limpeza = 0.0
    try:
        while True:
            try:
                ciclo()
                if time.time() - ultima_limpeza > 86400 and obter_trava():
                    try:
                        limpar_dados()
                        ultima_limpeza = time.time()
                    finally:
                        liberar_trava()
            except Exception as e:  # um ciclo ruim não derruba o agendador
                log.error("Ciclo do agendador falhou (%s)", descrever_erro(e))
            time.sleep(minutos * 60)
    except KeyboardInterrupt:
        log.info("Agendador encerrado")


def executar():
    global FALHAS_ALERTA
    FALHAS_ALERTA = []
    execucao = uuid.uuid4().hex[:8]
    inicio = datetime.now()
    con = conectar()

    # reprocessa também as que falharam no encaminhamento antes
    novas = con.execute(
        "SELECT * FROM ocorrencias WHERE status IN ('nova','erro_encaminhamento')"
        " ORDER BY id").fetchall()
    if not novas:  # ciclo vazio: só marca que o robô está vivo (não polui log nem histórico)
        _batimento(con, "sem itens")
        con.commit()
        con.close()
        return dict(lidas=0, rejeitadas=0, duplicadas=0, encaminhadas=0, erros=0,
                    processados=0, sucessos=0, falhas=0, erros_detalhe=[],
                    execucao=None, vazia=True)

    log.info("Execução %s iniciada: %d item(ns) na fila", execucao, len(novas))
    resumo = dict(lidas=len(novas), rejeitadas=0, duplicadas=0, encaminhadas=0, erros=0)
    erros = []  # {"ocorrencia_id", "etapa", "mensagem"}: mensagem já sanitizada
    aprovadas = []

    for o in novas:
        try:
            if o["status"] == "erro_encaminhamento":
                aprovadas.append(o)
                continue
            motivo = validar(o)
            if motivo:
                con.execute("UPDATE ocorrencias SET status='rejeitada', motivo=? WHERE id=?",
                            (motivo, o["id"]))
                audit(con, execucao, o["id"], "REJEITADA", motivo)
                log.info("Ocorrência %s: rejeitada (%s)", o["id"], motivo)
                resumo["rejeitadas"] += 1
                con.commit()
                continue

            dup = achar_duplicata(con, o)
            if dup:
                con.execute("UPDATE ocorrencias SET status='duplicada', duplicata_de=? WHERE id=?",
                            (dup["id"], o["id"]))
                reinc = dup["reincidencias"] + 1
                score, nivel = calcular_prioridade(dup["categoria"], reinc)
                con.execute("UPDATE ocorrencias SET reincidencias=?, prioridade=?, nivel=?"
                            " WHERE id=?", (reinc, score, nivel, dup["id"]))
                audit(con, execucao, o["id"], "DUPLICADA",
                      f"original={dup['id']} protocolo={dup['protocolo']}")
                if nivel == "alta":  # reincidências elevaram a prioridade da original
                    criar_alerta(con, execucao, dup["id"], dup["protocolo"], "prioridade_alta",
                                 nivel, msg_alerta_alta(dup, dup["protocolo"]))
                log.info("Ocorrência %s: duplicada da %s", o["id"], dup["id"])
                resumo["duplicadas"] += 1
                con.commit()
                continue

            score, nivel = calcular_prioridade(o["categoria"], o["reincidencias"])
            protocolo = gerar_protocolo()
            con.execute("UPDATE ocorrencias SET prioridade=?, nivel=?, protocolo=? WHERE id=?",
                        (score, nivel, protocolo, o["id"]))
            audit(con, execucao, o["id"], "VALIDADA", f"prioridade={score} nivel={nivel}")
            log.info("Ocorrência %s: validada, protocolo %s, prioridade %s", o["id"], protocolo, nivel)
            con.commit()
            aprovadas.append(con.execute("SELECT * FROM ocorrencias WHERE id=?",
                                         (o["id"],)).fetchone())
        except Exception as e:  # falha isolada não derruba o lote
            con.rollback()
            msg = descrever_erro(e)
            tent = (o["tentativas"] or 0) + 1
            if tent >= LIMITE_TENTATIVAS_ITEM:  # quarentena: não trava a fila para sempre
                con.execute("UPDATE ocorrencias SET tentativas=?, status='erro_permanente',"
                            " motivo=? WHERE id=?", (tent, "falha repetida no processamento", o["id"]))
                criar_alerta(con, execucao, o["id"], o["protocolo"], "ocorrencia_em_quarentena",
                             "media", f"Ocorrência {o['id']} isolada após {tent} falhas de "
                             "processamento. É preciso revisão manual.")
            else:
                con.execute("UPDATE ocorrencias SET tentativas=? WHERE id=?", (tent, o["id"]))
            log.error("Ocorrência %s: falha no processamento, tentativa %d/%d (%s)",
                      o["id"], tent, LIMITE_TENTATIVAS_ITEM, msg)
            audit(con, execucao, o["id"], "ERRO_PROCESSAMENTO", f"tentativa {tent}: {msg}")
            con.commit()
            resumo["erros"] += 1
            erros.append({"ocorrencia_id": o["id"], "etapa": "processamento", "mensagem": msg})

    # relê do banco: duplicatas do mesmo lote podem ter elevado a prioridade
    aprovadas = [con.execute("SELECT * FROM ocorrencias WHERE id=?", (r["id"],)).fetchone()
                 for r in aprovadas]

    # ordena por prioridade (maior primeiro) e encaminha em lote
    aprovadas.sort(key=lambda r: (-(r["prioridade"] or 0), r["id"]))
    if aprovadas:
        try:
            com_retry(encaminhar, aprovadas, execucao)
            for r in aprovadas:
                con.execute("UPDATE ocorrencias SET status='encaminhada' WHERE id=?", (r["id"],))
                audit(con, execucao, r["id"], "ENCAMINHADA", r["protocolo"])
                log.info("Ocorrência %s: encaminhada, protocolo %s", r["id"], r["protocolo"])
                if r["nivel"] == "alta":
                    criar_alerta(con, execucao, r["id"], r["protocolo"], "prioridade_alta",
                                 r["nivel"], msg_alerta_alta(r, r["protocolo"]))
            resumo["encaminhadas"] = len(aprovadas)
        except Exception as e:  # noqa: BLE001
            msg = descrever_erro(e)
            for r in aprovadas:
                con.execute("UPDATE ocorrencias SET status='erro_encaminhamento' WHERE id=?",
                            (r["id"],))
                audit(con, execucao, r["id"], "ERRO_ENCAMINHAMENTO", msg)
            log.error("Encaminhamento falhou para %d ocorrência(s) (%s)", len(aprovadas), msg)
            resumo["erros"] += len(aprovadas)
            erros.append({"ocorrencia_id": None, "etapa": "encaminhamento",
                          "mensagem": msg, "itens_afetados": len(aprovadas)})
        con.commit()

    for msg in FALHAS_ALERTA:  # falha ao gravar alerta também é falha da execução
        erros.append({"ocorrencia_id": None, "etapa": "alerta", "mensagem": msg})
        resumo["erros"] += 1

    # ---- registro da execução ----
    fim = datetime.now()
    resumo.update(
        execucao=execucao,
        inicio=inicio.isoformat(timespec="seconds"),
        fim=fim.isoformat(timespec="seconds"),
        duracao_s=round((fim - inicio).total_seconds(), 2),
        processados=resumo["lidas"],
        falhas=resumo["erros"],                       # falhas técnicas
        sucessos=max(0, resumo["lidas"] - resumo["erros"]),
        erros_detalhe=erros,
    )
    if resumo["falhas"]:
        # no máx. 1 alerta de falha a cada 15 min, para uma pane não gerar 1 alerta por minuto
        limite = (datetime.now() - timedelta(minutes=15)).isoformat(timespec="seconds")
        if not con.execute("SELECT 1 FROM alertas WHERE tipo='falha_robo' AND ts>=?",
                           (limite,)).fetchone():
            criar_alerta(con, execucao, None, None, "falha_robo", "media",
                         f"Execução {execucao} terminou com {resumo['falhas']} falha(s). "
                         "Consulte a auditoria e o histórico de execuções.")
    con.execute("INSERT INTO execucoes VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (execucao, resumo["inicio"], resumo["fim"], resumo["duracao_s"],
                 resumo["processados"], resumo["sucessos"], resumo["falhas"],
                 resumo["encaminhadas"], resumo["duplicadas"], resumo["rejeitadas"],
                 json.dumps(erros, ensure_ascii=False)))
    audit(con, execucao, None, "RESUMO",
          {k: resumo[k] for k in ("processados", "sucessos", "falhas")})
    _batimento(con, "com falhas" if resumo["falhas"] else "ok")
    con.commit()
    LOGS.mkdir(exist_ok=True)
    with open(LOGS / "execucoes.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(resumo, ensure_ascii=False) + "\n")
    log.info("Execução %s finalizada: processados=%d sucessos=%d falhas=%d "
             "(encaminhadas=%d duplicadas=%d rejeitadas=%d)", execucao,
             resumo["processados"], resumo["sucessos"], resumo["falhas"],
             resumo["encaminhadas"], resumo["duplicadas"], resumo["rejeitadas"])
    con.close()
    return resumo


# ---------- LGPD: retenção, exclusão e reprocessamento ----------
def _remover_fotos_orfas(con, caminhos):
    """Apaga o arquivo da foto só se nenhuma ocorrência restante a usa."""
    removidas = 0
    for c in caminhos:
        if c and not con.execute("SELECT 1 FROM ocorrencias WHERE foto_path=?", (c,)).fetchone():
            p = Path(c)
            if p.is_file():
                p.unlink()
                removidas += 1
    return removidas


def limpar_dados(dias=RETENCAO_DIAS):
    """Retenção: apaga ocorrências, fotos, alertas e arquivos de saída com mais de N dias.
    A auditoria é mantida (só ids e eventos, sem dados do cidadão)."""
    limite = datetime.now() - timedelta(days=dias)
    lim_iso = limite.isoformat(timespec="seconds")
    con = conectar()
    velhas = con.execute("SELECT id, foto_path FROM ocorrencias WHERE criado_em < ?",
                         (limite.isoformat(),)).fetchall()
    fotos = {r["foto_path"] for r in velhas if r["foto_path"]}
    for r in velhas:
        con.execute("DELETE FROM ocorrencias WHERE id=?", (r["id"],))
    con.execute("DELETE FROM alertas WHERE ts < ?", (lim_iso,))
    n_fotos = _remover_fotos_orfas(con, fotos)
    if UPLOADS.exists():  # fotos soltas, sem ocorrência
        soltas = {str(f) for f in UPLOADS.iterdir()
                  if f.is_file() and datetime.fromtimestamp(f.stat().st_mtime) < limite}
        n_fotos += _remover_fotos_orfas(con, soltas)
    n_arq = 0
    for pasta in (OUTBOX, ENTRADA / "processados", ENTRADA / "erro"):
        if pasta.exists():
            for arq in pasta.iterdir():
                if arq.is_file() and datetime.fromtimestamp(arq.stat().st_mtime) < limite:
                    arq.unlink()
                    n_arq += 1
    arq_al = ALERTAS / "alertas.jsonl"
    if arq_al.exists():  # mantém só os alertas recentes
        manter = []
        for linha in arq_al.read_text(encoding="utf-8").splitlines():
            try:
                if json.loads(linha).get("ts", "") >= lim_iso:
                    manter.append(linha)
            except ValueError:
                continue
        tmp = arq_al.with_suffix(".tmp")
        tmp.write_text("".join(l + "\n" for l in manter), encoding="utf-8")
        os.replace(tmp, arq_al)
    res = dict(dias=dias, ocorrencias=len(velhas), fotos=n_fotos, arquivos=n_arq)
    audit(con, "retencao", None, "RETENCAO",
          f"dias={dias} ocorrencias={len(velhas)} fotos={n_fotos} arquivos={n_arq}")
    con.commit()
    con.close()
    log.info("Retenção (%d dias): ocorrências=%d fotos=%d arquivos=%d",
             dias, len(velhas), n_fotos, n_arq)
    return res


def apagar_ocorrencia(chave):
    """Exclusão a pedido do titular: chave = código de acompanhamento ou protocolo."""
    if not chave or len(chave) < 6:
        return False
    con = conectar()
    r = con.execute("SELECT id, foto_path FROM ocorrencias WHERE token=? OR protocolo=?",
                    (chave, chave)).fetchone()
    if not r:
        con.close()
        return False
    con.execute("DELETE FROM alertas WHERE ocorrencia_id=?", (r["id"],))
    con.execute("DELETE FROM ocorrencias WHERE id=?", (r["id"],))
    _remover_fotos_orfas(con, {r["foto_path"]} if r["foto_path"] else set())
    audit(con, "manual", r["id"], "APAGADA", "exclusão a pedido do titular")
    con.commit()
    con.close()
    log.info("Ocorrência %s apagada a pedido do titular", r["id"])
    return True


def reprocessar(oid):
    """Tira uma ocorrência da quarentena e devolve para a fila."""
    con = conectar()
    cur = con.execute("UPDATE ocorrencias SET status='nova', tentativas=0, motivo=NULL "
                      "WHERE id=? AND status='erro_permanente'", (oid,))
    if cur.rowcount:
        audit(con, "manual", oid, "REPROCESSAR", "devolvida para a fila")
    con.commit()
    con.close()
    return bool(cur.rowcount)


# ---------- verificação de integridade ----------
def verificar_auditoria(con):
    """Recalcula a cadeia de hashes. Devolve (íntegra, nº de registros | id divergente)."""
    anterior, n = "", 0
    for r in con.execute("SELECT * FROM auditoria ORDER BY id"):
        if r["hash"] is None:  # registros de versões antigas, sem hash
            continue
        esperado = _hash_auditoria(anterior, r["ts"], r["execucao"], r["ocorrencia_id"],
                                   r["evento"], r["detalhe"] or "")
        if esperado != r["hash"]:
            return False, r["id"]
        anterior, n = r["hash"], n + 1
    return True, n


def _protocolos_encaminhados(con):
    return {r["protocolo"] for r in con.execute(
        "SELECT protocolo FROM ocorrencias WHERE status='encaminhada'")}


def verificar_local():
    """Confere: (1) auditoria não adulterada; (2) tudo que está 'encaminhada' no banco
    consta nos arquivos JSON entregues em outbox/."""
    con = conectar()
    integra, info = verificar_auditoria(con)
    no_banco = _protocolos_encaminhados(con)
    con.close()
    nos_arquivos = set()
    for arq in OUTBOX.glob("encaminhamentos_*.json"):
        try:
            for o in json.loads(arq.read_text(encoding="utf-8"))["ocorrencias"]:
                nos_arquivos.add(o["protocolo"])
        except (ValueError, KeyError, OSError):
            continue
    sem_arquivo = sorted(no_banco - nos_arquivos)
    return {"auditoria_integra": integra,
            "auditoria_registros" if integra else "auditoria_primeira_divergencia_id": info,
            "encaminhadas_no_banco": len(no_banco),
            "encaminhadas_nos_arquivos": len(no_banco & nos_arquivos),
            "sem_arquivo_de_saida": sem_arquivo,
            "consistente": integra and not sem_arquivo}


def verificar(url=None, chave=None):
    """Verificação ponta a ponta: auditoria + arquivos de saída + (opcional) o que a API
    do MVP está entregando, comparando os protocolos."""
    r = verificar_local()
    if url:
        req_h = {"X-API-Key": chave or ""}
        na_api, desde = set(), 0
        while True:
            req = urllib.request.Request(
                f"{url.rstrip('/')}/api/v1/encaminhamentos?desde_id={desde}&limite=500",
                headers=req_h)
            with urllib.request.urlopen(req, timeout=10) as resp:
                pacote = json.load(resp)
            if not pacote["itens"]:
                break
            na_api |= {i["protocolo"] for i in pacote["itens"]}
            desde = pacote["proximo_id"]
        con = conectar()
        no_banco = _protocolos_encaminhados(con)
        con.close()
        r["encaminhadas_na_api"] = len(na_api)
        r["divergencia_banco_x_api"] = sorted(no_banco ^ na_api)
        r["consistente"] = r["consistente"] and not r["divergencia_banco_x_api"]
    log.info("Verificação de integridade: consistente=%s", r["consistente"])
    return r


def semear():
    con = conectar()
    agora = datetime.now().isoformat()
    dados = [
        ("buraco", "Buraco grande", "Rua Manoel Coelho", "Em frente à padaria Pão Doce", "h1"),
        ("buraco", "Mesmo buraco, outra foto", "R. Manoel Coelho", "em frente a padaria Pao Doce", "h2"),  # duplicata
        ("poste", "Poste no meio da calçada", "Avenida Goiás", "Perto do ponto de ônibus", "h3"),
        ("lixeira", "Lixeira bloqueando", "Rua Maranhão", "Ao lado da escola", ""),  # sem foto
        ("obra", "Obra sem passagem", "Rua Santo Antônio", "Esquina com a farmácia", "h5"),
        ("xyz", "Categoria inexistente", "Rua Baraldi", "Praça central", "h6"),     # inválida
    ]
    for cat, desc, rua, ref, h in dados:
        con.execute("INSERT INTO ocorrencias(categoria,descricao,rua,referencia,"
                    "foto_hash,criado_em) VALUES(?,?,?,?,?,?)",
                    (cat, desc, rua, ref, h, agora))
    con.commit()
    con.close()
    log.info("Dados de demonstração inseridos")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="RPA Caminho Livre")
    ap.add_argument("--seed", action="store_true", help="cria dados de demonstração")
    ap.add_argument("--importar", metavar="ARQUIVO.csv", help="importa um CSV de outra fonte")
    ap.add_argument("--origem", default="externa", help="origem do CSV (com --importar)")
    ap.add_argument("--agendar", type=float, nargs="?", const=INTERVALO_PADRAO_MIN, metavar="MIN",
                    help="roda o ciclo completo sozinho a cada MIN minutos (padrão: 1)")
    ap.add_argument("--limpar", type=int, nargs="?", const=RETENCAO_DIAS, metavar="DIAS",
                    help=f"retenção LGPD: apaga dados com mais de DIAS dias (padrão {RETENCAO_DIAS})")
    ap.add_argument("--apagar", metavar="CODIGO", help="apaga uma ocorrência (código ou protocolo)")
    ap.add_argument("--reprocessar", type=int, metavar="ID", help="tira uma ocorrência da quarentena")
    ap.add_argument("--verificar", action="store_true", help="confere auditoria, saídas e API")
    ap.add_argument("--url", help="com --verificar: URL do servidor para comparar com a API")
    ap.add_argument("--chave", default=os.environ.get("CAMINHO_LIVRE_CHAVE", ""),
                    help="com --verificar --url: chave da API")
    args = ap.parse_args()
    if args.seed:
        semear()
    elif args.importar:
        print(importar_csv(args.importar, args.origem))
    elif args.limpar is not None:
        print(limpar_dados(args.limpar))
    elif args.apagar:
        print("apagada" if apagar_ocorrencia(args.apagar) else "não encontrada")
    elif args.reprocessar:
        print("devolvida para a fila" if reprocessar(args.reprocessar) else "não está em quarentena")
    elif args.verificar:
        resultado = verificar(args.url, args.chave)
        print(json.dumps(resultado, ensure_ascii=False, indent=2))
        sys.exit(0 if resultado["consistente"] else 1)
    elif args.agendar:
        agendar(args.agendar)
    else:
        ciclo()
