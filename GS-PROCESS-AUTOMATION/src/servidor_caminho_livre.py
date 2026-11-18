#!/usr/bin/env python3
"""
Caminho Livre - servidor (cidadão + painel dos órgãos públicos + API v1).

Só usa a biblioteca padrão. Rode na MESMA pasta do rpa_caminho_livre.py:
    python servidor_caminho_livre.py
Ao ligar, o servidor já inicia o ROBÔ AGENDADO (um ciclo a cada 1 minuto).

Acesso (público, sem login):
  GET  /                         formulário do cidadão (foto, categoria, rua, referência)
  POST /api/ocorrencias          envia o relato (corpo = bytes da imagem); exige aceite=sim
  GET  /api/acompanhar/<codigo>  andamento do relato (código recebido no envio)
  POST /api/apagar?token=<cod>   apaga o próprio relato (direito do titular, LGPD)

Acesso restrito (chave de API em chave_api.txt; header X-API-Key, Bearer ou cookie do painel):
  GET  /painel                   painel dos órgãos públicos (pede a chave)
  POST /api/robo                 roda um ciclo agora (respeita a trava de execução única)
  GET  /api/v1/encaminhamentos?desde_id=N&status=encaminhada&limite=100   consumo incremental
  GET  /api/v1/ocorrencias/<protocolo>
  GET  /api/v1/resumo            totais por status, última execução e batimento do robô
  GET  /api/v1/execucoes?limite=20   histórico (data/hora, processados, sucessos, falhas, erros)
  GET  /api/v1/alertas?desde_id=N
  GET  /api/v1/auditoria?desde_id=N  trilha de auditoria encadeada
  GET  /api/v1/integridade       confere auditoria e arquivos de saída
  GET  /uploads/<arquivo>        foto (sem metadados)

Segurança: escuta só em 127.0.0.1 por padrão (--host 0.0.0.0 para abrir à rede, de
preferência com --cert/--key para HTTPS); metadados das fotos (EXIF/GPS) são removidos;
limite de requisições por IP; cabeçalhos de segurança; logs sem dados do cidadão.
"""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import ssl
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

import rpa_caminho_livre as rpa

UPLOADS = rpa.UPLOADS
MAX_BYTES = 8 * 1024 * 1024  # 8 MB
CHAVE_ARQUIVO = Path("chave_api.txt")
LIMITE_ENVIOS_POR_MIN = 20
LIMITE_CONSULTAS_POR_MIN = 60
LIMITE_LOGIN_POR_MIN = 10
CHAVE_API = ""   # definida em main()
HTTPS = False

CSP = ("default-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; "
       "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'")

STATUS_VALIDOS = {"nova", "encaminhada", "duplicada", "rejeitada",
                  "erro_encaminhamento", "erro_permanente"}
STATUS_CIDADAO = {
    "nova": "Recebido. Aguardando análise do robô (isso leva cerca de 1 minuto).",
    "encaminhada": "Encaminhado aos responsáveis.",
    "duplicada": "Este problema já tinha sido relatado. O seu relato reforçou a prioridade.",
    "rejeitada": "Não foi possível aceitar o relato (dados incompletos ou inválidos).",
    "erro_encaminhamento": "Em análise. O envio aos responsáveis será tentado novamente.",
    "erro_permanente": "Em análise manual pela equipe.",
}


# ---------- fotos: detecção e remoção de metadados (EXIF/GPS) ----------
def detectar_extensao(dados: bytes):
    """Confere o conteúdo real do arquivo (não confia só no que o navegador diz)."""
    if dados[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if dados[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if dados[:4] == b"RIFF" and dados[8:12] == b"WEBP":
        return ".webp"
    return None


def _limpar_jpeg(d: bytes) -> bytes:
    """Remove APP1 (EXIF/XMP, onde fica o GPS), APP13 (IPTC) e comentários."""
    saida, i = bytearray(b"\xff\xd8"), 2
    while i < len(d):
        if d[i] != 0xFF:
            raise ValueError("jpeg inválido")
        while i < len(d) and d[i] == 0xFF:
            i += 1
        if i >= len(d):
            break
        m = d[i]
        i += 1
        if m == 0xDA:  # início dos dados da imagem: copia o resto
            saida += b"\xff\xda" + d[i:]
            return bytes(saida)
        if m == 0xD9:
            saida += b"\xff\xd9"
            return bytes(saida)
        if m in (0x01,) or 0xD0 <= m <= 0xD8:
            saida += bytes([0xFF, m])
            continue
        if i + 2 > len(d):
            raise ValueError("jpeg truncado")
        tam = int.from_bytes(d[i:i + 2], "big")
        if tam < 2 or i + tam > len(d):
            raise ValueError("jpeg truncado")
        if m not in (0xE1, 0xED, 0xFE):
            saida += bytes([0xFF, m]) + d[i:i + tam]
        i += tam
    return bytes(saida)


def _limpar_png(d: bytes) -> bytes:
    """Remove eXIf, textos (tEXt/iTXt/zTXt) e data/hora (tIME)."""
    saida, i = bytearray(d[:8]), 8
    while i + 8 <= len(d):
        tam = int.from_bytes(d[i:i + 4], "big")
        tipo, fim = d[i + 4:i + 8], i + 12 + int.from_bytes(d[i:i + 4], "big")
        if fim > len(d):
            raise ValueError("png truncado")
        if tipo not in (b"eXIf", b"tEXt", b"iTXt", b"zTXt", b"tIME"):
            saida += d[i:fim]
        i = fim
        if tipo == b"IEND":
            break
    return bytes(saida)


def _limpar_webp(d: bytes) -> bytes:
    """Remove os blocos EXIF e XMP e zera suas bandeiras no VP8X."""
    corpo, i = bytearray(), 12
    while i + 8 <= len(d):
        tipo, tam = d[i:i + 4], int.from_bytes(d[i + 4:i + 8], "little")
        fim = i + 8 + tam + (tam & 1)
        if tipo not in (b"EXIF", b"XMP "):
            bloco = bytearray(d[i:min(fim, len(d))])
            if tipo == b"VP8X" and len(bloco) > 8:
                bloco[8] &= ~(0x08 | 0x04)
            corpo += bloco
        i = fim
    return b"RIFF" + (4 + len(corpo)).to_bytes(4, "little") + b"WEBP" + bytes(corpo)


def limpar_metadados(dados: bytes, ext: str) -> bytes:
    """Devolve a imagem sem metadados. Levanta ValueError se estiver corrompida."""
    if ext == ".jpg":
        return _limpar_jpeg(dados)
    if ext == ".png":
        return _limpar_png(dados)
    return _limpar_webp(dados)


# ---------- segurança: chave de API e limite de requisições ----------
def carregar_chave():
    """Chave vem de CAMINHO_LIVRE_CHAVE, do arquivo chave_api.txt, ou é criada na 1ª vez."""
    env = os.environ.get("CAMINHO_LIVRE_CHAVE")
    if env:
        return env, False
    if CHAVE_ARQUIVO.exists():
        return CHAVE_ARQUIVO.read_text(encoding="utf-8").strip(), False
    chave = secrets.token_urlsafe(24)
    CHAVE_ARQUIVO.write_text(chave + "\n", encoding="utf-8")
    try:
        os.chmod(CHAVE_ARQUIVO, 0o600)
    except OSError:
        pass
    return chave, True


_acessos = defaultdict(deque)
_trava_limite = threading.Lock()


def limitar(ip, grupo, maximo):
    """Janela de 60 s por IP. O IP fica só em memória (nunca vai para log ou banco)."""
    agora = time.time()
    with _trava_limite:
        fila = _acessos[(ip, grupo)]
        while fila and agora - fila[0] > 60:
            fila.popleft()
        if len(fila) >= maximo:
            return False
        fila.append(agora)
        return True


# ---------- páginas ----------
ESTILO = """
 body{font-family:system-ui,sans-serif;max-width:760px;margin:24px auto;padding:0 16px;color:#1b1b1b}
 h1{margin-bottom:0} .sub{color:#555;margin-top:4px}
 form,.card{border:1px solid #ccc;border-radius:10px;padding:16px;margin:16px 0}
 label{display:block;margin:10px 0 4px;font-weight:600}
 input,select,textarea,button{font:inherit;padding:8px;width:100%;box-sizing:border-box}
 input[type=checkbox]{width:auto;margin-right:8px}
 button{cursor:pointer;background:#0a6;color:#fff;border:0;border-radius:8px;margin-top:12px}
 button.sec{background:#345} button.perigo{background:#b00}
 .aviso{background:#f6f3e6;border:1px solid #d8cfa3;border-radius:10px;padding:12px;font-size:14px}
 #prev{max-width:100%;max-height:220px;margin-top:8px;display:none;border-radius:8px}
 #msg,#res{margin-top:10px;font-weight:600} .ok{color:#080}.err{color:#b00}
 a{color:#06c}
"""

PAGINA = """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Caminho Livre</title><style>""" + ESTILO + """</style></head><body>
<h1>Caminho Livre</h1>
<p class="sub">Nenhum obstáculo deve impedir alguém de chegar ao seu destino.
 <a href="/painel">Painel dos órgãos públicos</a></p>

<div class="aviso">
 <b>Aviso de privacidade.</b> Usamos a foto, a rua e o ponto de referência apenas para localizar o
 obstáculo e encaminhá-lo ao poder público. Não pedimos nome, telefone nem e-mail.
 <b>Não fotografe pessoas identificáveis nem placas de veículos e não escreva dados pessoais na
 descrição.</b> Removemos da foto os metadados, como a localização por GPS. Os dados são apagados
 automaticamente após __RETENCAO__ dias, e você pode apagar o seu relato quando quiser com o
 código de acompanhamento.
</div>

<form id="f">
 <h2>Registrar obstáculo</h2>
 <label for="foto">Foto do obstáculo *</label>
 <input id="foto" type="file" accept="image/*" capture="environment" required>
 <img id="prev" alt="pré-visualização">
 <label for="cat">Categoria *</label>
 <select id="cat">
  <option value="buraco">Buraco</option><option value="desnivel">Desnível</option>
  <option value="obra">Obra</option><option value="veiculo">Veículo estacionado</option>
  <option value="poste">Poste</option><option value="lixeira">Lixeira</option>
  <option value="outro">Outro</option>
 </select>
 <label for="rua">Rua onde a foto foi tirada *</label>
 <input id="rua" placeholder="Ex.: Rua Manoel Coelho" maxlength="120" required>
 <label for="ref">Ponto de referência *</label>
 <input id="ref" placeholder="Ex.: Em frente à padaria, perto do ponto de ônibus" maxlength="160" required>
 <label for="desc">Descrição (opcional, sem dados pessoais)</label>
 <textarea id="desc" rows="2" maxlength="500"></textarea>
 <label><input id="aceite" type="checkbox" required> Li o aviso de privacidade e concordo.</label>
 <button type="submit">Enviar ocorrência</button>
 <div id="msg"></div>
</form>

<div class="card">
 <h2>Acompanhar meu relato</h2>
 <label for="cod">Código de acompanhamento</label>
 <input id="cod" placeholder="Código recebido ao enviar" maxlength="20">
 <button type="button" class="sec" id="consultar">Consultar andamento</button>
 <button type="button" class="perigo" id="apagar">Apagar meu relato</button>
 <div id="res"></div>
</div>

<script>
const $ = id => document.getElementById(id);
function dizer(el, texto, cls) { el.textContent = texto; el.className = cls || ""; }
$("foto").onchange = e => {
  const f = e.target.files[0];
  if (f) { $("prev").src = URL.createObjectURL(f); $("prev").style.display = "block"; }
};
$("f").onsubmit = async e => {
  e.preventDefault();
  const arq = $("foto").files[0];
  if (!arq) { dizer($("msg"), "Selecione uma foto.", "err"); return; }
  const q = new URLSearchParams({categoria: $("cat").value, rua: $("rua").value.trim(),
    referencia: $("ref").value.trim(), descricao: $("desc").value, aceite: "sim"});
  dizer($("msg"), "Enviando...");
  try {
    const r = await fetch("/api/ocorrencias?" + q, {method: "POST", body: arq});
    const j = await r.json();
    if (!r.ok) throw new Error(j.erro || "falha no envio");
    dizer($("msg"), "Relato recebido! Seu código de acompanhamento: " + j.token +
          " (guarde-o: ele permite consultar e apagar o relato).", "ok");
    $("cod").value = j.token;
    $("f").reset(); $("prev").style.display = "none";
  } catch (err) { dizer($("msg"), "Erro: " + err.message, "err"); }
};
$("consultar").onclick = async () => {
  const c = $("cod").value.trim();
  if (!c) { dizer($("res"), "Informe o código.", "err"); return; }
  const r = await fetch("/api/acompanhar/" + encodeURIComponent(c));
  const j = await r.json();
  if (!r.ok) { dizer($("res"), j.erro || "Não encontrado.", "err"); return; }
  dizer($("res"), j.mensagem + (j.protocolo ? " Protocolo: " + j.protocolo + "." : ""), "ok");
};
$("apagar").onclick = async () => {
  const c = $("cod").value.trim();
  if (!c || !confirm("Apagar o relato e a foto definitivamente?")) return;
  const r = await fetch("/api/apagar?token=" + encodeURIComponent(c), {method: "POST", body: ""});
  const j = await r.json();
  dizer($("res"), r.ok ? "Relato apagado." : (j.erro || "Não foi possível apagar."), r.ok ? "ok" : "err");
};
</script></body></html>"""

LOGIN = """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Caminho Livre - Acesso restrito</title><style>""" + ESTILO + """</style></head><body>
<h1>Acesso restrito</h1>
<p class="sub">O painel é destinado aos órgãos públicos e organizações parceiras.</p>
<form method="post" action="/login">
 <label for="chave">Chave de acesso</label>
 <input id="chave" name="chave" type="password" autocomplete="current-password" required>
 <button type="submit">Entrar</button>
 <div class="err">__ERRO__</div>
</form>
<p class="sub">A chave fica no arquivo <code>chave_api.txt</code>, na pasta do servidor.</p>
</body></html>"""

PAINEL = """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Caminho Livre - Painel</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#1b1b1b}
 h1{margin-bottom:0} .sub{color:#555;margin-top:4px}
 .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:16px 0}
 .c{border:1px solid #ccc;border-radius:10px;padding:12px}
 .c b{display:block;font-size:26px} .c span{color:#555;font-size:13px}
 table{width:100%;border-collapse:collapse;font-size:14px;margin-bottom:24px}
 td,th{border-bottom:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}
 td img{width:48px;height:48px;object-fit:cover;border-radius:6px}
 .alta{color:#b00;font-weight:600}.media{color:#b60;font-weight:600}.baixa{color:#060}
 .falha{color:#b00;font-weight:600} small{color:#555} a{color:#06c}
 .barra{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin:8px 0}
 button{cursor:pointer;background:#345;color:#fff;border:0;border-radius:8px;padding:8px 14px;font:inherit}
 .bom{color:#060;font-weight:600}.ruim{color:#b00;font-weight:600}
</style></head><body>
<h1>Painel Caminho Livre</h1>
<p class="sub">MVP para órgãos públicos e organizações comunitárias. Lê tudo da API v1.
 <a href="/">Formulário do cidadão</a> · <a href="/sair">Sair</a></p>
<div class="barra">
 <span id="robo">Robô: ...</span><span id="integ">Auditoria: ...</span>
 <button id="rodar">Rodar agora</button><span id="rodarmsg"></span>
</div>
<div class="cards" id="cards"></div>

<h2>Alertas</h2>
<table><thead><tr><th>Data/hora</th><th>Tipo</th><th>Nível</th><th>Mensagem</th></tr></thead>
<tbody id="alertas"></tbody></table>

<h2>Pontos críticos (encaminhados, por prioridade)</h2>
<table><thead><tr><th>Foto</th><th>Protocolo</th><th>Categoria</th><th>Prioridade</th>
<th>Local</th><th>Reincid.</th><th>Origem</th></tr></thead><tbody id="criticos"></tbody></table>

<h2>Execuções do robô</h2>
<table><thead><tr><th>Data/hora</th><th>Processados</th><th>Sucessos</th><th>Falhas</th>
<th>Duração</th><th>Mensagens de erro</th></tr></thead><tbody id="exec"></tbody></table>

<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const rot = {encaminhada:"Encaminhadas", duplicada:"Duplicadas", rejeitada:"Rejeitadas",
             erro_encaminhamento:"Erro de envio", erro_permanente:"Em quarentena", nova:"Novas"};
const fetchJ = async u => { const r = await fetch(u); if (r.status === 401) { location.href = "/painel"; throw 0; } return r.json(); };
async function carregar() {
  const [res, enc, ex, al, ig] = await Promise.all([
    fetchJ("/api/v1/resumo"), fetchJ("/api/v1/encaminhamentos?limite=500"),
    fetchJ("/api/v1/execucoes?limite=15"), fetchJ("/api/v1/alertas?limite=500"),
    fetchJ("/api/v1/integridade")]);
  const hb = res.ultimo_ciclo;
  $("robo").innerHTML = hb ? "Robô ativo. Último ciclo: <b>" + esc(new Date(hb.ts).toLocaleString("pt-BR")) +
    "</b> (" + esc(hb.resultado) + ")" : "<span class='ruim'>Robô ainda não rodou</span>";
  $("integ").innerHTML = ig.consistente ? "<span class='bom'>Auditoria íntegra e saídas conferidas</span>" :
    "<span class='ruim'>Atenção: divergência na verificação de integridade</span>";
  $("cards").innerHTML = "<div class='c'><b>" + res.total + "</b><span>Total de ocorrências</span></div>" +
    Object.keys(rot).map(k => "<div class='c'><b>" + (res.por_status[k] || 0) + "</b><span>" + rot[k] + "</span></div>").join("");
  $("alertas").innerHTML = al.itens.slice(-15).reverse().map(a => "<tr><td>" +
    esc(new Date(a.ts).toLocaleString("pt-BR")) + "</td><td>" + esc(a.tipo) + "</td><td class='" +
    (a.nivel === "alta" ? "alta" : "media") + "'>" + esc(a.nivel) + "</td><td>" + esc(a.mensagem) +
    "</td></tr>").join("") || "<tr><td colspan='4'>Nenhum alerta.</td></tr>";
  const itens = enc.itens.sort((a, b) => (b.prioridade.pontos || 0) - (a.prioridade.pontos || 0) || a.id - b.id);
  $("criticos").innerHTML = itens.map(o => "<tr><td>" + (o.foto.url ? "<img src='" + esc(o.foto.url) + "'>" : "-") +
    "</td><td>" + esc(o.protocolo) + "</td><td>" + esc(o.categoria) + "</td><td class='" + esc(o.prioridade.nivel) + "'>" +
    esc(o.prioridade.nivel) + " (" + esc(o.prioridade.pontos) + ")</td><td>" + esc(o.local.rua) + "<br><small>" +
    esc(o.local.referencia) + "</small></td><td>" + esc(o.reincidencias) + "</td><td>" + esc(o.origem) + "</td></tr>").join("") ||
    "<tr><td colspan='7'>Nenhuma ocorrência encaminhada ainda.</td></tr>";
  $("exec").innerHTML = ex.itens.map(e => "<tr><td>" + esc(new Date(e.inicio).toLocaleString("pt-BR")) + "</td><td>" +
    e.processados + "</td><td>" + e.sucessos + "</td><td class='" + (e.falhas ? "falha" : "") + "'>" + e.falhas +
    "</td><td>" + e.duracao_s + " s</td><td>" +
    (e.erros.length ? e.erros.map(x => esc(x.etapa + ": " + x.mensagem)).join("<br>") : "-") + "</td></tr>").join("") ||
    "<tr><td colspan='6'>Nenhuma execução com itens ainda.</td></tr>";
}
$("rodar").onclick = async () => {
  $("rodarmsg").textContent = "Executando...";
  const r = await fetch("/api/robo", {method: "POST", body: ""});
  $("rodarmsg").textContent = r.status === 409 ? "Já há uma execução em andamento." : (r.ok ? "Concluído." : "Falhou.");
  carregar();
};
carregar().catch(() => {}); setInterval(() => carregar().catch(() => {}), 10000);
</script></body></html>"""


# ---------- contratos de saída ----------
def para_contrato(r):
    """Formato estável (v1.1) entregue a outros componentes."""
    return {
        "id": r["id"],
        "protocolo": r["protocolo"],
        "status": r["status"],
        "categoria": r["categoria"],
        "prioridade": {"nivel": r["nivel"], "pontos": r["prioridade"]},
        "local": {"rua": r["rua"], "referencia": r["referencia"]},
        "descricao": r["descricao"],
        "foto": {"url": "/uploads/" + Path(r["foto_path"]).name if r["foto_path"] else None,
                 "hash": r["foto_hash"]},
        "reincidencias": r["reincidencias"],
        "duplicata_de": r["duplicata_de"],
        "motivo_rejeicao": r["motivo"],
        "criado_em": r["criado_em"],
        "origem": r["origem"] or "cidadao",
    }


def execucao_para_json(r):
    return {"execucao": r["id"], "inicio": r["inicio"], "fim": r["fim"],
            "duracao_s": r["duracao_s"], "processados": r["processados"],
            "sucessos": r["sucessos"], "falhas": r["falhas"],
            "encaminhadas": r["encaminhadas"], "duplicadas": r["duplicadas"],
            "rejeitadas": r["rejeitadas"], "erros": json.loads(r["erros_json"] or "[]")}


class Handler(BaseHTTPRequestHandler):
    server_version = "CaminhoLivre"
    sys_version = ""  # não revela a versão do Python

    # ---------- infraestrutura ----------
    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        super().end_headers()

    def log_message(self, fmt, *args):
        # nunca registra a query string (rua, referência, código), o IP, o código de
        # acompanhamento (vai no caminho) nem o nome do arquivo da foto
        rota = urlparse(self.path).path
        if rota.startswith("/api/acompanhar/"):
            rota = "/api/acompanhar/[codigo]"
        elif rota.startswith("/uploads/"):
            rota = "/uploads/[arquivo]"
        rpa.log.info("HTTP %s %s -> %s", self.command, rota, args[1] if len(args) > 1 else "")

    def _json(self, codigo, obj):
        corpo = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def _html(self, codigo, texto, extras=()):
        corpo = texto.encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        for k, v in extras:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(corpo)

    def _redirecionar(self, destino, extras=()):
        self.send_response(303)
        self.send_header("Location", destino)
        self.send_header("Content-Length", "0")
        for k, v in extras:
            self.send_header(k, v)
        self.end_headers()

    def _ip(self):
        return self.client_address[0]

    def _autenticado(self):
        chave = self.headers.get("X-API-Key") or ""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            chave = auth[7:]
        if not chave:
            try:
                c = SimpleCookie(self.headers.get("Cookie", ""))
                chave = unquote(c["cl_chave"].value) if "cl_chave" in c else ""
            except CookieError:
                chave = ""
        return bool(chave) and hmac.compare_digest(chave.encode(), CHAVE_API.encode())

    def _exigir_chave(self):
        if self._autenticado():
            return True
        rpa.log.warning("Acesso negado a %s (sem chave válida)", urlparse(self.path).path)
        self._json(401, {"erro": "autenticação necessária (X-API-Key)"})
        return False

    def _cookie(self, valor, max_age):
        seguro = "; Secure" if HTTPS else ""
        return ("Set-Cookie",
                f"cl_chave={quote(valor)}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{seguro}")

    # ---------- GET ----------
    def do_GET(self):
        url = urlparse(self.path)
        rota, q = url.path, parse_qs(url.query)
        if rota == "/":
            return self._html(200, PAGINA.replace("__RETENCAO__", str(rpa.RETENCAO_DIAS)))
        if rota == "/painel":
            if self._autenticado():
                return self._html(200, PAINEL)
            return self._html(401, LOGIN.replace("__ERRO__", ""))
        if rota == "/sair":
            return self._redirecionar("/painel", [self._cookie("", 0)])
        if rota.startswith("/api/acompanhar/"):
            return self._acompanhar(Path(rota).name)
        if rota.startswith("/api/v1/"):
            if not self._exigir_chave():
                return
            return self._api_v1(rota, q)
        if rota.startswith("/uploads/"):
            if not self._exigir_chave():
                return
            return self._foto(rota)
        self._json(404, {"erro": "rota não encontrada"})

    def _acompanhar(self, token):
        if not limitar(self._ip(), "consulta", LIMITE_CONSULTAS_POR_MIN):
            return self._json(429, {"erro": "muitas consultas; tente em instantes"})
        con = rpa.conectar()
        r = con.execute("SELECT status, protocolo, categoria FROM ocorrencias WHERE token=?",
                        (token.upper(),)).fetchone()
        con.close()
        if not r:
            return self._json(404, {"erro": "código não encontrado"})
        self._json(200, {"status": r["status"], "mensagem": STATUS_CIDADAO.get(r["status"], ""),
                         "protocolo": r["protocolo"], "categoria": r["categoria"]})

    def _foto(self, rota):
        arq = UPLOADS / Path(rota).name  # .name impede ../ (path traversal)
        if not arq.is_file():
            return self._json(404, {"erro": "arquivo não encontrado"})
        dados = arq.read_bytes()
        tipo = {".jpg": "image/jpeg", ".png": "image/png", ".webp": "image/webp"}.get(
            arq.suffix, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(dados)))
        self.end_headers()
        self.wfile.write(dados)

    def _api_v1(self, rota, q):
        try:
            desde = int(q.get("desde_id", ["0"])[0])
            limite = max(1, min(int(q.get("limite", ["100"])[0]), 500))
        except ValueError:
            return self._json(400, {"erro": "desde_id e limite devem ser inteiros"})
        v = rpa.CONTRATO_VERSAO
        if rota == "/api/v1/integridade":
            return self._json(200, {"versao": v, **rpa.verificar_local()})
        con = rpa.conectar()
        try:
            if rota == "/api/v1/encaminhamentos":
                status = q.get("status", ["encaminhada"])[0]
                if status not in STATUS_VALIDOS:
                    return self._json(400, {"erro": "status inválido", "validos": sorted(STATUS_VALIDOS)})
                linhas = con.execute("SELECT * FROM ocorrencias WHERE status=? AND id>? "
                                     "ORDER BY id ASC LIMIT ?", (status, desde, limite)).fetchall()
                return self._json(200, {"versao": v, "total": len(linhas),
                                        "proximo_id": linhas[-1]["id"] if linhas else desde,
                                        "itens": [para_contrato(r) for r in linhas]})
            if rota == "/api/v1/alertas":
                linhas = con.execute("SELECT * FROM alertas WHERE id>? ORDER BY id ASC LIMIT ?",
                                     (desde, limite)).fetchall()
                return self._json(200, {"versao": v, "total": len(linhas),
                                        "proximo_id": linhas[-1]["id"] if linhas else desde,
                                        "itens": [{k: r[k] for k in ("id", "ts", "execucao",
                                                   "ocorrencia_id", "protocolo", "tipo", "nivel",
                                                   "mensagem")} for r in linhas]})
            if rota == "/api/v1/auditoria":
                linhas = con.execute("SELECT * FROM auditoria WHERE id>? ORDER BY id ASC LIMIT ?",
                                     (desde, limite)).fetchall()
                return self._json(200, {"versao": v, "total": len(linhas),
                                        "proximo_id": linhas[-1]["id"] if linhas else desde,
                                        "itens": [{k: r[k] for k in ("id", "ts", "execucao",
                                                   "ocorrencia_id", "evento", "detalhe", "hash")}
                                                  for r in linhas]})
            if rota == "/api/v1/resumo":
                por_status = {r["status"]: r["n"] for r in con.execute(
                    "SELECT status, COUNT(*) n FROM ocorrencias GROUP BY status")}
                ult = con.execute("SELECT * FROM execucoes ORDER BY inicio DESC LIMIT 1").fetchone()
                hb = con.execute("SELECT ts, resultado FROM heartbeat WHERE id=1").fetchone()
                return self._json(200, {
                    "versao": v, "total": sum(por_status.values()), "por_status": por_status,
                    "ultima_execucao": execucao_para_json(ult) if ult else None,
                    "ultimo_ciclo": {"ts": hb["ts"], "resultado": hb["resultado"]} if hb else None})
            if rota == "/api/v1/execucoes":
                linhas = con.execute("SELECT * FROM execucoes ORDER BY inicio DESC LIMIT ?",
                                     (limite,)).fetchall()
                return self._json(200, {"versao": v, "total": len(linhas),
                                        "itens": [execucao_para_json(r) for r in linhas]})
            if rota.startswith("/api/v1/ocorrencias/"):
                r = con.execute("SELECT * FROM ocorrencias WHERE protocolo=?",
                                (Path(rota).name,)).fetchone()
                if not r:
                    return self._json(404, {"erro": "protocolo não encontrado"})
                return self._json(200, {"versao": v, "ocorrencia": para_contrato(r)})
        finally:
            con.close()
        self._json(404, {"erro": "rota não encontrada"})

    # ---------- POST ----------
    def do_POST(self):
        url = urlparse(self.path)
        rota, q = url.path, parse_qs(url.query)
        if rota == "/api/ocorrencias":
            return self._receber_ocorrencia(q)
        if rota == "/api/apagar":
            if not limitar(self._ip(), "apagar", LIMITE_CONSULTAS_POR_MIN):
                return self._json(429, {"erro": "muitas tentativas; tente em instantes"})
            if rpa.apagar_ocorrencia((q.get("token", [""])[0]).strip().upper()):
                return self._json(200, {"apagada": True})
            return self._json(404, {"erro": "código não encontrado"})
        if rota == "/login":
            return self._login()
        if rota == "/api/robo":
            if not self._exigir_chave():
                return
            try:
                resumo = rpa.ciclo()
            except Exception as e:  # noqa: BLE001
                rpa.log.error("Falha ao executar o robô (%s)", rpa.descrever_erro(e))
                return self._json(500, {"erro": "falha ao executar o robô; veja o log"})
            return self._json(409 if resumo.get("pulada") else 200, resumo)
        self._json(404, {"erro": "rota não encontrada"})

    def _ler_corpo(self, maximo):
        try:
            tamanho = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None, 0
        if tamanho > maximo:
            return None, tamanho
        return self.rfile.read(tamanho) if tamanho > 0 else b"", tamanho

    def _login(self):
        if not limitar(self._ip(), "login", LIMITE_LOGIN_POR_MIN):
            return self._html(429, LOGIN.replace("__ERRO__", "Muitas tentativas. Aguarde um minuto."))
        corpo, _ = self._ler_corpo(2048)
        chave = parse_qs((corpo or b"").decode("utf-8", "ignore")).get("chave", [""])[0]
        if chave and hmac.compare_digest(chave.encode(), CHAVE_API.encode()):
            return self._redirecionar("/painel", [self._cookie(chave, 28800)])
        rpa.log.warning("Tentativa de login recusada")
        self._html(401, LOGIN.replace("__ERRO__", "Chave incorreta."))

    def _receber_ocorrencia(self, q):
        if not limitar(self._ip(), "envio", LIMITE_ENVIOS_POR_MIN):
            return self._json(429, {"erro": "muitos envios; tente novamente em instantes"})
        if (q.get("aceite", [""])[0]) != "sim":
            return self._json(400, {"erro": "é preciso aceitar o aviso de privacidade"})
        dados, tamanho = self._ler_corpo(MAX_BYTES)
        if tamanho <= 0:
            return self._json(400, {"erro": "a foto é obrigatória"})
        if dados is None:
            return self._json(413, {"erro": "foto maior que 8 MB"})

        ext = detectar_extensao(dados)
        if not ext:
            return self._json(400, {"erro": "arquivo não é uma imagem JPG, PNG ou WEBP"})
        try:
            dados = limpar_metadados(dados, ext)  # tira EXIF/GPS antes de guardar
        except ValueError:
            return self._json(400, {"erro": "imagem corrompida ou incompleta"})

        categoria = (q.get("categoria", [""])[0]).strip()
        if categoria not in rpa.PESOS:
            return self._json(400, {"erro": "categoria inválida"})
        rua = (q.get("rua", [""])[0]).strip()[:120]
        referencia = (q.get("referencia", [""])[0]).strip()[:160]
        if len(rpa.normalizar(rua)) < 3:
            return self._json(400, {"erro": "informe a rua onde a foto foi tirada"})
        if len(rpa.normalizar(referencia)) < 3:
            return self._json(400, {"erro": "informe um ponto de referência"})
        descricao = (q.get("descricao", [""])[0]).strip()[:500]

        UPLOADS.mkdir(exist_ok=True)
        foto_hash = hashlib.sha256(dados).hexdigest()  # hash da imagem já limpa
        caminho = UPLOADS / f"{foto_hash[:16]}{ext}"
        if not caminho.exists():
            caminho.write_bytes(dados)
        token = secrets.token_hex(5).upper()  # código de acompanhamento (segredo do titular)

        con = rpa.conectar()
        cur = con.execute(
            "INSERT INTO ocorrencias(categoria,descricao,rua,referencia,foto_hash,foto_path,"
            "criado_em,status,token) VALUES(?,?,?,?,?,?,?,'nova',?)",
            (categoria, descricao, rua, referencia, foto_hash, str(caminho),
             datetime.now().isoformat(), token))
        con.commit()
        oid = cur.lastrowid
        con.close()
        rpa.log.info("Ocorrência %s recebida", oid)
        self._json(201, {"id": oid, "status": "nova", "token": token,
                         "retencao_dias": rpa.RETENCAO_DIAS})


def main():
    global CHAVE_API, HTTPS
    ap = argparse.ArgumentParser(description="Servidor Caminho Livre")
    ap.add_argument("--host", default="127.0.0.1",
                    help="endereço de escuta (padrão 127.0.0.1; 0.0.0.0 abre à rede)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--intervalo", type=float, default=rpa.INTERVALO_PADRAO_MIN,
                    help="minutos entre ciclos do robô (padrão 1)")
    ap.add_argument("--sem-agendador", action="store_true", help="não inicia o robô agendado")
    ap.add_argument("--cert", help="certificado TLS (.pem) para HTTPS")
    ap.add_argument("--key", help="chave privada TLS (.pem) para HTTPS")
    args = ap.parse_args()

    CHAVE_API, nova = carregar_chave()
    rpa.conectar().close()  # garante banco e tabelas
    rpa.ENTRADA.mkdir(exist_ok=True)
    UPLOADS.mkdir(exist_ok=True)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    esquema = "http"
    if args.cert and args.key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        esquema, HTTPS = "https", True

    print(f"Caminho Livre em {esquema}://{args.host}:{args.port}   (Ctrl+C para parar)")
    print(f"Painel dos órgãos: {esquema}://{args.host}:{args.port}/painel")
    print("Chave de acesso do painel e da API:", "criada agora em" if nova else "no arquivo",
          str(CHAVE_ARQUIVO) if not os.environ.get("CAMINHO_LIVRE_CHAVE") else "(variável de ambiente)")
    if args.host not in ("127.0.0.1", "localhost"):
        print("ATENÇÃO: servidor acessível pela rede." +
              ("" if HTTPS else " Sem HTTPS, relatos e a chave trafegam sem criptografia."))
    if not args.sem_agendador:
        threading.Thread(target=rpa.agendar, args=(args.intervalo,), daemon=True).start()
        print(f"Robô agendado: um ciclo a cada {args.intervalo:g} minuto(s).")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")


if __name__ == "__main__":
    main()
