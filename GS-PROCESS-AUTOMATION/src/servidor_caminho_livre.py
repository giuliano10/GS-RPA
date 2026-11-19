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
# Identidade visual: escuro + magenta (mesma linguagem dos slides da CitizenTech).
# Só apresentação: ids, rotas, chamadas à API e regras continuam as mesmas.
LOGO = """<svg class="logo" viewBox="0 0 32 32" aria-hidden="true">
 <rect width="32" height="32" rx="9" fill="#E6195A"/>
 <path d="M8.5 26.5C8.5 20 19 22.5 21.5 15.5" fill="none" stroke="#fff" stroke-width="2.4"
  stroke-linecap="round" stroke-dasharray="0.01 4.2"/>
 <path d="M22 4.5a5.2 5.2 0 0 0-5.2 5.2c0 3.8 5.2 8.3 5.2 8.3s5.2-4.5 5.2-8.3A5.2 5.2 0 0 0 22 4.5z" fill="#fff"/>
 <circle cx="22" cy="9.7" r="2" fill="#E6195A"/></svg>"""

MARCA = ("""<a class="marca" href="/">""" + LOGO +
         """<span><b>Caminho Livre</b><small>CitizenTech</small></span></a>""")

FAVICON = ("""<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' """
           """viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='9' fill='%23E6195A'/%3E"""
           """%3Cpath d='M22 4.5a5.2 5.2 0 0 0-5.2 5.2c0 3.8 5.2 8.3 5.2 8.3s5.2-4.5 5.2-8.3A5.2 5.2 0 0 0 22 4.5z' """
           """fill='white'/%3E%3C/svg%3E">""")

BASE = """
 :root{--bg:#f4f5f7;--card:#fff;--ink:#14161b;--muted:#646b78;--line:#e4e6eb;--soft:#f8f9fb;
  --brand:#E6195A;--brand-2:#c2124a;--brand-bg:#fde8ef;--dark:#0e1014;--dark-2:#171a21;
  --ok:#0f8a4f;--ok-bg:#e6f6ee;--warn:#b45d06;--warn-bg:#fdf1e2;--bad:#c62828;--bad-bg:#fdecec;
  --r:16px;--sh:0 1px 2px rgba(16,24,40,.05),0 8px 24px rgba(16,24,40,.06)}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--ink);line-height:1.5;-webkit-font-smoothing:antialiased;
  font-family:Inter,"Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif}
 a{color:var(--brand);text-decoration:none} a:hover{text-decoration:underline}
 code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.9em;background:var(--soft);
  border:1px solid var(--line);border-radius:6px;padding:1px 6px}
 .wrap{max-width:1160px;margin:0 auto;padding:0 24px}
 .topo{background:var(--dark);color:#fff;border-bottom:1px solid #22262f}
 .topo .wrap{display:flex;align-items:center;justify-content:space-between;gap:16px;min-height:64px}
 .marca{display:flex;align-items:center;gap:10px;color:#fff} .marca:hover{text-decoration:none}
 .marca .logo{width:34px;height:34px;flex:none}
 .marca b{display:block;font-size:17px;letter-spacing:-.01em;line-height:1.1}
 .marca small{display:block;font-size:11px;color:#9aa1ad;letter-spacing:.08em;text-transform:uppercase}
 .nav{display:flex;gap:6px;flex-wrap:wrap}
 .nav a{color:#d5d9e0;font-size:14px;font-weight:500;padding:8px 14px;border-radius:999px;border:1px solid #2b303a}
 .nav a:hover{text-decoration:none;color:#fff;border-color:var(--brand);background:rgba(230,25,90,.12)}
 @media (max-width:560px){.wrap{padding:0 16px}.nav a{font-size:13px;padding:6px 10px}.marca small{display:none}.card{padding:20px}}
 .card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--sh);padding:24px}
 .card h2{font-size:19px;margin:0 0 4px;letter-spacing:-.01em} .card .desc{color:var(--muted);margin:0 0 16px;font-size:14px}
 label{display:block;margin:16px 0 6px;font-weight:600;font-size:14px}
 input,select,textarea{font:inherit;font-size:15px;width:100%;padding:12px 14px;border:1px solid #d4d8df;
  border-radius:12px;background:#fff;color:var(--ink);transition:border-color .15s,box-shadow .15s}
 input::placeholder,textarea::placeholder{color:#9aa1ad}
 input:focus,select:focus,textarea:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 4px rgba(230,25,90,.14)}
 select{appearance:none;-webkit-appearance:none;padding-right:40px;cursor:pointer;background:#fff url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%23646b78' stroke-width='1.8' fill='none' stroke-linecap='round'/%3E%3C/svg%3E") no-repeat right 16px center}
 textarea{resize:vertical;min-height:84px}
 button{font:inherit;font-weight:600;font-size:15px;cursor:pointer;border:0;border-radius:12px;padding:12px 18px;
  background:var(--brand);color:#fff;transition:background .15s,transform .05s,box-shadow .15s}
 button:hover{background:var(--brand-2)} button:active{transform:translateY(1px)}
 button:focus-visible,a:focus-visible{outline:3px solid rgba(230,25,90,.45);outline-offset:2px}
 button.sec{background:#fff;color:var(--ink);border:1px solid #d4d8df} button.sec:hover{background:var(--soft)}
 button.perigo{background:#fff;color:var(--bad);border:1px solid #f1c4c4} button.perigo:hover{background:var(--bad-bg)}
 .ok{color:var(--ok)} .err{color:var(--bad)}
 .rodape{color:var(--muted);font-size:13px;padding:32px 0 40px;text-align:center}
 .rodape b{color:var(--ink)}
"""

ESTILO = BASE + """
 .hero{background:linear-gradient(135deg,#0e1014 0%,#1a1220 60%,#2a0f1d 100%);color:#fff;position:relative;overflow:hidden}
 .hero:before{content:"";position:absolute;inset:0;opacity:.5;pointer-events:none;
  background:repeating-linear-gradient(115deg,transparent 0 140px,rgba(255,255,255,.035) 140px 141px)}
 .hero .wrap{position:relative;padding-top:56px;padding-bottom:120px}
 .eyebrow{display:inline-flex;align-items:center;gap:8px;font-size:12px;font-weight:600;letter-spacing:.1em;
  text-transform:uppercase;color:#ffb3c9;background:rgba(230,25,90,.14);border:1px solid rgba(230,25,90,.35);
  padding:6px 12px;border-radius:999px}
 .hero h1{font-size:clamp(28px,4.2vw,46px);line-height:1.1;letter-spacing:-.025em;margin:18px 0 14px;max-width:780px}
 .hero h1 em{font-style:normal;color:var(--brand)}
 .hero p.sub{color:#c3c8d1;font-size:17px;max-width:640px;margin:0}
 .passos{display:flex;flex-wrap:wrap;gap:12px;margin-top:28px;padding:0;list-style:none}
 .passos li{display:flex;align-items:center;gap:10px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);
  border-radius:12px;padding:10px 14px;font-size:14px;color:#e6e9ee}
 .passos li span{display:grid;place-items:center;width:24px;height:24px;border-radius:50%;background:var(--brand);
  color:#fff;font-weight:700;font-size:12px}
 .grade{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(0,1fr);gap:24px;margin-top:-84px;position:relative;
  grid-template-rows:auto 1fr;grid-template-areas:"form aviso" "form acomp";align-items:start}
 #f{grid-area:form} .aviso{grid-area:aviso} .acomp{grid-area:acomp}
 @media (max-width:880px){.grade{grid-template-columns:1fr;grid-template-areas:"aviso" "form" "acomp"}}
 .aviso{font-size:14px;color:#3b414c}
 .aviso h3{display:flex;align-items:center;gap:10px;font-size:16px;margin:0 0 10px;color:var(--ink)}
 .aviso h3 svg,.acomp h2 svg{width:22px;height:22px;flex:none}
 .aviso p{margin:0 0 10px} .aviso p:last-child{margin:0}
 .aviso .destaque{background:var(--brand-bg);border-radius:10px;padding:10px 12px;color:#7a0f33}
 .linha{display:grid;grid-template-columns:1fr 1fr;gap:0 16px} @media (max-width:560px){.linha{grid-template-columns:1fr}}
 .drop{position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;
  gap:6px;min-height:150px;border:2px dashed #d4d8df;border-radius:14px;background:var(--soft);padding:18px;
  transition:border-color .15s,background .15s;overflow:hidden}
 .drop:hover,.drop:focus-within{border-color:var(--brand);background:#fff7fa}
 .drop input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
 .drop .ic{display:grid;place-items:center;width:46px;height:46px;border-radius:12px;background:var(--brand-bg);color:var(--brand)}
 .drop .ic svg{width:24px;height:24px}
 .dica{display:flex;flex-direction:column;align-items:center;gap:6px} .dica br{display:none}
 .drop strong{font-size:15px} .drop small{color:var(--muted);font-size:13px}
 .drop:has(#prev[style*="block"]) .dica{display:none}
 .drop:has(#prev[style*="block"]){padding:8px;border-style:solid}
 #prev{max-width:100%;max-height:280px;display:none;border-radius:10px}
 .check{display:flex;align-items:flex-start;gap:10px;font-weight:500;background:var(--soft);border:1px solid var(--line);
  border-radius:12px;padding:12px 14px;margin-top:18px;cursor:pointer}
 .check input{width:18px;height:18px;margin:2px 0 0;accent-color:var(--brand);flex:none}
 #f button[type=submit]{width:100%;margin-top:18px;padding:14px 18px;font-size:16px;box-shadow:0 8px 20px rgba(230,25,90,.25)}
 .acoes{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}
 .acoes button{font-size:14px;padding:12px 10px;white-space:nowrap}
 @media (max-width:420px){.acoes{grid-template-columns:1fr}}
 .acomp h2{display:flex;align-items:center;gap:10px}
 #msg,#res{margin-top:14px;font-weight:600;font-size:14px;border-radius:12px;padding:12px 14px;background:var(--soft);
  border:1px solid var(--line);color:var(--ink)}
 #msg:empty,#res:empty{display:none}
 #msg.ok,#res.ok{background:var(--ok-bg);border-color:#bfe6cf;color:#0b6b3d}
 #msg.err,#res.err{background:var(--bad-bg);border-color:#f3c7c7;color:#a31f1f}
 .selos{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}
 .selos span{font-size:12px;font-weight:600;color:var(--muted);background:var(--soft);border:1px solid var(--line);
  border-radius:999px;padding:4px 10px}
"""

ICONE_ESCUDO = """<svg viewBox="0 0 24 24" fill="none" stroke="#E6195A" stroke-width="2" stroke-linecap="round"
 stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/>
 <path d="M9 12l2 2 4-4"/></svg>"""

ICONE_BUSCA = """<svg viewBox="0 0 24 24" fill="none" stroke="#E6195A" stroke-width="2" stroke-linecap="round"
 aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>"""

ICONE_CAMERA = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
 stroke-linejoin="round" aria-hidden="true"><path d="M4 8h3l2-3h6l2 3h3v11H4z"/><circle cx="12" cy="13" r="3.5"/></svg>"""

PAGINA = """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Caminho Livre · Registre um obstáculo</title>""" + FAVICON + """<style>""" + ESTILO + """</style></head><body>
<header class="topo"><div class="wrap">""" + MARCA + """
 <nav class="nav"><a href="/painel">Painel dos órgãos públicos</a></nav>
</div></header>

<section class="hero"><div class="wrap">
 <span class="eyebrow">Acessibilidade urbana · São Paulo</span>
 <h1>Nenhum obstáculo deve impedir alguém de <em>chegar ao seu destino.</em></h1>
 <p class="sub">Viu um buraco, um desnível ou algo bloqueando a calçada? Registre em menos de um minuto.
  Nosso robô valida, prioriza e encaminha o relato ao poder público automaticamente.</p>
 <ol class="passos">
  <li><span>1</span>Tire uma foto do obstáculo</li>
  <li><span>2</span>Informe a rua e uma referência</li>
  <li><span>3</span>Acompanhe pelo código</li>
 </ol>
</div></section>

<main class="wrap">
<div class="grade">
<form id="f" class="card">
 <h2>Registrar obstáculo</h2>
 <p class="desc">Campos com * são obrigatórios.</p>
 <label for="foto">Foto do obstáculo *</label>
 <div class="drop">
  <div class="dica">
   <div class="ic">""" + ICONE_CAMERA + """</div>
   <strong>Toque para tirar ou escolher uma foto</strong><br>
   <small>JPG, PNG ou WEBP, até 8 MB. Removemos a localização da imagem.</small>
  </div>
  <input id="foto" type="file" accept="image/*" capture="environment" required>
  <img id="prev" alt="pré-visualização">
 </div>
 <label for="cat">Categoria *</label>
 <select id="cat">
  <option value="buraco">Buraco</option><option value="desnivel">Desnível</option>
  <option value="obra">Obra</option><option value="veiculo">Veículo estacionado</option>
  <option value="poste">Poste</option><option value="lixeira">Lixeira</option>
  <option value="outro">Outro</option>
 </select>
 <div class="linha">
  <div><label for="rua">Rua onde a foto foi tirada *</label>
  <input id="rua" placeholder="Ex.: Rua Manoel Coelho" maxlength="120" required></div>
  <div><label for="ref">Ponto de referência *</label>
  <input id="ref" placeholder="Ex.: Em frente à padaria" maxlength="160" required></div>
 </div>
 <label for="desc">Descrição (opcional, sem dados pessoais)</label>
 <textarea id="desc" rows="2" maxlength="500" placeholder="Conte o que dificulta a passagem"></textarea>
 <label class="check"><input id="aceite" type="checkbox" required> Li o aviso de privacidade e concordo.</label>
 <button type="submit">Enviar ocorrência</button>
 <div id="msg"></div>
</form>

<aside class="card aviso">
 <h3>""" + ICONE_ESCUDO + """Aviso de privacidade</h3>
 <p>Usamos a foto, a rua e o ponto de referência apenas para localizar o obstáculo e encaminhá-lo ao
  poder público. Não pedimos nome, telefone nem e-mail.</p>
 <p class="destaque"><b>Não fotografe pessoas identificáveis nem placas de veículos e não escreva dados
  pessoais na descrição.</b></p>
 <p>Removemos da foto os metadados, como a localização por GPS. Os dados são apagados automaticamente
  após __RETENCAO__ dias, e você pode apagar o seu relato quando quiser com o código de acompanhamento.</p>
 <div class="selos"><span>Sem GPS</span><span>Sem dados pessoais</span><span>Apagado em __RETENCAO__ dias</span></div>
</aside>

<section class="card acomp">
 <h2>""" + ICONE_BUSCA + """Acompanhar meu relato</h2>
 <p class="desc">Use o código recebido ao enviar.</p>
 <label for="cod">Código de acompanhamento</label>
 <input id="cod" placeholder="Ex.: A1B2C3D4E5" maxlength="20">
 <div class="acoes">
  <button type="button" class="sec" id="consultar">Consultar andamento</button>
  <button type="button" class="perigo" id="apagar">Apagar meu relato</button>
 </div>
 <div id="res"></div>
</section>
</div>
</main>
<footer class="rodape"><b>Caminho Livre</b> · CitizenTech · FIAP Global Solution 2026.2</footer>

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
<title>Caminho Livre · Acesso restrito</title>""" + FAVICON + """<style>""" + BASE + """
 body{min-height:100vh;display:flex;flex-direction:column;
  background:linear-gradient(135deg,#0e1014 0%,#1a1220 60%,#2a0f1d 100%)}
 .centro{flex:1;display:grid;place-items:center;padding:32px 20px}
 .login{width:100%;max-width:420px;padding:32px}
 .login .marca{color:var(--ink);margin-bottom:24px} .login .marca small{color:var(--muted)}
 .login h1{font-size:24px;letter-spacing:-.02em;margin:0 0 6px}
 .login .desc{color:var(--muted);margin:0 0 8px;font-size:14px}
 .login button{width:100%;margin-top:18px;padding:14px}
 .login .err{margin-top:12px;font-weight:600;font-size:14px}
 .login .err:empty{display:none}
 .login .err:not(:empty){background:var(--bad-bg);border:1px solid #f3c7c7;border-radius:12px;padding:10px 12px}
 .login .nota{font-size:13px;color:var(--muted);margin:18px 0 0;border-top:1px solid var(--line);padding-top:16px}
 .voltar{color:#c3c8d1;font-size:14px;text-align:center;padding-bottom:28px} .voltar a{color:#fff}
</style></head><body>
<div class="centro">
<form method="post" action="/login" class="card login">
 """ + MARCA + """
 <h1>Acesso restrito</h1>
 <p class="desc">O painel é destinado aos órgãos públicos e organizações parceiras.</p>
 <label for="chave">Chave de acesso</label>
 <input id="chave" name="chave" type="password" autocomplete="current-password" required>
 <button type="submit">Entrar no painel</button>
 <div class="err">__ERRO__</div>
 <p class="nota">A chave fica no arquivo <code>chave_api.txt</code>, na pasta do servidor.</p>
</form>
</div>
<p class="voltar"><a href="/">← Voltar ao formulário do cidadão</a></p>
</body></html>"""

PAINEL = """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Caminho Livre · Painel</title>""" + FAVICON + """
<style>""" + BASE + """
 .cab{background:linear-gradient(135deg,#0e1014 0%,#1a1220 60%,#2a0f1d 100%);color:#fff;padding:32px 0 92px}
 .cab .wrap{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;flex-wrap:wrap}
 .cab h1{margin:0;font-size:clamp(24px,3vw,34px);letter-spacing:-.02em}
 .cab p{margin:6px 0 0;color:#c3c8d1;max-width:620px}
 .eyebrow{font-size:12px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:#ffb3c9}
 .barra{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
 .pill{display:inline-flex;align-items:center;gap:8px;font-size:13px;color:#e6e9ee;background:rgba(255,255,255,.07);
  border:1px solid rgba(255,255,255,.12);border-radius:999px;padding:8px 14px}
 .pill b{color:#fff}
 .ponto{width:8px;height:8px;border-radius:50%;background:#2fd17a;box-shadow:0 0 0 0 rgba(47,209,122,.6);
  animation:pulso 2s infinite;flex:none}
 @keyframes pulso{70%{box-shadow:0 0 0 8px rgba(47,209,122,0)}100%{box-shadow:0 0 0 0 rgba(47,209,122,0)}}
 .pill .bom{color:#7ee2a8;font-weight:600} .pill .ruim{color:#ff9b9b;font-weight:600}
 #rodar{padding:10px 18px;box-shadow:0 8px 20px rgba(230,25,90,.3)}
 #rodarmsg{font-size:13px;color:#c3c8d1}
 .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:14px;margin-top:-64px;position:relative}
 .c{background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--sh);padding:18px 18px 16px;
  position:relative;overflow:hidden}
 .c:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--cor,#c9ced6)}
 .c b{display:block;font-size:32px;line-height:1.1;letter-spacing:-.02em} .c span{color:var(--muted);font-size:13px;font-weight:500}
 .c.total{background:var(--brand);border-color:var(--brand);color:#fff} .c.total span{color:#ffd6e3} .c.total:before{display:none}
 .k-encaminhada{--cor:#0f8a4f} .k-duplicada{--cor:#6b5bd6} .k-rejeitada{--cor:#8a919c}
 .k-erro_encaminhamento{--cor:#b45d06} .k-erro_permanente{--cor:#c62828} .k-nova{--cor:#2a7de1}
 .secao{margin-top:24px;padding:0;overflow:hidden}
 .secao .tit{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:20px 24px 14px}
 .secao h2{font-size:18px;margin:0} .secao .tit small{color:var(--muted);font-size:13px}
 .tabela{overflow-x:auto}
 table{width:100%;min-width:760px;border-collapse:collapse;font-size:14px}
 .proto,td.num{white-space:nowrap}
 th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600;background:var(--soft);
  text-align:left;padding:10px 16px;border-top:1px solid var(--line);border-bottom:1px solid var(--line);white-space:nowrap}
 td{padding:12px 16px;border-bottom:1px solid var(--line);vertical-align:middle}
 tbody tr:last-child td{border-bottom:0} tbody tr:hover td{background:#fcfcfd}
 td img{width:56px;height:56px;object-fit:cover;border-radius:10px;display:block;border:1px solid var(--line)}
 .semfoto{display:grid;place-items:center;width:56px;height:56px;border-radius:10px;background:var(--soft);
  border:1px dashed #d4d8df;color:#9aa1ad;font-size:11px}
 .proto{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;font-weight:600}
 small{color:var(--muted)} .local b{font-weight:600}
 .tag{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;border-radius:999px;padding:4px 10px;
  white-space:nowrap;background:var(--soft);color:#3b414c;border:1px solid var(--line)}
 .tag:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
 .tag.alta{background:var(--bad-bg);color:var(--bad);border-color:#f3c7c7}
 .tag.media{background:var(--warn-bg);color:var(--warn);border-color:#f2d6b3}
 .tag.baixa{background:var(--ok-bg);color:var(--ok);border-color:#bfe6cf}
 .tag.neutra:before{display:none}
 .num{font-variant-numeric:tabular-nums}
 .falha{display:inline-grid;place-items:center;min-width:26px;height:24px;padding:0 8px;border-radius:999px;
  background:var(--bad-bg);color:var(--bad);font-weight:700}
 .erro{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;color:#a31f1f;background:var(--bad-bg);
  border-radius:8px;padding:4px 8px;display:inline-block;margin:2px 0}
 .vazio{text-align:center;color:var(--muted);padding:28px 16px}
</style></head><body>
<header class="topo"><div class="wrap">""" + MARCA + """
 <nav class="nav"><a href="/">Formulário do cidadão</a><a href="/sair">Sair</a></nav>
</div></header>

<section class="cab"><div class="wrap">
 <div>
  <span class="eyebrow">Painel dos órgãos públicos</span>
  <h1>Ocorrências de acessibilidade</h1>
  <p>MVP para órgãos públicos e organizações comunitárias. Atualiza sozinho a cada 10 segundos, lendo a API v1.</p>
 </div>
 <div class="barra">
  <span class="pill"><span class="ponto"></span><span id="robo">Robô: ...</span></span>
  <span class="pill"><span id="integ">Auditoria: ...</span></span>
  <button id="rodar">Rodar agora</button><span id="rodarmsg"></span>
 </div>
</div></section>

<main class="wrap">
<div class="cards" id="cards"></div>

<section class="card secao">
 <div class="tit"><h2>Pontos críticos</h2><small>Encaminhados, da maior para a menor prioridade</small></div>
 <div class="tabela"><table><thead><tr><th>Foto</th><th>Protocolo</th><th>Categoria</th><th>Prioridade</th>
 <th>Local</th><th>Reincid.</th><th>Origem</th></tr></thead><tbody id="criticos"></tbody></table></div>
</section>

<section class="card secao">
 <div class="tit"><h2>Alertas</h2><small>Os 15 mais recentes</small></div>
 <div class="tabela"><table><thead><tr><th>Data/hora</th><th>Tipo</th><th>Nível</th><th>Mensagem</th></tr></thead>
 <tbody id="alertas"></tbody></table></div>
</section>

<section class="card secao">
 <div class="tit"><h2>Execuções do robô</h2><small>Histórico com sucessos, falhas e erros</small></div>
 <div class="tabela"><table><thead><tr><th>Data/hora</th><th>Processados</th><th>Sucessos</th><th>Falhas</th>
 <th>Duração</th><th>Mensagens de erro</th></tr></thead><tbody id="exec"></tbody></table></div>
</section>
</main>
<footer class="rodape"><b>Caminho Livre</b> · CitizenTech · FIAP Global Solution 2026.2</footer>

<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const rot = {encaminhada:"Encaminhadas", duplicada:"Duplicadas", rejeitada:"Rejeitadas",
             erro_encaminhamento:"Erro de envio", erro_permanente:"Em quarentena", nova:"Novas"};
// rótulos só para exibição (o dado continua o mesmo)
const nomeCat = {buraco:"Buraco", desnivel:"Desnível", obra:"Obra", veiculo:"Veículo", poste:"Poste",
                 lixeira:"Lixeira", outro:"Outro"};
const nomeTipo = {prioridade_alta:"Prioridade alta", falha_importacao:"Falha de importação",
                  ocorrencia_em_quarentena:"Ocorrência em quarentena", falha_robo:"Falha do robô"};
const nomeNivel = {alta:"Alta", media:"Média", baixa:"Baixa"};
const cap = s => { s = String(s ?? ""); return s === "cidadao" ? "Cidadão" : s.charAt(0).toUpperCase() + s.slice(1); };
const fetchJ = async u => { const r = await fetch(u); if (r.status === 401) { location.href = "/painel"; throw 0; } return r.json(); };
async function carregar() {
  const [res, enc, ex, al, ig] = await Promise.all([
    fetchJ("/api/v1/resumo"), fetchJ("/api/v1/encaminhamentos?limite=500"),
    fetchJ("/api/v1/execucoes?limite=15"), fetchJ("/api/v1/alertas?limite=500"),
    fetchJ("/api/v1/integridade")]);
  const hb = res.ultimo_ciclo;
  $("robo").innerHTML = hb ? "Robô ativo · último ciclo <b>" + esc(new Date(hb.ts).toLocaleString("pt-BR")) +
    "</b> (" + esc(hb.resultado) + ")" : "<span class='ruim'>Robô ainda não rodou</span>";
  $("integ").innerHTML = ig.consistente ? "<span class='bom'>✓ Auditoria íntegra e saídas conferidas</span>" :
    "<span class='ruim'>Atenção: divergência na verificação de integridade</span>";
  $("cards").innerHTML = "<div class='c total'><b>" + res.total + "</b><span>Total de ocorrências</span></div>" +
    Object.keys(rot).map(k => "<div class='c k-" + k + "'><b>" + (res.por_status[k] || 0) + "</b><span>" + rot[k] + "</span></div>").join("");
  $("alertas").innerHTML = al.itens.slice(-15).reverse().map(a => "<tr><td class='num'>" +
    esc(new Date(a.ts).toLocaleString("pt-BR")) + "</td><td><b>" + esc(nomeTipo[a.tipo] || a.tipo) + "</b></td><td><span class='tag " +
    (a.nivel === "alta" ? "alta" : "media") + "'>" + esc(nomeNivel[a.nivel] || a.nivel) + "</span></td><td>" + esc(a.mensagem) +
    "</td></tr>").join("") || "<tr><td colspan='4' class='vazio'>Nenhum alerta.</td></tr>";
  const itens = enc.itens.sort((a, b) => (b.prioridade.pontos || 0) - (a.prioridade.pontos || 0) || a.id - b.id);
  $("criticos").innerHTML = itens.map(o => "<tr><td>" + (o.foto.url ? "<img src='" + esc(o.foto.url) + "' alt='foto do obstáculo'>" :
    "<span class='semfoto'>sem foto</span>") +
    "</td><td class='proto'>" + esc(o.protocolo) + "</td><td>" + esc(nomeCat[o.categoria] || o.categoria) +
    "</td><td><span class='tag " + esc(o.prioridade.nivel) + "'>" +
    esc(nomeNivel[o.prioridade.nivel] || o.prioridade.nivel) + " · " + esc(o.prioridade.pontos) + " pts</span></td><td class='local'><b>" +
    esc(o.local.rua) + "</b><br><small>" + esc(o.local.referencia) + "</small></td><td class='num'>" + esc(o.reincidencias) +
    "</td><td><span class='tag neutra'>" + esc(cap(o.origem)) + "</span></td></tr>").join("") ||
    "<tr><td colspan='7' class='vazio'>Nenhuma ocorrência encaminhada ainda.</td></tr>";
  $("exec").innerHTML = ex.itens.map(e => "<tr><td class='num'>" + esc(new Date(e.inicio).toLocaleString("pt-BR")) + "</td><td class='num'>" +
    e.processados + "</td><td class='num'>" + e.sucessos + "</td><td class='num'>" + (e.falhas ? "<span class='falha'>" + e.falhas + "</span>" : e.falhas) +
    "</td><td class='num'>" + e.duracao_s + " s</td><td>" +
    (e.erros.length ? e.erros.map(x => "<span class='erro'>" + esc(x.etapa + ": " + x.mensagem) + "</span>").join("<br>") : "<small>—</small>") + "</td></tr>").join("") ||
    "<tr><td colspan='6' class='vazio'>Nenhuma execução com itens ainda.</td></tr>";
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
