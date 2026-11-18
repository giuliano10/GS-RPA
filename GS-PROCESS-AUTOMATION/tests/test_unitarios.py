#!/usr/bin/env python3
"""
Testes unitários do Caminho Livre (só biblioteca padrão).

Uso, a partir da raiz do repositório:
    python tests/test_unitarios.py
    (ou: python -m unittest -v tests.test_unitarios)

Tudo roda numa pasta temporária: nenhum dado real é tocado.
"""
import os
import struct
import sys
import tempfile
import unittest
import zlib
from datetime import datetime, timedelta
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
_tmp = tempfile.mkdtemp(prefix="cl_unit_")
os.chdir(_tmp)  # banco, logs e uploads vão para a pasta temporária
sys.path.insert(0, str(RAIZ / "src"))
import rpa_caminho_livre as rpa  # noqa: E402
import servidor_caminho_livre as srv  # noqa: E402

GPS = b"GPSLatitude=-23.6229;GPSLongitude=-46.5548"


def _seg(m, p):
    return bytes([0xFF, m]) + (len(p) + 2).to_bytes(2, "big") + p


def _jpeg():
    return (b"\xff\xd8" + _seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
            + _seg(0xE1, b"Exif\x00\x00" + GPS) + _seg(0xFE, b"camera") + _seg(0xDB, b"\x00" + bytes(64))
            + _seg(0xDA, b"\x01\x01\x00\x00\x3f\x00") + b"\x12\x34\x56" + b"\xff\xd9")


def _chunk(t, d):
    c = struct.pack(">I", len(d)) + t + d
    return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)


def _png():
    raw = b"".join(b"\x00" + b"\x10\x20\x30" * 8 for _ in range(8))
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0))
            + _chunk(b"eXIf", GPS) + _chunk(b"tEXt", b"Comment\x00" + GPS)
            + _chunk(b"IDAT", zlib.compress(raw)) + _chunk(b"IEND", b""))


def _webp():
    def bloco(t, d):
        return t + len(d).to_bytes(4, "little") + d + (b"\x00" if len(d) & 1 else b"")
    corpo = (bloco(b"VP8X", bytes([0x0C, 0, 0, 0, 7, 0, 0, 7, 0, 0])) + bloco(b"VP8 ", b"\x00" * 20)
             + bloco(b"EXIF", GPS) + bloco(b"XMP ", GPS))
    return b"RIFF" + (4 + len(corpo)).to_bytes(4, "little") + b"WEBP" + corpo


def _limpar_banco():
    con = rpa.conectar()
    for t in ("ocorrencias", "alertas", "auditoria", "execucoes"):
        con.execute(f"DELETE FROM {t}")
    con.execute("DELETE FROM sqlite_sequence")  # reinicia os ids (AUTOINCREMENT)
    con.commit()
    return con


class TestSanitizacao(unittest.TestCase):
    def test_remove_dados_pessoais(self):
        t = rpa.sanitizar("ana@x.com cpf 123.456.789-09 tel (11) 91234-5678 lat -23.622912")
        for sensivel in ("ana@x.com", "123.456.789-09", "91234-5678", "23.622912"):
            self.assertNotIn(sensivel, t)

    def test_remove_caminho_de_arquivo(self):
        self.assertEqual(rpa.sanitizar("falha em /home/aluno/uploads/a08d.png"), "falha em [caminho]")
        self.assertIn("[caminho]", rpa.sanitizar("erro C:\\Users\\ana\\foto.png"))

    def test_preserva_rotas_da_api_e_fracoes(self):
        self.assertEqual(rpa.sanitizar("HTTP GET /api/v1/resumo -> 200"), "HTTP GET /api/v1/resumo -> 200")
        self.assertEqual(rpa.sanitizar("tentativa 1/3 falhou"), "tentativa 1/3 falhou")

    def test_descrever_erro_nao_vaza_dados(self):
        msg = rpa.descrever_erro(ValueError("falha com ana@x.com em /tmp/dados/x.csv"))
        self.assertTrue(msg.startswith("ValueError:"))
        self.assertNotIn("ana@x.com", msg)
        self.assertNotIn("/tmp/dados", msg)


class TestRegrasDeNegocio(unittest.TestCase):
    def test_normalizar_acentos_e_abreviacoes(self):
        self.assertEqual(rpa.normalizar("R. Manoel Coelho"), "rua manoel coelho")
        self.assertEqual(rpa.normalizar("Av. Goiás"), "avenida goias")

    def test_similaridade_ruas_equivalentes(self):
        self.assertGreaterEqual(rpa.similaridade("R. Manoel Coelho", "Rua Manoel Coelho"), rpa.SIMILARIDADE_RUA)
        self.assertLess(rpa.similaridade("Rua Manoel Coelho", "Avenida Goiás"), rpa.SIMILARIDADE_RUA)

    def test_prioridade(self):
        self.assertEqual(rpa.calcular_prioridade("buraco", 0), (5, "media"))
        self.assertEqual(rpa.calcular_prioridade("buraco", 2), (7, "alta"))
        self.assertEqual(rpa.calcular_prioridade("lixeira", 0), (2, "baixa"))
        self.assertEqual(rpa.calcular_prioridade("buraco", 99)[0], 10)  # reincidência limitada a 5

    @staticmethod
    def _ocorrencia(**kw):
        base = dict(categoria="buraco", rua="Rua A1", referencia="Ref A1", foto_hash="h",
                    foto_path=None, origem="cidadao")
        base.update(kw)
        return base

    def test_validacao(self):
        self.assertIsNone(rpa.validar(self._ocorrencia()))
        self.assertIn("foto_hash", rpa.validar(self._ocorrencia(foto_hash=None)))
        self.assertIn("rua", rpa.validar(self._ocorrencia(rua="")))
        self.assertIn("categoria inválida", rpa.validar(self._ocorrencia(categoria="xyz")))
        self.assertIn("muito curta", rpa.validar(self._ocorrencia(rua="ab")))

    def test_fonte_externa_nao_exige_foto(self):
        self.assertIsNone(rpa.validar(self._ocorrencia(foto_hash=None, origem="prefeitura")))

    def test_foto_inexistente_e_rejeitada(self):
        self.assertIn("arquivo da foto", rpa.validar(self._ocorrencia(foto_path="nao/existe.jpg")))

    def test_protocolo(self):
        self.assertRegex(rpa.gerar_protocolo(), r"^CL-\d{4}-[0-9A-F]{8}$")


class TestDuplicidade(unittest.TestCase):
    def setUp(self):
        self.con = _limpar_banco()
        agora = datetime.now().isoformat()
        self.con.execute("INSERT INTO ocorrencias(categoria,rua,referencia,foto_hash,criado_em,status,protocolo)"
                         " VALUES('buraco','Rua Manoel Coelho','Em frente à padaria Pão Doce','hA',?,"
                         "'encaminhada','CL-2026-AAAAAAAA')", (agora,))
        self.con.commit()

    def _nova(self, cat, rua, ref, h):
        cur = self.con.execute("INSERT INTO ocorrencias(categoria,rua,referencia,foto_hash,criado_em)"
                               " VALUES(?,?,?,?,?)", (cat, rua, ref, h, datetime.now().isoformat()))
        self.con.commit()
        return self.con.execute("SELECT * FROM ocorrencias WHERE id=?", (cur.lastrowid,)).fetchone()

    def tearDown(self):
        self.con.close()

    def test_mesma_foto(self):
        self.assertIsNotNone(rpa.achar_duplicata(self.con, self._nova("buraco", "Outra Rua 99", "xyz abc", "hA")))

    def test_mesma_rua_e_referencia_escritas_de_outro_jeito(self):
        o = self._nova("buraco", "R. Manoel Coelho", "em frente a padaria Pao Doce", "hB")
        self.assertIsNotNone(rpa.achar_duplicata(self.con, o))

    def test_outra_categoria_nao_e_duplicata(self):
        o = self._nova("poste", "Rua Manoel Coelho", "Em frente à padaria Pão Doce", "hC")
        self.assertIsNone(rpa.achar_duplicata(self.con, o))

    def test_outra_rua_nao_e_duplicata(self):
        o = self._nova("buraco", "Avenida Goiás", "Perto do ponto de ônibus", "hD")
        self.assertIsNone(rpa.achar_duplicata(self.con, o))

    def test_hash_vazio_nunca_conta_como_mesma_foto(self):
        self.con.execute("INSERT INTO ocorrencias(categoria,rua,referencia,criado_em,status,protocolo,origem)"
                         " VALUES('obra','Rua Z1','Ref Z1',?,'encaminhada','CL-2026-BBBBBBBB','prefeitura')",
                         (datetime.now().isoformat(),))
        self.con.commit()
        o = self._nova("obra", "Rua Completamente Diferente", "Outro lugar", None)
        self.assertIsNone(rpa.achar_duplicata(self.con, o))

    def test_fora_da_janela_de_30_dias(self):
        self.con.execute("UPDATE ocorrencias SET criado_em=?", ((datetime.now() - timedelta(days=45)).isoformat(),))
        self.con.commit()
        o = self._nova("buraco", "Rua Manoel Coelho", "Em frente à padaria Pão Doce", "hE")
        self.assertIsNone(rpa.achar_duplicata(self.con, o))


class TestMetadadosDasFotos(unittest.TestCase):
    def test_remove_gps_de_jpeg_png_e_webp(self):
        for nome, dados, ext in (("jpeg", _jpeg(), ".jpg"), ("png", _png(), ".png"), ("webp", _webp(), ".webp")):
            with self.subTest(formato=nome):
                self.assertEqual(srv.detectar_extensao(dados), ext)
                self.assertIn(GPS, dados)
                limpo = srv.limpar_metadados(dados, ext)
                self.assertNotIn(GPS, limpo)
                self.assertEqual(srv.detectar_extensao(limpo), ext)

    def test_mantem_o_conteudo_da_imagem(self):
        self.assertIn(b"\x12\x34\x56", srv.limpar_metadados(_jpeg(), ".jpg"))
        self.assertIn(b"IDAT", srv.limpar_metadados(_png(), ".png"))

    def test_rejeita_arquivo_que_nao_e_imagem(self):
        self.assertIsNone(srv.detectar_extensao(b"isto nao e uma imagem"))

    def test_jpeg_truncado_gera_erro(self):
        with self.assertRaises(ValueError):
            srv.limpar_metadados(b"\xff\xd8\xff\xe1\x00\x50abc", ".jpg")


class TestAuditoriaEncadeada(unittest.TestCase):
    def test_detecta_adulteracao(self):
        con = _limpar_banco()
        for i in range(4):
            rpa.audit(con, "exec1", i, "VALIDADA", f"prioridade={i}")
        con.commit()
        self.assertEqual(rpa.verificar_auditoria(con), (True, 4))
        ids = [r[0] for r in con.execute("SELECT id FROM auditoria ORDER BY id")]
        con.execute("UPDATE auditoria SET detalhe='ADULTERADO' WHERE id=?", (ids[1],))
        con.commit()
        self.assertEqual(rpa.verificar_auditoria(con), (False, ids[1]))
        con.close()

    def test_detecta_remocao(self):
        con = _limpar_banco()
        for i in range(4):
            rpa.audit(con, "exec1", i, "VALIDADA", "x")
        con.commit()
        ids = [r[0] for r in con.execute("SELECT id FROM auditoria ORDER BY id")]
        con.execute("DELETE FROM auditoria WHERE id=?", (ids[1],))
        con.commit()
        self.assertFalse(rpa.verificar_auditoria(con)[0])
        con.close()

    def test_detalhe_da_auditoria_e_sanitizado(self):
        con = _limpar_banco()
        rpa.audit(con, "e", 1, "ERRO", "falha com ana@x.com")
        con.commit()
        self.assertNotIn("ana@x.com", con.execute("SELECT detalhe FROM auditoria").fetchone()[0])
        con.close()


class TestLGPD(unittest.TestCase):
    def setUp(self):
        self.con = _limpar_banco()
        Path("uploads").mkdir(exist_ok=True)

    def tearDown(self):
        self.con.close()

    def _inserir(self, dias, foto, token):
        Path(foto).write_bytes(b"x")
        self.con.execute("INSERT INTO ocorrencias(categoria,rua,referencia,foto_path,criado_em,token)"
                         " VALUES('buraco','Rua A1','Ref A1',?,?,?)",
                         (foto, (datetime.now() - timedelta(days=dias)).isoformat(), token))
        self.con.commit()

    def test_retencao_apaga_so_o_que_passou_do_prazo(self):
        self._inserir(200, "uploads/velha.jpg", "TOKENVELHO1")
        self._inserir(1, "uploads/nova.jpg", "TOKENNOVO01")
        res = rpa.limpar_dados(90)
        self.assertEqual(res["ocorrencias"], 1)
        self.assertFalse(Path("uploads/velha.jpg").exists())
        self.assertTrue(Path("uploads/nova.jpg").exists())

    def test_titular_pode_apagar_o_proprio_relato(self):
        self._inserir(1, "uploads/minha.jpg", "MEUTOKEN001")
        self.assertTrue(rpa.apagar_ocorrencia("MEUTOKEN001"))
        self.assertFalse(Path("uploads/minha.jpg").exists())
        self.assertFalse(rpa.apagar_ocorrencia("MEUTOKEN001"))  # já não existe

    def test_codigo_curto_ou_vazio_nao_apaga_nada(self):
        self._inserir(1, "uploads/outra.jpg", "OUTROTOKEN1")
        self.assertFalse(rpa.apagar_ocorrencia(""))
        self.assertFalse(rpa.apagar_ocorrencia("abc"))
        self.assertTrue(Path("uploads/outra.jpg").exists())

    def test_foto_compartilhada_so_some_quando_ninguem_mais_usa(self):
        self._inserir(1, "uploads/igual.jpg", "TOKENAAAA01")
        self.con.execute("INSERT INTO ocorrencias(categoria,rua,referencia,foto_path,criado_em,token)"
                         " VALUES('buraco','Rua B1','Ref B1','uploads/igual.jpg',?,'TOKENBBBB01')",
                         (datetime.now().isoformat(),))
        self.con.commit()
        rpa.apagar_ocorrencia("TOKENAAAA01")
        self.assertTrue(Path("uploads/igual.jpg").exists())
        rpa.apagar_ocorrencia("TOKENBBBB01")
        self.assertFalse(Path("uploads/igual.jpg").exists())


class TestTrava(unittest.TestCase):
    def test_apenas_uma_execucao_por_vez(self):
        rpa.liberar_trava()
        self.assertTrue(rpa.obter_trava())
        self.assertFalse(rpa.obter_trava())
        rpa.liberar_trava()
        self.assertTrue(rpa.obter_trava())
        rpa.liberar_trava()

    def test_trava_abandonada_e_removida(self):
        rpa.liberar_trava()
        rpa.TRAVA.write_text("antiga")
        velho = datetime.now().timestamp() - 3600
        os.utime(rpa.TRAVA, (velho, velho))
        self.assertTrue(rpa.obter_trava())
        rpa.liberar_trava()


if __name__ == "__main__":
    unittest.main(verbosity=2)
