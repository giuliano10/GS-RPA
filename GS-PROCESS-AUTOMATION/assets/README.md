# Evidências visuais

Capturas de tela **reais** da aplicação funcionando, geradas por [`tests/capturar_telas.py`](../tests/capturar_telas.py)
com um navegador automatizado, sobre dados de demonstração. As fotos dos relatos são **ilustrações**
marcadas "FOTO DE EXEMPLO"; não são fotos de pessoas nem de lugares reais.

| Arquivo | O que mostra |
|---|---|
| `01_formulario_cidadao.png` | Formulário com o aviso de privacidade |
| `02_formulario_preenchido.png` | Relato preenchido, com aceite do aviso |
| `03_relato_enviado_com_codigo.png` | Confirmação com o código de acompanhamento |
| `04_acompanhamento_andamento.png` | Andamento do relato, processado sozinho pelo robô agendado |
| `05_painel_exige_login.png` | Painel protegido por chave |
| `06_painel_orgaos_publicos.png` | Painel: totais, alertas, pontos críticos por prioridade e histórico do robô com erros |
| `07_resultado_testes_integracao.png` | Resultado do teste ponta a ponta (texto de `tests/evidencias/`) |

Para regerar: `pip install pillow playwright && playwright install chromium && python tests/capturar_telas.py`.
