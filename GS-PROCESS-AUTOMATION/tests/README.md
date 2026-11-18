# Testes

Só biblioteca padrão do Python. Tudo roda em pastas temporárias, sem tocar em dados reais.

```bash
python tests/test_unitarios.py                       # 30 testes unitários (menos de 1 s)
python tests/test_integracao.py [--saida PASTA]      # 48 verificações ponta a ponta (~30 s)
python tests/capturar_telas.py                       # opcional: gera as capturas de assets/ (Pillow + Playwright)
```

## O que é verificado

| Área | Exemplos |
|---|---|
| Regras de negócio | Validação, prioridade (baixa, média, alta), protocolo, duplicidade por foto ou por rua + referência, janela de 30 dias |
| Segurança | Acesso negado sem chave, login com cookie HttpOnly e SameSite, cabeçalhos CSP/nosniff, limite de 20 envios por minuto (429) |
| LGPD | Aceite do aviso obrigatório, remoção de GPS/EXIF (JPEG, PNG, WEBP), exclusão pelo titular, retenção de 90 dias |
| Automação | CSV importado **sem clique** pelo agendador, deduplicação entre fontes, alertas, quarentena após 3 falhas |
| Resiliência | CSV defeituoso vai para `entrada/erro/` e gera alerta, trava de execução única, trava abandonada removida |
| Auditoria e integração | Cadeia de hashes detecta adulteração, `--verificar` confere banco × arquivos × API, nenhum dado sensível nos logs |

## Evidências

- [`evidencias/resultado_unitarios.txt`](evidencias/resultado_unitarios.txt): saída dos testes unitários.
- [`evidencias/resultado_integracao.txt`](evidencias/resultado_integracao.txt): saída do teste ponta a ponta.
- Capturas de tela em [`../assets`](../assets) e amostras de logs em [`../logs`](../logs).

Os testes não cobrem a visão computacional nem o mapa de rotas, que não fazem parte deste repositório.
