# Amostras de logs (sem dados sensíveis)

Geradas por `python tests/test_integracao.py --saida logs` a partir de uma execução real do sistema
com dados de demonstração. O intervalo do agendador nesse teste foi encurtado para 3 segundos.

| Arquivo | Conteúdo |
|---|---|
| `rpa_amostra.log` | Log do robô e do servidor: data/hora, ocorrência (só o id), resultado e alertas |
| `execucoes_amostra.jsonl` | Uma linha por execução: início, fim, duração, processados, sucessos, falhas e mensagens de erro |
| `auditoria_amostra.json` | Trilha de auditoria encadeada por hash (`/api/v1/auditoria`) |
| `verificacao_integridade.json` | Resultado de `--verificar`: auditoria íntegra e banco × arquivos × API consistentes |

**Por que não há dados sensíveis:** os logs registram apenas ids e protocolos. Um filtro troca e-mail, CPF,
telefone, coordenadas, hashes e caminhos de arquivo por marcadores, a URL nunca vai para o log (nem o código de
acompanhamento, nem o IP) e as mensagens de erro saem só com o tipo do erro. O teste de integração confere isso:
termos como ruas, referências, códigos e IPs não aparecem nos logs.
