# Power Automate — não utilizado

A automação deste projeto foi implementada em **Python** (pasta [`../src`](../src)). Esta pasta existe para
registrar a decisão e deixar o mapeamento caso a equipe queira reproduzir o fluxo no Power Automate.
Nenhum fluxo foi exportado, então não há arquivos de exportação aqui.

| Etapa do robô (Python) | Equivalente no Power Automate |
|---|---|
| Agendador de 1 em 1 minuto | Gatilho **Recorrência** (1 minuto) |
| Trava de execução única | Controle de simultaneidade do gatilho (grau de paralelismo = 1) |
| Importar CSV da pasta `entrada/` | Gatilho/ação do **OneDrive ou SharePoint** + **Criar tabela / Analisar CSV** |
| Validar campos e categoria | **Condição** e **Alternar** |
| Detectar duplicidade | **Obter itens** (Lista/Excel) com filtro + **Condição** |
| Para cada ocorrência | **Aplicar a cada** |
| Retry do encaminhamento | Configuração de **política de repetição** da ação |
| Tratamento de exceções | Escopos **Try / Catch** com `runAfter` em *falhou* |
| Alertas | Ação **Postar mensagem no Teams** (ou e-mail) |
| Log e auditoria | Ação que grava em uma lista do SharePoint |
