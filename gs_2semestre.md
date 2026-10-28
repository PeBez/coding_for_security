# Trabalho Final (GS) — SecuraPy Platform: SIEM como Plataforma de Segurança

| | |
|---|---|
| **Disciplina:** | Coding for Security |
| **Tipo:** | Trabalho Final Prático — Projeto em Grupo |
| **Abrangência:** | 1º e 2º semestres (com **foco no 2º semestre**) |
| **Equipe:** | 3 a 4 integrantes |
| **Peso:** | 40% da nota final |
| **Entrega:** | Código-fonte + Documentação + Apresentação em vídeo |

---

## 1. Cenário

No 1º semestre, a consultoria **CyberShield Ltda.** entregou ao cliente do setor financeiro um **MVP** do **SecuraPy** — um SIEM simplificado em linha de comando, que lia logs de arquivos, aplicava regras, detectava ataques e alertava via socket. O cliente aprovou o MVP e **renovou o contrato**.

Agora o cliente quer mais. O SecuraPy CLI resolveu o problema imediato, mas não escala nem se integra ao restante do ecossistema de TI. A nova demanda é transformar o SecuraPy em uma **plataforma de segurança de verdade**:

- Os eventos e alertas precisam ser **persistidos em banco de dados** (não podem sumir quando o programa fecha).
- Outros sistemas (dashboards, apps, automações) precisam consultar os dados via **API REST**.
- A detecção baseada só em regras fixas deve ser complementada por **machine learning**, que aprende padrões e prioriza alertas.
- Os analistas querem uma **interface web** e explicações em linguagem natural (via **LLM**) para acelerar a triagem.
- Tudo deve ser **empacotado com Docker** para deploy reproduzível.

A equipe de vocês é, de novo, o time de desenvolvimento da CyberShield. O desafio da GS é **evoluir o SecuraPy do 1º semestre para o SecuraPy Platform**, reaproveitando o que já foi construído e aplicando tudo que aprenderam no 2º semestre.

> **Importante — abrangência:** este trabalho abrange **os dois semestres**. A base de coleta, parsing, regras, detecção (brute force, port scan, blacklist) e alertas via socket vem do 1º semestre e **deve ser reaproveitada**. As camadas novas — banco de dados, API Flask, ML, web, Docker e LLM — são o **foco do 2º semestre** e concentram a maior parte da nota.

---

## 2. Arquitetura da Plataforma

O sistema evolui de scripts CLI para uma arquitetura em camadas. Sugestão de organização:

```
securaPy_platform/
├── core/                          # NÚCLEO — reaproveitado do 1º semestre (evoluído)
│   ├── coletor.py                 # Leitura e parsing de logs (1º sem)
│   ├── regras.py                  # Motor de regras configurável (1º sem)
│   ├── detector.py                # Brute force, port scan, blacklist (1º sem)
│   └── enriquecimento.py          # Consulta ipinfo.io + cache (1º sem, melhorado)
│
├── db/                            # PERSISTÊNCIA — 2º sem (Aulas 1-3)
│   ├── mongo_repo.py              # Repositório de eventos/alertas no MongoDB
│   └── mysql_repo.py              # Repositório de usuários/permissões no MySQL
│
├── ml/                            # MACHINE LEARNING — 2º sem (Aulas 4, 12)
│   ├── treinar.py                 # Treina e salva o classificador (joblib)
│   ├── modelo.pkl                 # Modelo persistido
│   └── classificar.py             # Carrega o modelo e classifica/prioriza alertas
│
├── api/                           # API REST — 2º sem (Aulas 6, 7, 10)
│   ├── app.py                     # Aplicação Flask (rotas, validação, segurança)
│   └── auth.py                    # Autenticação por token
│
├── ia/                            # LLM — 2º sem (Aula 13)
│   └── assistente.py              # Triagem e explicação de eventos via LLM (com fallback)
│
├── web/                           # DASHBOARD — 2º sem (Aula 8)
│   └── templates/                 # Páginas HTML (com escape/XSS defendido)
│
├── alertas/                       # TEMPO REAL — 1º semestre
│   ├── servidor_alertas.py        # Servidor TCP de alertas (1º sem)
│   └── cliente_alertas.py         # Console cliente (1º sem)
│
├── logs/                          # Dados de teste (auth.log, firewall.log, web_access.log)
├── config/regras.json             # Regras configuráveis (1º sem)
├── Dockerfile                     # 2º sem (Aula 11)
├── docker-compose.yml             # Sobe app + MongoDB + MySQL juntos
├── requirements.txt
└── README.md                      # Documentação completa
```

> **Referências na apostila:** persistência (Aulas 1–3), ML (Aulas 4 e 12), API (Aulas 6, 7 e 10), segurança web (Aula 8), Docker (Aula 11), LLM (Aula 13). A base reaproveitada está na GS e apostila do 1º semestre.

---

## 3. Requisitos Detalhados

O trabalho é dividido em módulos. Os módulos do **NÚCLEO** vêm do 1º semestre (reaproveitados/adaptados); os demais são o foco do 2º semestre.

---

### MÓDULO A — Núcleo reaproveitado (1º semestre)

#### Contexto

Toda a plataforma se apoia na capacidade de ler logs, aplicar regras e detectar ataques — já construída no 1º semestre. Aqui vocês **integram** esse núcleo à nova arquitetura, sem reescrevê-lo do zero.

#### Requisitos

1. **Coletor** lê os 3 logs (`auth.log`, `firewall.log`, `web_access.log`) e normaliza em eventos (dicionários padronizados).
2. **Motor de regras** carrega `regras.json` e gera alertas com severidade.
3. **Detector** identifica brute force, port scan e IPs em blacklist (usando dict e set).
4. **Servidor de alertas** TCP faz broadcast em tempo real para consoles conectados.

> Se o grupo quiser, pode refatorar o núcleo em funções mais limpas — mas o comportamento deve ser o mesmo do 1º semestre. Os dados de teste são os mesmos `logs/` da GS anterior.

#### Cenário de teste

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| A1 | Carregar os 3 logs | Lista unificada de eventos, campo `fonte` correto |
| A2 | Detectar brute force no `auth.log` | `185.220.101.1` com 10 FAILs (ALTA) |
| A3 | Detectar port scan no `firewall.log` | `185.220.101.1` com 7 portas distintas |
| A4 | Cruzar com blacklist | Interseção retorna os 3 IPs maliciosos conhecidos |

---

### MÓDULO B — Persistência em Banco de Dados (2º sem — Aulas 1–3)

#### Contexto

Os eventos e alertas não podem mais viver só em memória. Eventos e alertas (volume, schema flexível) vão para o **MongoDB**; usuários e permissões da plataforma (integridade relacional) vão para o **MySQL**.

#### Requisitos

1. **`mongo_repo.py`** — funções para salvar eventos e alertas, buscar com filtros (fonte, tipo, IP, período), e agregar (top IPs, contagem por severidade). Criar índice em `ip` e `timestamp`.
2. **`mysql_repo.py`** — CRUD de usuários da plataforma com **queries parametrizadas** (email único, nível de acesso 1–5). Autenticação de operadores.
3. **Migração** — um script que lê os logs via núcleo e popula o MongoDB (ingestão inicial).

#### Cenários de teste

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| B1 | Ingerir os 3 logs no MongoDB | 58 eventos persistidos (23 auth + 17 firewall + 18 web) |
| B2 | Agregação "top 5 IPs por eventos" | `185.220.101.1` no topo |
| B3 | Cadastrar usuário com email duplicado | Erro tratado (não quebra) |
| B4 | Tentar SQL Injection no login (`' OR '1'='1`) | Neutralizado pela parametrização |

#### Dicas

- CRUD MongoDB e agregação — **Aula 2**. CRUD MySQL parametrizado — **Aula 3**. Índices e TTL — **Aula 2, seção 2.4**.

---

### MÓDULO C — Machine Learning para priorização (2º sem — Aulas 4, 12)

#### Contexto

O motor de regras detecta o que é conhecido. O ML aprende a **priorizar**: dado o volume de eventos de um IP e o tipo de atividade, quão provável é que seja um ataque real? Isso reduz o "alert fatigue" — o analista vê primeiro o que mais importa.

#### Requisitos

1. **`treinar.py`** — extrai features dos eventos (ex: nº de FAILs, nº de portas distintas, presença em blacklist, nº de requisições web com erro), rotula (ataque/normal) e treina um classificador dentro de um **Pipeline** (StandardScaler + modelo). Avalia com **validação cruzada** e reporta precisão/recall/F1.
2. **Persistência** — salva o modelo com `joblib` e registra o **hash SHA-256** do arquivo (integridade — reaproveita `hashlib` do 1º sem).
3. **`classificar.py`** — carrega o modelo (verificando o hash) e atribui a cada IP suspeito um score de risco, usado para ordenar os alertas.
4. **Detecção de anomalias** (opcional/bônus) — Isolation Forest sobre métricas de tráfego para achar padrões desconhecidos.

#### Cenários de teste

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| C1 | Treinar e avaliar | Relatório com precisão, recall e F1 impressos |
| C2 | Classificar `185.220.101.1` (10 FAILs + port scan + blacklist) | Score de risco ALTO / rótulo "ataque" |
| C3 | Classificar `192.168.1.10` (tráfego normal interno) | Rótulo "normal" |
| C4 | Verificar integridade do modelo | Hash confere; se alterado, alerta |

#### Dicas

- Classificação e métricas — **Aula 4**. Pipeline, validação cruzada e persistência — **Aula 12**. Hash de integridade — **1º sem, Aula 11 (hashlib)**.

---

### MÓDULO D — API REST (2º sem — Aulas 6, 7, 10)

#### Contexto

A API é a porta de entrada da plataforma. Dashboards, automações e outros sistemas consultam os dados por aqui — em vez de mexer direto no banco.

#### Requisitos

1. **Rotas de eventos e alertas:** `GET /api/eventos` (com filtros e paginação), `GET /api/alertas`, `GET /api/alertas/<id>`, `POST /api/alertas`.
2. **Rota de análise:** `POST /api/analisar` — recebe um caminho de log ou um lote de eventos, roda núcleo + regras + detector + ML, persiste e retorna o resumo.
3. **Busca por IP:** `GET /api/ip/<ip>` — retorna todos os eventos do IP, alertas relacionados, dados de enriquecimento (geolocalização) e score de ML.
4. **Autenticação por token:** rotas de escrita exigem um header `Authorization: Bearer <token>`. Sem token válido → 401.
5. **Status codes corretos**, validação de entrada e tratamento de erros sem vazar detalhes internos.

#### Cenários de teste

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| D1 | `GET /api/alertas?severidade=critica&pagina=1&tamanho=5` | Alertas críticos paginados |
| D2 | `GET /api/ip/185.220.101.1` | Eventos + alertas + geo + score do IP |
| D3 | `POST /api/alertas` sem token | 401 |
| D4 | `POST /api/alertas` com corpo inválido | 400 |
| D5 | `GET /api/ip/<id_malformado>` | 400 amigável |

#### Dicas

- Flask CRUD e status codes — **Aula 6**. Integração com MongoDB/MySQL, paginação e filtros — **Aula 7**. Autenticação por token e boas práticas REST — **Aula 10**.

---

### MÓDULO E — Segurança Web e Dashboard (2º sem — Aula 8)

#### Contexto

A plataforma tem interface web para os analistas. Como qualquer aplicação web, ela é alvo — e uma ferramenta de **segurança** não pode ter falhas de segurança básicas.

#### Requisitos

1. **Dashboard HTML** que exibe: resumo de eventos por fonte, alertas por severidade, top 10 IPs suspeitos e busca por IP.
2. **Defesa contra XSS** — todo dado exibido é escapado (use Jinja2, que escapa por padrão).
3. **Headers de segurança** em todas as respostas (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`).
4. **Login de operador** com mensagem de erro genérica (anti-enumeração) e senha nunca em texto puro (hash).
5. **Logging de acesso** — registrar cada requisição (mapeando ao OWASP A09).

#### Cenários de teste

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| E1 | Cadastrar alerta com descrição `<script>alert(1)</script>` e exibir | Texto literal na tela, script NÃO executa |
| E2 | Inspecionar headers da resposta | Os 3 headers de segurança presentes |
| E3 | Login com senha errada e com usuário inexistente | Mesma mensagem 401 genérica |
| E4 | Acessar qualquer rota | Linha de log registrada |

#### Dicas

- OWASP Top 10, XSS, headers, misconfiguration — **Aula 8**. Templates e rotas — **Aula 6**.

---

### MÓDULO F — Empacotamento com Docker (2º sem — Aula 11)

#### Contexto

Deploy manual é fonte de erro. Com Docker, a plataforma inteira sobe com um comando, de forma idêntica em qualquer máquina.

#### Requisitos

1. **`Dockerfile`** que empacote a aplicação Python.
2. **`docker-compose.yml`** que suba **três serviços juntos**: a API SecuraPy, o MongoDB e o MySQL, conectados em rede.
3. **Script de verificação** (via SDK docker-py) que confirme que os contêineres subiram e estão "running".

#### Cenários de teste

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| F1 | `docker-compose up` | Os 3 serviços sobem e se comunicam |
| F2 | Script de status via SDK | Lista os 3 contêineres como "running" |
| F3 | Acessar a API dentro do compose | Responde 200 |

#### Dicas

- Docker SDK, imagens e contêineres — **Aula 11**. Ambiente com Docker — seção *Ambiente de Laboratório* da apostila.

---

### MÓDULO G — Assistente com LLM (2º sem — Aula 13)

#### Contexto

Para acelerar a triagem, a plataforma oferece um assistente que **explica** e **classifica** eventos em linguagem natural — um "analista júnior virtual".

#### Requisitos

1. **`assistente.py`** — recebe um evento/alerta e retorna classificação (NORMAL/SUSPEITO/CRÍTICO) + explicação curta.
2. **Boas práticas:** API key em variável de ambiente, `temperature` baixo, nenhum dado sensível enviado.
3. **Robustez:** valida a saída contra o conjunto fixo de rótulos e cai em **fallback por regras** se a API falhar ou a resposta for inválida.
4. **Consciência de prompt injection:** a entrada (que pode conter conteúdo de um atacante) é tratada como dado, e a saída nunca é usada para decisão automática sem validação.

#### Cenários de teste

| # | Cenário | Resultado esperado |
|---|---------|-------------------|
| G1 | Classificar `GET /../../etc/passwd` | CRÍTICO (path traversal) com explicação |
| G2 | Classificar acesso interno normal | NORMAL |
| G3 | Sem API key configurada | Usa fallback por regras, não quebra |
| G4 | Entrada com prompt injection | Não é classificada como NORMAL cegamente; saída validada |

> **Sem chave de API?** Aceita-se um `assistente` em modo `mock` (regras que simulam o LLM), desde que a interface seja idêntica. O importante é a arquitetura, não gastar créditos.

#### Dicas

- Integração OpenAI, papéis de mensagem, temperature e riscos — **Aula 13**.

---

## 4. Integração (`main.py` / `docker-compose`)

O fluxo ponta a ponta esperado:

1. `docker-compose up` sobe API + MongoDB + MySQL.
2. Chamar `POST /api/analisar` (autenticado) → o núcleo carrega os logs, aplica regras, detecta ataques, o ML pontua o risco, tudo é persistido no MongoDB.
3. O dashboard web mostra o resumo; o analista busca um IP e vê eventos + geo + score + explicação do LLM.
4. Alertas críticos são transmitidos em tempo real pelo servidor de alertas TCP para os consoles conectados.

```python
# Exemplo de orquestração conceitual (implementem o conteúdo):
# 1. eventos = coletor.carregar_todos_os_logs("logs")        # 1º sem
# 2. alertas = regras.aplicar_regras(eventos, regras.carregar_regras("config/regras.json"))
# 3. ameacas = detector.gerar_resumo_ameacas(...)            # 1º sem
# 4. mongo_repo.salvar_eventos(eventos); mongo_repo.salvar_alertas(alertas)  # Mód. B
# 5. scores = ml.classificar.pontuar(ameacas)                # Mód. C
# 6. (API expõe tudo; dashboard exibe; LLM explica; alertas via socket)      # Mód. D,E,G
```

---

## 5. Entregáveis

| # | Entregável | Descrição |
|---|-----------|-----------|
| 1 | **Código-fonte** | Pasta `securaPy_platform/` completa, com Dockerfile e docker-compose |
| 2 | **README.md** | Integrantes, descrição, arquitetura, como executar (com Docker), dependências, divisão de tarefas por integrante e o que foi reaproveitado do 1º semestre |
| 3 | **Apresentação em vídeo** | 12–18 min, enviada pelo Teams: subir com docker-compose, analisar logs via API, mostrar dashboard, buscar IP, ver score de ML, explicação do LLM e alertas em tempo real com 2 consoles |
| 4 | **Relatório de exemplo** | JSON exportado pela plataforma com os dados de teste |
| 5 | **Modelo treinado** | `modelo.pkl` + hash de integridade + relatório de métricas (precisão/recall/F1) |

---

## 6. Critérios de Avaliação

Nota total: **10,0 pontos**. Bônus de até **+1,0**.

### 6.1 Funcionalidade (5,0 pontos)

| Módulo | Pontuação | Critério |
|--------|-----------|----------|
| **A — Núcleo (1º sem) integrado** | **0,5** | Coleta, regras, detecção e alerta funcionam na nova arquitetura |
| **B — Persistência (Mongo + MySQL)** | **1,0** | Ingestão, consultas, agregação e CRUD parametrizado funcionais |
| **C — Machine Learning** | **1,0** | Treino, métricas, persistência com integridade e classificação de risco |
| **D — API REST** | **1,0** | Rotas, filtros, paginação, autenticação por token, status codes corretos |
| **E — Segurança Web / Dashboard** | **0,75** | Dashboard, defesa XSS, headers, login endurecido, logging |
| **F — Docker** | **0,5** | Dockerfile + compose sobem a plataforma inteira |
| **G — Assistente LLM** | **0,25** | Classificação + explicação com fallback e boas práticas |

### 6.2 Tratamento de Erros (1,0 ponto)

| Critério | Pontuação |
|----------|-----------|
| Log inexistente/ malformado não trava a ingestão | 0,15 |
| Erros de banco (duplicata, conexão) tratados | 0,20 |
| Input inválido na API retorna 400, não 500 | 0,15 |
| Erros de rede (LLM, enriquecimento, socket) tratados | 0,15 |
| Falha da API do LLM cai em fallback | 0,15 |
| Erros 500 não vazam traceback/query/segredos | 0,20 |

### 6.3 Qualidade do Código (1,5 pontos)

| Critério | Pontuação |
|----------|-----------|
| **Arquitetura em camadas:** separação clara núcleo/db/ml/api/web/ia | 0,40 |
| **Reaproveitamento consciente do 1º semestre** (sem reescrever à toa) | 0,25 |
| **Segurança no código:** queries parametrizadas, escape de saída, segredos em env | 0,35 |
| **Funções bem definidas**, responsabilidade única, sem duplicação | 0,25 |
| **Estruturas de dados adequadas** (dict, set, tupla) conforme o problema | 0,25 |

### 6.4 Documentação e Apresentação (1,5 pontos)

| Critério | Pontuação |
|----------|-----------|
| README completo (execução via Docker, arquitetura, o que veio do 1º sem) | 0,35 |
| Divisão de tarefas documentada | 0,15 |
| Apresentação em vídeo fluida, demonstrando o fluxo ponta a ponta | 1,00 |

**Observação:** cada integrante apresenta a parte que contribuiu; ao final, um integrante faz um **teste ponta a ponta** (subir via Docker → analisar → dashboard → alerta em tempo real).

### 6.5 Bônus (até +1,0 ponto extra)

| Bônus | Pontuação |
|-------|-----------|
| **Detecção de anomalias** (Isolation Forest) além das regras | +0,30 |
| **Correlação temporal** (brute force em janela de tempo, não só contagem total) | +0,20 |
| **CI/CD ou testes automatizados** (pytest) para os módulos, como no 1º sem | +0,30 |
| **Autenticação JWT completa** (geração e verificação de token) na API | +0,20 |

### Resumo da Pontuação

| Categoria | Pontuação |
|-----------|-----------|
| Funcionalidade | 5,0 |
| Tratamento de Erros | 1,0 |
| Qualidade do Código | 1,5 |
| Documentação e Apresentação | 1,5 |
| **Total** | **10,0** |
| Bônus (extra) | até +1,0 |

---

## 7. Sugestão de Divisão de Trabalho

### Equipe de 4 pessoas

| Integrante | Responsabilidade | Módulos |
|-----------|-----------------|---------|
| **Pessoa A** | Núcleo + Persistência | Módulo A (integração 1º sem) + Módulo B (MongoDB/MySQL) |
| **Pessoa B** | Machine Learning | Módulo C (treino, métricas, classificação, integridade) |
| **Pessoa C** | API + Docker | Módulo D (API REST) + Módulo F (Docker/compose) |
| **Pessoa D** | Web + LLM | Módulo E (dashboard/segurança) + Módulo G (assistente LLM) |

### Equipe de 3 pessoas

| Integrante | Responsabilidade | Módulos |
|-----------|-----------------|---------|
| **Pessoa A** | Núcleo + Persistência + ML | Módulos A, B e C |
| **Pessoa B** | API + Docker | Módulos D e F |
| **Pessoa C** | Web + LLM + integração | Módulos E, G e o `docker-compose`/integração final |

---

## 8. Dicas Gerais

1. **Comecem integrando o núcleo do 1º semestre** — ele alimenta todo o resto. Não reescrevam do zero; adaptem.
2. **Combinem os contratos cedo** — o formato do `evento` e do `alerta` (dicionários) é a "cola" entre todos os módulos. Definam juntos antes de codar.
3. **Persistência antes de API** — a API só faz sentido com dados no banco. Sigam a ordem B → C → D.
4. **Segurança não é opcional** — uma ferramenta de segurança com SQL Injection ou XSS perde credibilidade. Parametrizem e escapem desde o início.
5. **Docker por último, mas não na véspera** — deixem tempo para debugar o `docker-compose`.
6. **LLM com fallback** — não deixem a nota depender de crédito de API; o modo `mock` garante que sempre funcione.
7. **Git é essencial** — trabalhem em paralelo com branches; a arquitetura em camadas facilita dividir sem conflito.
8. **Testem ponta a ponta antes de gravar o vídeo** — o teste final da apresentação não pode ser a primeira vez que tudo roda junto.

---

**Bom trabalho! Vocês estão saindo de "quem resolve exercícios" para "quem constrói plataformas de segurança". Em segurança, cada detalhe importa — e agora vocês têm as ferramentas para cuidar de cada um deles.**
