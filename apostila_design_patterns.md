# Design Patterns em Python

| | |
|---|---|
| **Disciplina** | Coding for Security |
| **Professor** | Fabio Bara |
| **Tipo** | Módulo extra de fim de semestre (fora da estrutura oficial do curso) |
| **Carga** | 6 aulas de 2 horas |
| **Pré-requisito** | Apostila do 2º semestre (Aulas 1–8) |
| **Avaliação** | Sem Check Points. Cada aula tem exercícios de refatoração. |

## Como funciona

Cada aula segue o mesmo formato:

1. **O problema** — um trecho de código que funciona, mas incomoda.
2. **O padrão** — o que é, como fica em Python.
3. **Quando NÃO usar** — padrão aplicado fora de hora deixa o código pior.
4. **Exercícios de refatoração** — você recebe código pronto com problema e aplica o padrão.

Os exemplos usam o domínio do SecuraPy (SIEM) que vocês já conhecem. Tudo roda com **Python 3.10+ puro**, sem Docker e sem instalar nada.

> **Aviso honesto:** design pattern não é enfeite. Aplicado onde não precisa, ele adiciona três arquivos para resolver um problema que não existe. Cada aula tem uma seção dizendo quando o padrão é a escolha errada — leia essa seção com o mesmo cuidado que lê o resto.

## Sumário

- [Aula 1 — Factory: quem decide qual classe criar](#aula-1--factory-quem-decide-qual-classe-criar)
- [Aula 2 — Singleton: a instância única (e por que ela te trai)](#aula-2--singleton-a-instância-única-e-por-que-ela-te-trai)
- [Aula 3 — Observer: um evento, vários interessados](#aula-3--observer-um-evento-vários-interessados)
- [Aula 4 — Decorator: comportamento por cima da função](#aula-4--decorator-comportamento-por-cima-da-função)
- [Aula 5 — Adapter e Facade: domando APIs externas](#aula-5--adapter-e-facade-domando-apis-externas)
- [Aula 6 — Repository: o domínio não conhece o banco](#aula-6--repository-o-domínio-não-conhece-o-banco)
- [Referências](#referências)

---

## Aula 1 — Factory: quem decide qual classe criar

> **Duração:** 2 horas

### Introdução ao padrão

O **Factory** (Fábrica) é um padrão **criacional**: ele trata de *como* os objetos nascem. A ideia é simples — em vez de espalhar pelo código a decisão de qual classe concreta instanciar, você concentra essa decisão em um único lugar. Quem precisa do objeto pede "me dê um parser de SSH" e recebe um objeto pronto, sem nunca escrever `ParserSSH()`.

**Intenção (GoF):** definir uma interface para criar um objeto, deixando que a escolha da classe concreta aconteça em outro ponto do sistema.

**Analogia:** você pede um café na máquina apertando um botão. Não precisa saber qual mecanismo interno moe, aquece e serve — só o nome da bebida. Trocar o mecanismo não muda o botão.

**Onde você já viu:** `datetime.strptime()` devolve um `datetime` sem você construí-lo; `json.loads()` devolve `dict`, `list`, `int` ou `str` conforme o conteúdo; `logging.getLogger(nome)` devolve o logger certo.

**Variantes que veremos:** *Simple Factory* (uma função com um dicionário) e *Factory com registro* (as classes se cadastram sozinhas por decorador). O Factory Method clássico do GoF — uma subclasse decidindo o que criar — é mais raro em Python, onde funções são objetos de primeira classe.

**Objetivos**

- Isolar a decisão de "qual classe instanciar" em um único lugar.
- Escrever um Simple Factory e uma Factory com registro.
- Reconhecer o risco de segurança de criar classe a partir de string vinda do usuário.

### 1.1 O problema

Do coletor de logs de vocês:

```python
def ler(caminho, tipo):
    if tipo == "ssh":
        return parse_ssh(caminho)
    elif tipo == "apache":
        return parse_apache(caminho)
    elif tipo == "firewall":
        return parse_firewall(caminho)
    else:
        raise ValueError("tipo desconhecido")
```

Funciona. O incômodo: toda vez que entra um formato novo (DNS, Windows Event Log), você **edita** essa função. E ela não é a única — tem um `if/elif` igual no validador e outro no exportador. Três lugares para esquecer de atualizar.

### 1.2 O padrão

**Problema:** o código precisa criar objetos, mas não deveria decidir qual classe concreta.
**Solução:** uma função (ou método) que faz essa escolha e devolve o objeto pronto.

Primeiro o contrato comum:

```python
from abc import ABC, abstractmethod


class Parser(ABC):
    @abstractmethod
    def campos(self, linha: str) -> dict | None:
        """Devolve dict com os campos, ou None se a linha não casar."""


class ParserSSH(Parser):
    def campos(self, linha):
        if "sshd" not in linha:
            return None
        ip = linha.split("from ")[-1].split()[0]
        ok = "Accepted" in linha
        return {"fonte": "ssh", "ip": ip, "sucesso": ok}


class ParserApache(Parser):
    def campos(self, linha):
        partes = linha.split()
        if len(partes) < 9:
            return None
        return {"fonte": "apache", "ip": partes[0], "sucesso": partes[8].startswith("2")}
```

Agora o **Simple Factory** — um dicionário e uma função:

```python
_PARSERS = {"ssh": ParserSSH, "apache": ParserApache}


def criar_parser(tipo: str) -> Parser:
    classe = _PARSERS.get(tipo)
    if classe is None:
        raise ValueError(f"tipo '{tipo}' não suportado; use: {sorted(_PARSERS)}")
    return classe()
```

Melhor ainda: a classe **se registra sozinha**, com um decorador.

```python
def registrar(nome):
    def dentro(classe):
        _PARSERS[nome] = classe
        return classe
    return dentro


@registrar("firewall")
class ParserFirewall(Parser):
    def campos(self, linha):
        if "DROP" not in linha and "ACCEPT" not in linha:
            return None
        ip = linha.split("SRC=")[-1].split()[0]
        return {"fonte": "firewall", "ip": ip, "sucesso": "ACCEPT" in linha}
```

Adicionar formato novo agora é **criar um arquivo**. Nenhum `if` existente é tocado — isso é o princípio Aberto/Fechado do SOLID na prática.

```python
for tipo in ("ssh", "apache", "firewall"):
    print(tipo, "->", criar_parser(tipo).__class__.__name__)
```

```text
ssh -> ParserSSH
apache -> ParserApache
firewall -> ParserFirewall
```

### 1.3 Nota de segurança

A tentação é escrever a factory assim:

```python
def criar_parser(tipo):
    return globals()[tipo + "Parser"]()     # NÃO FAÇA ISSO
```

Se `tipo` vem do usuário (query string, campo de JSON, nome de arquivo), ele escolhe qualquer nome do seu módulo. É **A08 — Software and Data Integrity Failures**. O dicionário explícito é a defesa: só existe o que você colocou lá, e um tipo inválido vira `ValueError`, não instanciação surpresa.

### 1.4 Quando NÃO usar

- **Duas opções que nunca vão virar três.** Um `if` de duas linhas é mais legível que uma factory.
- **Quando quem chama já sabe a classe.** `ParserSSH()` direto é melhor que `criar_parser("ssh")` — você trocou verificação do compilador por string.
- **Quando a diferença entre os objetos é só um parâmetro.** Aí é argumento de construtor, não subclasse.

### 1.5 Exercícios de refatoração

> **Exercício 1.1 — Da cadeia de ifs para a factory:** o código abaixo funciona e tem três `if/elif` espalhados.
>
> ```python
> # ANTES
> def criar_notificador(canal, config):
>     if canal == "email":
>         return {"tipo": "email", "para": config["email_destino"]}
>     elif canal == "slack":
>         return {"tipo": "slack", "webhook": config["slack_url"]}
>     elif canal == "arquivo":
>         return {"tipo": "arquivo", "caminho": config["log_path"]}
>
> def enviar(n, msg):
>     if n["tipo"] == "email":
>         print(f"[EMAIL -> {n['para']}] {msg}")
>     elif n["tipo"] == "slack":
>         print(f"[SLACK {n['webhook']}] {msg}")
>     elif n["tipo"] == "arquivo":
>         open(n["caminho"], "a").write(msg + "\n")
> ```
>
> **Requisitos:** classe abstrata `Notificador` com método `enviar(msg)`; três subclasses; factory com dicionário; decorador `@registrar("nome")`; adicione um quarto canal (`"console"`) **sem tocar** em nenhum código existente.
>
> **Saída esperada:**
> ```text
> [EMAIL -> soc@empresa.com] IP 10.0.0.9 bloqueado
> [SLACK https://hooks.../x] IP 10.0.0.9 bloqueado
> [CONSOLE] IP 10.0.0.9 bloqueado
> canal 'telegram' -> ValueError: não suportado; use: ['arquivo', 'console', 'email', 'slack']
> ```
>
> **Pergunta em comentário (2 linhas):** quantos arquivos você precisou editar para adicionar o canal `console`? E no código ANTES, quantos seriam?

> **Exercício 1.2 — A factory com buraco:** a factory abaixo tem uma vulnerabilidade real. Encontre, explique e corrija.
>
> ```python
> # ANTES
> @app.get("/api/exportar")
> def exportar():
>     formato = request.args.get("formato", "json")
>     exportador = globals()[f"Exportador{formato.capitalize()}"]()
>     return exportador.gerar(buscar_incidentes())
> ```
>
> **Requisitos:** identifique o código OWASP 2025 correspondente em um comentário; reescreva com dicionário de registro; formato inválido devolve **400** com mensagem que lista os formatos válidos (e não vaza traceback); escreva um teste que prove que `?formato=../../etc` e `?formato=app` não derrubam nem instanciam nada.
>
> **Saída esperada:**
> ```text
> GET /api/exportar?formato=json  -> 200
> GET /api/exportar?formato=csv   -> 200
> GET /api/exportar?formato=app   -> 400 {"erro":"formato inválido","validos":["csv","json"]}
> ```

---

## Aula 2 — Singleton: a instância única (e por que ela te trai)

> **Duração:** 2 horas

### Introdução ao padrão

O **Singleton** é o padrão **criacional** mais conhecido e o menos recomendado. A proposta: garantir que uma classe tenha **exatamente uma** instância durante toda a execução, acessível de qualquer lugar.

**Intenção (GoF):** assegurar que uma classe tenha uma só instância e fornecer um ponto global de acesso a ela.

**Analogia:** a chave mestra do prédio. Existe uma só, e todo mundo pega a mesma. O problema é o mesmo da vida real — se alguém amassar a chave, todos ficam de fora, e não dá para saber quem mexeu nela por último.

**Onde você já viu:** o próprio sistema de módulos do Python. `import config` carrega o módulo uma única vez e todos compartilham o mesmo objeto — você já usa Singleton sem escrever nenhuma classe.

**O aviso desta aula:** esta é a única aula do módulo em que o veredicto é "aprenda para reconhecer, mas prefira outra coisa". Singleton é estado global com outro nome: contamina testes, esconde dependências e, quando guarda uma conexão de banco, pode virar falha de controle de acesso. Vamos implementá-lo corretamente, listar os quatro problemas que ele cria e terminar com quatro alternativas melhores.

**Objetivos**

- Implementar Singleton em Python de duas formas.
- Enumerar os quatro problemas que ele cria.
- Usar as alternativas: módulo, `lru_cache`, pool de conexões, injeção de dependência.

### 2.1 O problema

Visto em várias entregas do CP2:

```python
def conectar():
    return mysql.connector.connect(host="localhost", user="root",
                                   password=os.environ["MYSQL_PASSWORD"],
                                   database="securapy")
```

Cada rota chama `conectar()`. Com 15 rotas e 50 requisições por segundo, são 750 handshakes TCP + autenticação por segundo. A conexão custa caro; o natural é querer **uma só**.

### 2.2 O padrão

**Problema:** garantir que uma classe tenha exatamente uma instância, com ponto de acesso global.

```python
class Configuracao:
    _instancia = None

    def __new__(cls, *args, **kwargs):
        if cls._instancia is None:
            cls._instancia = super().__new__(cls)
            cls._instancia._iniciado = False
        return cls._instancia

    def __init__(self, caminho="config.json"):
        if self._iniciado:          # sem isso, __init__ roda em TODA chamada
            return
        self._iniciado = True
        self.dados = {"limite_falhas": 5, "janela_seg": 60}
        print(f"[config] carregado de {caminho}")


a = Configuracao()
b = Configuracao("outro.json")
print(a is b, b.dados["limite_falhas"])
```

```text
[config] carregado de config.json
True 5
```

Repare na pegadinha: `Configuracao("outro.json")` **não** carregou o outro arquivo. O argumento foi silenciosamente ignorado. Isso é bug esperando para acontecer.

### 2.3 Os quatro problemas

| Problema | O que acontece |
|---|---|
| **Estado global disfarçado** | Qualquer lugar do código pode alterar a instância. É variável global com paletó. |
| **Testes contaminados** | O teste A muda `limite_falhas`; o teste B herda a mudança. A ordem dos testes passa a importar. |
| **Dependência invisível** | `Configuracao()` dentro de uma função não aparece na assinatura. Você não sabe do que a função depende sem ler o corpo. |
| **Concorrência** | Duas threads podem passar pelo `if cls._instancia is None` ao mesmo tempo e criar duas instâncias. |

### 2.4 Nota de segurança

O caso grave é **conexão de banco compartilhada entre threads**:

```python
class Banco:                                  # PERIGOSO
    _inst = None
    def __new__(cls):
        if cls._inst is None:
            cls._inst = super().__new__(cls)
            cls._inst.con = mysql.connector.connect(...)
        return cls._inst
```

O cursor do MySQL não é thread-safe. Duas requisições simultâneas usando a mesma conexão podem receber o resultado uma da outra — a requisição da Ana recebe os incidentes do Bruno. Isso é **A01 — Broken Access Control** por acidente de arquitetura, e nenhum teste de autorização pega.

### 2.5 As alternativas (use estas)

**1. O módulo já é um singleton.** Python importa cada módulo uma vez:

```python
# config.py
dados = {"limite_falhas": 5, "janela_seg": 60}
```

```python
from config import dados      # mesma referência em todo lugar
```

**2. `lru_cache` para construção cara:**

```python
from functools import lru_cache

@lru_cache(maxsize=1)
def configuracao():
    return json.loads(open("config.json").read())
```

Uma linha, thread-safe, e `configuracao.cache_clear()` reseta no teste.

**3. Para conexão de banco: pool, não singleton.**

```python
from mysql.connector.pooling import MySQLConnectionPool
from contextlib import contextmanager

_pool = MySQLConnectionPool(pool_name="securapy", pool_size=5,
                            host="localhost", user="app",
                            password=os.environ["MYSQL_PASSWORD"],
                            database="securapy")

@contextmanager
def cursor():
    con = _pool.get_connection()
    cur = con.cursor(dictionary=True)
    try:
        yield cur
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        cur.close()
        con.close()      # devolve ao pool
```

Uma conexão por requisição, reaproveitada do pool. É o que você queria quando pensou em singleton.

**4. Injeção de dependência** — passe o objeto em vez de buscá-lo:

```python
class MotorDeRegras:
    def __init__(self, config):     # a dependência está na assinatura
        self.config = config
```

No teste: `MotorDeRegras({"limite_falhas": 2})`. Sem estado global, sem ordem de testes.

### 2.6 Quando NÃO usar

Praticamente sempre. Singleton é o padrão mais citado e o menos recomendado hoje. Se a resposta é "porque criar é caro", use `lru_cache` ou pool. Se é "porque todo mundo precisa acessar", passe como parâmetro.

### 2.7 Exercícios de refatoração

> **Exercício 2.1 — O Singleton que não é:** o código abaixo tem **dois** bugs. Encontre os dois e corrija.
>
> ```python
> # ANTES
> class Blacklist:
>     _instancia = None
>
>     def __new__(cls):
>         if cls._instancia is None:
>             cls._instancia = super().__new__(cls)
>         return cls._instancia
>
>     def __init__(self):
>         self.ips = set()
>
>     def bloquear(self, ip):
>         self.ips.add(ip)
>
>
> b1 = Blacklist(); b1.bloquear("10.0.0.1")
> b2 = Blacklist()
> print(b2.ips)     # esperado {'10.0.0.1'} — mas imprime set()
> ```
>
> **Requisitos:** explique em comentário por que `b2.ips` saiu vazio; corrija mantendo o Singleton; depois **reescreva sem Singleton** usando módulo ou injeção, e mostre que os dois testes abaixo passam em qualquer ordem.
>
> **Saída esperada:**
> ```text
> [singleton corrigido] b1 is b2: True | ips: {'10.0.0.1'}
> [sem singleton] teste_bloqueia OK
> [sem singleton] teste_comeca_vazia OK   <- este falhava com Singleton
> ```

> **Exercício 2.2 — Trocando Singleton por pool:** o SecuraPy abaixo compartilha uma conexão entre threads.
>
> ```python
> # ANTES
> class Banco:
>     _inst = None
>     def __new__(cls):
>         if cls._inst is None:
>             cls._inst = super().__new__(cls)
>             cls._inst.con = sqlite3.connect("securapy.db", check_same_thread=False)
>         return cls._inst
>     def consultar(self, sql, p=()):
>         return self._inst.con.cursor().execute(sql, p).fetchall()
> ```
>
> **Requisitos:** substitua por um pool simples (`queue.Queue` de conexões) + `@contextmanager`; `commit` no sucesso e `rollback` na exceção; dispare 20 threads inserindo ao mesmo tempo e prove que as 20 linhas entraram e nenhuma consulta recebeu resultado de outra.
>
> **Saída esperada:**
> ```text
> 20 threads disparadas
> linhas no banco: 20
> nenhuma leitura cruzada detectada
> ```
>
> **Pergunta em comentário (2 linhas):** qual código OWASP 2025 descreve o vazamento que o código ANTES podia causar?

---

## Aula 3 — Observer: um evento, vários interessados

> **Duração:** 2 horas

### Introdução ao padrão

O **Observer** (Observador) é um padrão **comportamental**: trata de como os objetos conversam entre si. Um objeto — o *sujeito* — avisa quando algo acontece; outros objetos — os *observadores* — se inscrevem para receber o aviso. O sujeito não sabe quem são nem quantos são.

**Intenção (GoF):** definir uma dependência um-para-muitos, de modo que quando um objeto muda de estado todos os dependentes sejam notificados automaticamente.

**Analogia:** a sirene de incêndio do prédio. Ela toca; quem reage — brigada, portaria, elevadores — é problema de cada um. A sirene não mantém lista de telefones nem espera resposta.

**Onde você já viu:** o módulo `logging` da biblioteca padrão é Observer puro — o `Logger` publica, os `Handler` observam, e você adiciona um `FileHandler` sem tocar em nenhuma chamada de `log.info()`. No front-end, `addEventListener` é a mesma ideia.

**A linha que importa:** num SIEM, o valor do padrão está no `try/except` dentro do laço de notificação. Um canal de alerta quebrado não pode derrubar os outros — e é exatamente isso que o Observer bem escrito garante.

**Objetivos**

- Desacoplar quem gera o alerta de quem reage a ele.
- Implementar Observer com classes e com callbacks.
- Entender por que o `try/except` dentro do laço de notificação é a linha mais importante do padrão.

### 3.1 O problema

```python
def alertar(evento):
    print(f"[ALERTA] {evento}")
    open("alertas.log", "a").write(f"{evento}\n")
    enviar_socket(evento)
    contador["total"] += 1
```

Para adicionar "mandar no Slack", você edita `alertar`. Para testar o motor de regras, você precisa de socket e arquivo. E se `enviar_socket` levantar exceção, o contador nunca incrementa — um canal quebrado derruba os outros.

### 3.2 O padrão

**Problema:** vários objetos precisam reagir a um evento, e o emissor não deveria conhecê-los.

```python
class CentralDeAlertas:
    def __init__(self):
        self._inscritos = []

    def inscrever(self, obs):
        self._inscritos.append(obs)
        return obs                       # permite usar como decorador

    def publicar(self, alerta: dict):
        for obs in self._inscritos:
            try:
                obs(alerta)
            except Exception as e:
                print(f"[central] observador {obs!r} falhou: {type(e).__name__}")
```

**O `try/except` é o coração do padrão.** Sem ele, um observador com bug derruba todos os outros — e num SIEM isso significa perder o alerta que importava porque o webhook do Slack caiu.

Os observadores, como funções:

```python
central = CentralDeAlertas()
contagem = {}


@central.inscrever
def console(a):
    print(f"[{a['severidade'].upper()}] {a['mensagem']}")


@central.inscrever
def arquivo(a):
    open("alertas.log", "a").write(f"{a['severidade']};{a['mensagem']}\n")


@central.inscrever
def contador(a):
    contagem[a["severidade"]] = contagem.get(a["severidade"], 0) + 1


@central.inscrever
def webhook_quebrado(a):
    raise ConnectionError("slack fora do ar")


central.publicar({"severidade": "critica", "mensagem": "brute force de 10.0.0.9"})
print(contagem)
```

```text
[CRITICA] brute force de 10.0.0.9
[central] observador <function webhook_quebrado at 0x...> falhou: ConnectionError
{'critica': 1}
```

O webhook caiu, o resto funcionou. É exatamente esse o comportamento que você quer às 3 da manhã.

### 3.3 Você já usa Observer

O módulo `logging` da biblioteca padrão é Observer: o `Logger` publica, os `Handler` são observadores, e você adiciona um `FileHandler` sem tocar em nenhuma chamada de `log.info()`.

### 3.4 Quando NÃO usar

- **Um observador só, para sempre.** Chamada direta é mais simples e aparece no stack trace.
- **Quando a ordem importa.** Observer não garante ordem de execução; se B depende de A, você está usando o padrão errado.
- **Quando o emissor precisa do resultado.** Observer é "avisei e segui"; se você precisa da resposta, é chamada de função.
- **Debug fica mais difícil.** Ler `publicar()` não diz o que vai acontecer — você precisa saber quem se inscreveu.

### 3.5 Exercícios de refatoração

> **Exercício 3.1 — Quebrando a função que faz tudo:**
>
> ```python
> # ANTES
> total_alertas = 0
>
> def processar_alerta(ip, tipo, severidade):
>     global total_alertas
>     print(f"[{severidade}] {tipo} de {ip}")
>     with open("alertas.log", "a") as f:
>         f.write(f"{severidade};{tipo};{ip}\n")
>     if severidade == "critica":
>         requests.post(SLACK_URL, json={"text": f"{tipo} de {ip}"})
>     total_alertas += 1
> ```
>
> **Requisitos:** `CentralDeAlertas` com `inscrever`/`publicar`; quatro observadores (console, arquivo, slack-só-se-crítica, contador); `try/except` por observador; adicione um quinto observador (blacklist automática) **sem editar** a central nem os outros; prove com um observador que levanta exceção de propósito que os demais continuam rodando.
>
> **Saída esperada:**
> ```text
> [CRITICA] brute_force de 10.0.0.9
> [central] observador 'slack' falhou: ConnectionError
> [blacklist] 10.0.0.9 adicionado
> total: 1 | criticas: 1
> ```

> **Exercício 3.2 — Observador lento não pode travar o SIEM:** um dos observadores leva 2 segundos (chamada HTTP). Com 50 alertas, o motor de regras para por 100 s.
>
> **Requisitos:** mantenha os observadores rápidos síncronos; coloque o observador lento atrás de uma `queue.Queue` consumida por uma thread daemon; `publicar()` deve voltar em menos de 10 ms mesmo com o lento inscrito; método `drenar()` que espera a fila esvaziar antes do programa encerrar.
>
> **Saída esperada:**
> ```text
> 50 alertas publicados em 0.01s
> fila do webhook: 50 pendentes
> drenando...
> webhook entregou 50/50
> ```
>
> **Pergunta em comentário (3 linhas):** se o processo morrer antes do `drenar()`, quantos alertas se perdem? Que código OWASP 2025 trata de falha de registro e monitoramento, e o que você faria para não perder nada?

---

## Aula 4 — Decorator: comportamento por cima da função

> **Duração:** 2 horas

### Introdução ao padrão

Cuidado com o nome: existem **dois** decorators e eles não são a mesma coisa. O **decorator do GoF** é um padrão **estrutural** — envolver um objeto em outro para acrescentar comportamento sem alterar a classe original. O **decorator do Python** é a sintaxe `@` — açúcar sintático para `f = decorador(f)`. Esta aula trata principalmente do segundo, que é o que vocês vão usar todo dia em Flask.

**Intenção (GoF):** acrescentar responsabilidades a um objeto dinamicamente, como alternativa flexível à herança.

**Analogia:** a capa de chuva. Você não fabrica uma "pessoa impermeável" — você envolve a pessoa numa capa. Quer refletivo também? Põe a faixa por cima. Cada camada acrescenta um comportamento e nenhuma reescreve a pessoa.

**Onde você já viu:** `@property`, `@staticmethod`, `@functools.lru_cache`, `@app.route` do Flask, `@pytest.fixture`.

**Por que isso é aula de segurança:** autenticação, autorização, auditoria e rate limit são exatamente o tipo de comportamento que se repete em toda rota — e repetir copiando é como ele acaba faltando em uma delas. Veremos também que a **ordem** dos decoradores pode deixar uma rota aberta sem gerar nenhum erro.

**Objetivos**

- Entender o que o `@` faz mecanicamente.
- Escrever decoradores com e sem argumentos, sempre com `functools.wraps`.
- Saber por que a **ordem** dos decoradores é questão de segurança.

### 4.1 O problema

```python
@app.get("/api/incidentes")
def listar():
    chave = request.headers.get("X-API-Key", "")
    analista = buscar_analista(chave)
    if analista is None:
        return jsonify({"erro": "não autenticado"}), 401
    if analista["nivel"] < 3:
        return jsonify({"erro": "acesso negado"}), 403
    log(f"{analista['id']} listou incidentes")
    return jsonify(buscar_incidentes())
```

Essas oito linhas de autenticação, autorização e auditoria se repetem em **todas** as rotas. Copiar e colar autorização é como ela acaba faltando em uma rota.

### 4.2 O que o `@` faz

Nada de mágico:

```python
@autenticado
def listar(): ...

# é exatamente isto:
def listar(): ...
listar = autenticado(listar)
```

Um decorador é uma função que recebe uma função e devolve outra.

```python
from functools import wraps


def autenticado(f):
    @wraps(f)                            # preserva __name__ e __doc__
    def dentro(*args, **kwargs):
        analista = buscar_analista(request.headers.get("X-API-Key", ""))
        if analista is None:
            return jsonify({"erro": "não autenticado"}), 401
        g.analista = analista
        return f(*args, **kwargs)
    return dentro
```

**`@wraps` não é cosmético.** Sem ele, toda função decorada passa a se chamar `dentro`. O Flask registra rotas pelo `__name__` da função — duas rotas decoradas sem `@wraps` colidem e o segundo `app.route` levanta erro de endpoint duplicado.

Com argumento, são três níveis:

```python
def requer_nivel(minimo):            # 1. recebe o argumento
    def decorador(f):                # 2. recebe a função
        @wraps(f)
        def dentro(*a, **kw):        # 3. recebe a chamada
            if g.analista["nivel"] < minimo:
                return jsonify({"erro": "acesso negado"}), 403
            return f(*a, **kw)
        return dentro
    return decorador
```

E a rota fica:

```python
@app.get("/api/incidentes")
@autenticado
@requer_nivel(3)
@auditado
def listar():
    return jsonify(buscar_incidentes())
```

### 4.3 A ordem importa — e é segurança

Decoradores aplicam de baixo para cima, e executam de cima para baixo. Essas duas rotas **não** são equivalentes:

```python
@app.get("/a")          # CERTO: o Flask registra a versão protegida
@autenticado
def a(): ...

@autenticado            # ERRADO: o Flask já registrou a versão SEM proteção
@app.get("/b")
def b(): ...
```

No segundo caso, `app.get` registrou a função crua antes de `autenticado` envolvê-la. A rota `/b` fica **aberta**, sem nenhum erro, sem nenhum aviso. `@app.route` sempre por último (mais acima). Esse bug não aparece em teste de caminho feliz — só em pentest.

### 4.4 Quando NÃO usar

- **Lógica específica de uma função só.** Decorador existe para o que se repete.
- **Quando o decorador precisa de muito contexto da função.** Se ele inspeciona argumentos por nome e posição, está acoplado demais.
- **Empilhar cinco decoradores.** O stack trace vira lasanha e ninguém sabe mais o que roda antes do quê.

### 4.5 Exercícios de refatoração

> **Exercício 4.1 — Extraindo os decoradores:** três rotas com o mesmo bloco copiado.
>
> ```python
> # ANTES
> @app.get("/api/incidentes")
> def listar():
>     a = buscar_analista(request.headers.get("X-API-Key",""))
>     if a is None: return jsonify({"erro":"não autenticado"}), 401
>     print(f"[audit] {a['id']} GET /api/incidentes")
>     return jsonify(TODOS)
>
> @app.post("/api/incidentes")
> def criar():
>     a = buscar_analista(request.headers.get("X-API-Key",""))
>     if a is None: return jsonify({"erro":"não autenticado"}), 401
>     if a["nivel"] < 3: return jsonify({"erro":"acesso negado"}), 403
>     print(f"[audit] {a['id']} POST /api/incidentes")
>     return jsonify({"criado": True}), 201
>
> @app.delete("/api/incidentes/<int:i>")
> def apagar(i):
>     a = buscar_analista(request.headers.get("X-API-Key",""))
>     if a["nivel"] < 5: return jsonify({"erro":"acesso negado"}), 403
>     print(f"[audit] {a['id']} DELETE /api/incidentes/{i}")
>     return jsonify({"removido": i})
> ```
>
> **Requisitos:** `@autenticado`, `@requer_nivel(n)` e `@auditado`, todos com `@wraps`; a rota `apagar` tem um **bug de segurança** no ANTES — encontre e corrija em comentário; teste com `app.test_client()` cobrindo sem chave, chave inválida, nível baixo e nível suficiente.
>
> **Saída esperada:**
> ```text
> GET    sem chave        -> 401
> POST   nivel 2          -> 403
> POST   nivel 3          -> 201
> DELETE sem chave        -> 401   <- no ANTES dava 500
> DELETE nivel 5          -> 200
> ```

> **Exercício 4.2 — A ordem que abre a porta:** o arquivo abaixo tem quatro rotas; **duas** estão desprotegidas por causa da ordem dos decoradores, e o servidor sobe sem reclamar.
>
> ```python
> # ANTES
> @app.get("/api/publico")
> def publico(): return jsonify({"ok": True})
>
> @autenticado
> @app.get("/api/privado")
> def privado(): return jsonify({"segredo": "x"})
>
> @app.get("/api/admin")
> @requer_nivel(5)
> @autenticado
> def admin(): return jsonify({"usuarios": TODOS})
>
> @app.get("/api/relatorio")
> @autenticado
> @requer_nivel(3)
> def relatorio(): return jsonify({"linhas": 42})
> ```
>
> **Requisitos:** identifique as duas rotas furadas e explique cada uma em comentário (uma é ordem de registro, a outra é ordem entre `@autenticado` e `@requer_nivel`); corrija; escreva um teste que percorre `app.url_map` e falha se alguma rota não-pública responder diferente de 401 sem chave.
>
> **Saída esperada:**
> ```text
> /api/publico     sem chave -> 200 (esperado, é público)
> /api/privado     sem chave -> 401
> /api/admin       sem chave -> 401   <- antes dava 500 (g.analista inexistente)
> /api/relatorio   sem chave -> 401
> auditoria de rotas: 4/4 corretas
> ```

---

## Aula 5 — Adapter e Facade: domando APIs externas

> **Duração:** 2 horas

### Introdução aos padrões

Esta aula junta dois padrões **estruturais** — que tratam de como compor objetos em estruturas maiores. Ambos resolvem o mesmo desconforto por ângulos diferentes: *o que está do outro lado não tem a cara que eu queria*.

**Adapter (Adaptador)**
**Intenção (GoF):** converter a interface de uma classe em outra interface que o cliente espera, permitindo que classes incompatíveis trabalhem juntas.
**Analogia:** o adaptador de tomada. O aparelho não muda, a tomada não muda — a peça no meio traduz.

**Facade (Fachada)**
**Intenção (GoF):** fornecer uma interface unificada e simples para um conjunto de interfaces de um subsistema.
**Analogia:** o painel do carro. Atrás dele há injeção eletrônica, câmbio e freios ABS; na sua frente há três pedais e um volante.

**A diferença em uma frase:** o Adapter envolve **um** objeto para mudar o formato dele; a Facade envolve **vários** para esconder a complexidade de todos. Um traduz, o outro simplifica.

**Onde você já viu:** `io.TextIOWrapper` adapta um fluxo de bytes para texto; `requests` é uma fachada sobre `urllib3`, sockets e TLS.

**Objetivos**

- Normalizar respostas de serviços diferentes atrás de uma interface só.
- Montar uma fachada que esconde um subsistema inteiro.
- Validar o que vem de fora na fronteira do adaptador.

### 5.1 O problema

Três serviços de reputação de IP, três formatos:

```python
# ipinfo
{"ip": "10.0.0.9", "org": "AS123 Acme", "country": "BR"}
# abuseipdb
{"data": {"ipAddress": "10.0.0.9", "abuseConfidenceScore": 87, "countryCode": "BR"}}
# base interna
("10.0.0.9", 3, "BR", "2026-01-10")
```

O código que consome vira um festival de `if fonte == ...`, e trocar de fornecedor significa caçar esses `if` pelo projeto inteiro.

### 5.2 Adapter

**Problema:** você quer usar uma classe/API cuja interface não é a que seu código espera.
**Solução:** um objeto no meio que traduz.

Primeiro, o formato que **o seu** sistema quer:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class Reputacao:
    ip: str
    score: int          # 0 a 100, sempre
    pais: str

    @property
    def suspeito(self) -> bool:
        return self.score >= 50
```

Os adaptadores:

```python
class AdaptadorIpinfo:
    def consultar(self, ip) -> Reputacao:
        r = api_ipinfo(ip)
        score = 70 if "hosting" in r.get("org", "").lower() else 10
        return Reputacao(r["ip"], score, r.get("country", "??"))


class AdaptadorAbuseIPDB:
    def consultar(self, ip) -> Reputacao:
        d = api_abuse(ip)["data"]
        return Reputacao(d["ipAddress"], int(d["abuseConfidenceScore"]), d["countryCode"])


class AdaptadorBaseInterna:
    def consultar(self, ip) -> Reputacao:
        ip_, nivel, pais, _ = buscar_interno(ip)
        return Reputacao(ip_, min(nivel * 25, 100), pais)
```

Quem consome não sabe de nenhum deles:

```python
def enriquecer(ip, fontes):
    for f in fontes:
        try:
            return f.consultar(ip)
        except Exception as e:
            print(f"[enriquecer] {type(f).__name__} falhou: {type(e).__name__}")
    return Reputacao(ip, 0, "??")
```

**Nota de segurança:** o adaptador é a fronteira entre o mundo externo e o seu sistema — é **ali** que se valida. Se `abuseConfidenceScore` vier `"muito alto"` ou `-1`, o `int()` estoura ou o score sai fora da faixa, e `suspeito` passa a mentir. Valide a faixa dentro do adaptador, não no consumidor.

### 5.3 Facade

**Problema:** usar um subsistema exige conhecer seis classes e a ordem certa de chamá-las.
**Solução:** uma classe com poucos métodos que esconde tudo.

```python
class SecuraPy:
    """Fachada: três métodos escondem coletor, parsers, motor e alertas."""

    def __init__(self, config="config.json"):
        self._parsers = [criar_parser(t) for t in ("ssh", "apache", "firewall")]
        self._motor = MotorDeRegras(carregar_regras(config))
        self._central = CentralDeAlertas()
        self._central.inscrever(SaidaConsole())

    def analisar(self, caminho) -> int:
        eventos = [c for linha in open(caminho)
                   for p in self._parsers
                   if (c := p.campos(linha)) is not None]
        alertas = self._motor.aplicar(eventos)
        for a in alertas:
            self._central.publicar(a)
        return len(alertas)

    def resumo(self) -> dict:
        return self._motor.estatisticas()
```

O `main.py` inteiro vira:

```python
siem = SecuraPy()
print(siem.analisar("auth.log"), "alertas")
print(siem.resumo())
```

| | Adapter | Facade |
|---|---|---|
| **Intenção** | traduzir uma interface | simplificar um subsistema |
| **Tamanho** | envolve 1 objeto | envolve N objetos |
| **Interface** | definida por quem consome | inventada pela fachada |

### 5.4 Quando NÃO usar

- **Adapter com uma fonte só, para sempre.** Você criou uma camada para traduzir de A para A.
- **Facade que só repassa.** Se cada método da fachada chama um método de um objeto e mais nada, ela não esconde complexidade — só adiciona um salto.
- **Facade que vira deus.** Fachada com 30 métodos virou a classe-monolito que você queria evitar.

### 5.5 Exercícios de refatoração

> **Exercício 5.1 — Normalizando três fontes:**
>
> ```python
> # ANTES
> def checar_ip(ip, fonte):
>     if fonte == "ipinfo":
>         r = api_ipinfo(ip)
>         return {"ip": r["ip"], "risco": 70 if "hosting" in r["org"] else 10}
>     elif fonte == "abuse":
>         d = api_abuse(ip)["data"]
>         return {"ip": d["ipAddress"], "risco": d["abuseConfidenceScore"]}
>     elif fonte == "interna":
>         t = buscar_interno(ip)
>         return {"ip": t[0], "risco": t[1] * 25}
> ```
>
> **Requisitos:** `@dataclass(frozen=True) Reputacao` com propriedade `suspeito`; três adaptadores; `enriquecer(ip, fontes)` que tenta em ordem e cai para a próxima em caso de exceção; **valide no adaptador** que `score` é inteiro entre 0 e 100, levantando `ValueError` se não for; use dublês (funções fake) para não depender de rede.
>
> **Saída esperada:**
> ```text
> 10.0.0.9  -> score 87  suspeito=True   (AdaptadorAbuseIPDB)
> 8.8.8.8   -> score 10  suspeito=False  (AdaptadorIpinfo)
> [enriquecer] AdaptadorAbuseIPDB falhou: ConnectionError
> 10.0.0.9  -> score 75  suspeito=True   (AdaptadorBaseInterna)
> score inválido 'muito alto' -> ValueError na fronteira, não no consumidor
> ```

> **Exercício 5.2 — A fachada do SIEM:** o `main.py` abaixo tem 40 linhas e conhece seis classes.
>
> ```python
> # ANTES
> parsers = [ParserSSH(), ParserApache(), ParserFirewall()]
> regras = json.load(open("regras.json"))
> motor = MotorDeRegras(regras)
> central = CentralDeAlertas()
> central.inscrever(SaidaConsole())
> central.inscrever(SaidaArquivo("alertas.log"))
> eventos = []
> for linha in open("auth.log"):
>     for p in parsers:
>         c = p.campos(linha)
>         if c: eventos.append(c); break
> for a in motor.aplicar(eventos):
>     central.publicar(a)
> print(motor.estatisticas())
> ```
>
> **Requisitos:** classe `SecuraPy` com `analisar(caminho)` e `resumo()`; o `main.py` final tem no máximo **4 linhas**; a fachada aceita injetar a central no construtor (para o teste usar uma central que só conta); escreva um teste da fachada sem nenhum arquivo em disco (use `io.StringIO` ou `tmp_path`).
>
> **Saída esperada:**
> ```text
> $ python main.py auth.log
> 3 alertas gerados
> {'eventos': 120, 'alertas': 3, 'regras_disparadas': ['brute_force', 'port_scan']}
> ```
>
> **Pergunta em comentário (2 linhas):** a fachada **esconde** as classes internas ou **impede** o acesso a elas? Se alguém precisar de um parser customizado, o que você faz sem quebrar o encapsulamento?

---

## Aula 6 — Repository: o domínio não conhece o banco

> **Duração:** 2 horas

### Introdução ao padrão

O **Repository** (Repositório) não é do catálogo original do GoF — vem de Martin Fowler e do Domain-Driven Design de Eric Evans. É um padrão **arquitetural**: ele não organiza classes dentro de um módulo, organiza as **camadas** do sistema.

**Intenção (Fowler):** mediar entre o domínio e a camada de persistência usando uma interface que se parece com uma coleção em memória.

**Analogia:** o balcão da biblioteca. Você pede "o livro tal"; se o livro está na estante, no subsolo ou veio de outra unidade por empréstimo não muda em nada o seu pedido.

**O que muda na prática:** a regra de negócio passa a falar `repo.buscar(id)` em vez de `SELECT ... WHERE id = %s`. Com isso, a mesma regra roda contra MySQL em produção e contra um `dict` no teste — e aí a pergunta "um analista de nível 2 consegue apagar o incidente de outro?" vira um teste de quatro linhas que roda em milissegundos, sem Docker e sem banco no ar.

**Bônus de segurança:** se todo SQL vive em um único arquivo, auditar o projeto contra SQL Injection deixa de ser caçada e vira leitura de um arquivo só.

**Objetivos**

- Separar regra de negócio de tecnologia de persistência.
- Escrever um repositório com implementação real e implementação em memória.
- Testar autorização **sem banco nenhum**.

### 6.1 O problema

```python
@app.delete("/api/incidentes/<int:iid>")
@autenticado
def apagar(iid):
    con = conectar_mysql(); cur = con.cursor(dictionary=True)
    cur.execute("SELECT dono_id FROM incidentes WHERE id = %s", (iid,))
    inc = cur.fetchone()
    if inc is None:
        return jsonify({"erro": "não encontrado"}), 404
    if g.analista["nivel"] < 5:
        return jsonify({"erro": "acesso negado"}), 403
    cur.execute("DELETE FROM incidentes WHERE id = %s", (iid,))
    con.commit(); con.close()
    return jsonify({"removido": iid})
```

A rota faz quatro coisas: conecta, escreve SQL, decide autorização e monta HTTP. Consequência prática: a pergunta "nível 2 consegue apagar?" é de **negócio**, mas para respondê-la você precisa subir um MySQL.

### 6.2 O padrão

**Solução:** uma interface que parece uma coleção em memória. Quem usa chama `repo.buscar(id)` — se por trás é MySQL, SQLite ou um `dict`, não é problema dele.

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Incidente:
    id: int | None
    dono_id: int
    titulo: str
    severidade: str


class RepositorioIncidentes(ABC):
    @abstractmethod
    def buscar(self, iid) -> Incidente | None: ...
    @abstractmethod
    def salvar(self, inc) -> Incidente: ...
    @abstractmethod
    def remover(self, iid) -> bool: ...
```

Note o vocabulário: `buscar`, `salvar`, `remover`. Nada de `SELECT` ou `rowcount` — a interface fala a língua do domínio.

```python
class RepositorioMySQL(RepositorioIncidentes):
    """O ÚNICO arquivo do sistema que escreve SQL."""

    def __init__(self, pool):
        self.pool = pool

    def buscar(self, iid):
        with self.pool.cursor() as cur:
            cur.execute("SELECT id, dono_id, titulo, severidade "
                        "FROM incidentes WHERE id = %s", (iid,))
            l = cur.fetchone()
        return Incidente(**l) if l else None

    def remover(self, iid):
        with self.pool.cursor() as cur:
            cur.execute("DELETE FROM incidentes WHERE id = %s", (iid,))
            return cur.rowcount > 0


class RepositorioEmMemoria(RepositorioIncidentes):
    def __init__(self, iniciais=()):
        self._d = {i.id: i for i in iniciais}

    def buscar(self, iid):
        return self._d.get(iid)

    def remover(self, iid):
        return self._d.pop(iid, None) is not None
```

A regra de negócio, agora sem saber o que é banco nem o que é HTTP:

```python
class AcessoNegado(Exception): ...
class NaoEncontrado(Exception): ...


class ServicoIncidentes:
    NIVEL_ADMIN = 5

    def __init__(self, repo):
        self.repo = repo

    def ver(self, analista, iid):
        inc = self.repo.buscar(iid)
        if inc is None or inc.dono_id != analista["id"]:
            # 403 antes de 404: não revelar se o id existe
            if analista["nivel"] >= self.NIVEL_ADMIN and inc is None:
                raise NaoEncontrado()
            raise AcessoNegado()
        return inc
```

E a rota encolhe para o que sempre deveria ter sido:

```python
@app.get("/api/incidentes/<int:iid>")
@autenticado
def obter(iid):
    try:
        return jsonify(asdict(servico.ver(g.analista, iid)))
    except AcessoNegado:
        return jsonify({"erro": "acesso negado"}), 403
    except NaoEncontrado:
        return jsonify({"erro": "não encontrado"}), 404
```

### 6.3 O ganho: testes em milissegundos

```python
ana, bruno = {"id": 1, "nivel": 5}, {"id": 2, "nivel": 2}

def servico_teste():
    return ServicoIncidentes(RepositorioEmMemoria([
        Incidente(1, 1, "Brute force SSH", "critica"),
        Incidente(2, 2, "Phishing no RH", "media"),
    ]))

assert servico_teste().ver(ana, 1).titulo == "Brute force SSH"

try:
    servico_teste().ver(bruno, 1); assert False
except AcessoNegado:
    print("[OK] não-dono recebe AcessoNegado")

try:
    servico_teste().ver(bruno, 999); assert False
except AcessoNegado:
    print("[OK] id inexistente não revela existência")
```

```text
[OK] não-dono recebe AcessoNegado
[OK] id inexistente não revela existência
```

Sem Docker, sem MySQL, sem Flask, em centésimos de segundo. **A matriz inteira de controle de acesso virou três testes que você roda a cada salvamento.**

### 6.4 Nota de segurança

1. **A parametrização fica confinada.** Se todo SQL está em `RepositorioMySQL`, auditar o projeto contra SQL Injection é ler **um** arquivo, e um `grep` por `execute(f"` fora dele vira alarme automático.
2. **A projeção de colunas também.** `buscar` lista as colunas; nunca `SELECT *`. É o lugar certo para garantir que a coluna `senha` nunca saia do banco.
3. **A autorização fica testável.** O bug mais comum do CP2 — 404 antes de 403 — é invisível na rota e vira teste de quatro linhas no serviço.

### 6.5 Quando NÃO usar

- **Script de uso único.** Para um `.py` que roda uma vez, é burocracia.
- **Quando você já usa um ORM.** O `Session` do SQLAlchemy e o `Model` do Django já **são** repositórios.
- **Quando o serviço só repassa.** Se `ServicoX.salvar` só chama `repo.salvar`, você escreveu a mesma camada duas vezes.

### 6.6 Exercícios de refatoração

> **Exercício 6.1 — Extraindo o repositório:**
>
> ```python
> # ANTES
> @app.get("/api/incidentes/<int:iid>")
> def obter(iid):
>     chave = request.headers.get("X-API-Key", "")
>     con = conectar(); cur = con.cursor(dictionary=True)
>     cur.execute("SELECT id, nivel FROM analistas WHERE api_key = %s", (chave,))
>     analista = cur.fetchone()
>     if analista is None:
>         con.close(); return jsonify({"erro": "não autenticado"}), 401
>     cur.execute("SELECT * FROM incidentes WHERE id = %s", (iid,))
>     inc = cur.fetchone(); con.close()
>     if inc is None: return jsonify({"erro": "não encontrado"}), 404
>     if inc["dono_id"] != analista["id"]: return jsonify({"erro": "negado"}), 403
>     return jsonify(inc)
> ```
>
> **Requisitos:** `RepositorioIncidentes` abstrato + `RepositorioEmMemoria` + uma implementação real (SQLite serve); `ServicoIncidentes.ver()` com exceções de domínio; a rota só traduz exceção em status; **corrija de passagem** o `SELECT *` e a ordem 404-antes-de-403.
>
> **Saída esperada:**
> ```text
> [OK] dono vê o próprio incidente
> [OK] não-dono -> AcessoNegado
> [OK] id inexistente, usuário comum -> AcessoNegado (não revela existência)
> [OK] id inexistente, admin -> NaoEncontrado
> tempo total: 0.00s
> ```

> **Exercício 6.2 — Trocando o banco sem tocar na regra:** usando o resultado do 6.1, escreva um `RepositorioSQLite` com a **mesma** interface.
>
> **Requisitos:** `sqlite3` da biblioteca padrão (atenção: o placeholder é `?`, não `%s`); **nenhuma linha** de `ServicoIncidentes` nem dos testes pode mudar; rode a mesma bateria contra as duas implementações num laço.
>
> **Saída esperada:**
> ```text
> === RepositorioEmMemoria ===  4/4 testes OK
> === RepositorioSQLite ===     4/4 testes OK
> ```
>
> **Pergunta em comentário (2 linhas):** o placeholder mudou de `%s` para `?`. Por que isso **não** vazou para o serviço nem para os testes? O que teria acontecido se o SQL estivesse na rota?

---

## Referências

- GAMMA, E.; HELM, R.; JOHNSON, R.; VLISSIDES, J. **Design Patterns: Elements of Reusable Object-Oriented Software.** Addison-Wesley, 1994.
- FREEMAN, E.; ROBSON, E. **Head First Design Patterns.** 2. ed. O'Reilly, 2020.
- FOWLER, Martin. **Refactoring: Improving the Design of Existing Code.** 2. ed. Addison-Wesley, 2018.
- FOWLER, Martin. **Patterns of Enterprise Application Architecture.** Addison-Wesley, 2002. (Repository, p. 322)
- PERCIVAL, H.; GREGORY, B. **Architecture Patterns with Python.** O'Reilly, 2020. Disponível em https://www.cosmicpython.com/
- Python Software Foundation. **`functools`, `abc`, `dataclasses`, `contextlib`, `sqlite3`, `queue`.** https://docs.python.org/3/library/
- OWASP. **OWASP Top 10:2025.** https://owasp.org/Top10/
