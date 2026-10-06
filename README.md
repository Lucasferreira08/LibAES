# Criptografia de arquivos com AES-CBC

Programa de terminal em Python que **cifra** e **decifra** arquivos de qualquer
formato (PDF, ZIP, DOC, imagens, executáveis...) usando **AES em modo CBC**.
A chave AES é derivada da senha informada usando **PBKDF2-HMAC-SHA256**.

## Requisitos

- Python 3.8 ou superior
- Biblioteca [`cryptography`](https://cryptography.io)

## Instalação

```bash
pip install -r requirements.txt
# ou
pip install cryptography
```

## Uso

```
python aes_cbc.py <arquivo> [chave] [-m {cifrar,decifrar}] [-b {128,192,256}] [-o SAIDA] [-f]
```

| Parâmetro        | Descrição                                                                 |
|------------------|---------------------------------------------------------------------------|
| `arquivo`        | Caminho do arquivo de entrada (obrigatório)                               |
| `chave`          | String da chave/senha. Se omitida, é pedida sem eco no terminal           |
| `-m, --modo`     | `cifrar` ou `decifrar`. Se omitido, um menu pergunta ao usuário           |
| `-b, --bits`     | Tamanho da chave AES ao cifrar: 128, 192 ou 256 (padrão 256)              |
| `-o, --saida`    | Arquivo de saída (padrão: `<arquivo>.enc` ao cifrar; remove `.enc` ao decifrar) |
| `-f, --forcar`   | Sobrescreve o arquivo de saída se já existir                              |

### Exemplos

Cifrar (com menu interativo para escolher a operação):

```
$ python aes_cbc.py relatorio.pdf "minha senha secreta"
Escolha a operação:
  1) Cifrar
  2) Decifrar
> 1
Arquivo cifrado com sucesso: relatorio.pdf.enc
```

Cifrar direto, com chave de 128 bits:

```bash
python aes_cbc.py fotos.zip "minha senha" -m cifrar -b 128
```

Decifrar:

```bash
python aes_cbc.py fotos.zip.enc "minha senha" -m decifrar -o fotos_recuperadas.zip
```

Sem passar a chave na linha de comando (mais seguro, não fica no histórico do shell):

```bash
python aes_cbc.py contrato.docx -m cifrar
Chave: ********
```

Ao decifrar não é preciso informar `-b`: o tamanho da chave fica gravado no
cabeçalho do arquivo cifrado. Se a senha estiver errada ou o arquivo tiver sido
alterado, o programa avisa e não gera saída.

## Como funciona

1. Gera um **salt** aleatório de 16 bytes e um **IV** aleatório de 16 bytes
   (`os.urandom`, gerador criptograficamente seguro).
2. Deriva da senha, com **PBKDF2-HMAC-SHA256 (600.000 iterações)**, a chave AES
   (16/24/32 bytes) e uma chave separada de 32 bytes para HMAC.
3. Aplica **padding PKCS#7** e cifra com **AES-CBC**.
4. Calcula um **HMAC-SHA256** sobre cabeçalho + salt + IV + texto cifrado
   (Encrypt-then-MAC). O CBC sozinho não garante integridade; o HMAC detecta
   senha errada e qualquer adulteração (evitando ataques de *padding oracle*).

Formato do arquivo gerado:

```
"AESC"(4) | tam. chave em bytes(1) | iterações(4) | salt(16) | IV(16) | texto cifrado(n·16) | HMAC(32)
```

## Pergunta: qual a melhor maneira de derivar uma string em uma chave de 128, 192 ou 256 bits?

**Usar uma função de derivação de chave baseada em senha (Password-Based KDF)
com salt aleatório e alto custo computacional** — e nunca usar a string
diretamente nem um hash simples.

### O que NÃO fazer

- **Usar os bytes da string diretamente** (truncando ou completando com zeros):
  a chave fica com pouquíssima entropia (só caracteres imprimíveis, previsíveis)
  e senhas curtas viram chaves fracas.
- **Fazer só `SHA-256(senha)`**: o resultado tem o tamanho certo, mas é
  rápido demais — um atacante testa bilhões de senhas por segundo em GPU — e,
  sem salt, a mesma senha gera sempre a mesma chave, permitindo
  *rainbow tables* pré-computadas.

### O que fazer

Uma KDF de senha resolve os dois problemas:

- **Salt aleatório** (≥ 16 bytes, armazenado junto ao arquivo cifrado, não é
  segredo): a mesma senha gera chaves diferentes em cada arquivo e inviabiliza
  tabelas pré-computadas.
- **Fator de trabalho** (iterações / memória): torna cada tentativa de senha
  cara, retardando ataques de força bruta e dicionário.
- **Tamanho de saída configurável**: gera exatamente 16, 24 ou 32 bytes
  (128/192/256 bits) — ou mais, para derivar chaves extras (como a do HMAC).

Opções recomendadas, da mais moderna para a mais tradicional:

| KDF          | Observações                                                                 |
|--------------|-----------------------------------------------------------------------------|
| **Argon2id** | Vencedor da Password Hashing Competition (2015), RFC 9106. *Memory-hard*: resiste bem a GPUs/ASICs. Primeira escolha atual (OWASP). |
| **scrypt**   | Também *memory-hard* (RFC 7914). Boa alternativa.                           |
| **PBKDF2**   | Padrão NIST (SP 800-132), RFC 8018. Disponível na biblioteca padrão de praticamente todas as linguagens. Não é memory-hard, então exige muitas iterações (OWASP: ≥ 600.000 com HMAC-SHA256). |

Este programa usa **PBKDF2-HMAC-SHA256** por estar disponível na biblioteca
padrão do Python (`hashlib.pbkdf2_hmac`) e ser o padrão NIST. Trocá-lo por
Argon2id (ex.: pacote `argon2-cffi`) seria uma melhoria direta.

> Observação: se a "chave" já fosse um segredo de alta entropia (ex.: 32 bytes
> aleatórios), e não uma senha humana, bastaria uma KDF rápida como **HKDF**
> (RFC 5869). Para senhas digitadas por pessoas, use sempre uma KDF lenta como as
> acima.
