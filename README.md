# Artifact Hash Guard · Java

[![Tests](https://github.com/alefkaue/artifact-hash-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/alefkaue/artifact-hash-guard/actions/workflows/tests.yml)

Verificador offline de integridade de artefatos com **Java e SHA-256**. Compara arquivos com hashes esperados em um manifesto, identificando conteúdo divergente ou arquivo ausente. Não modifica os artefatos.

## Executar

Requer JDK 21 ou superior. Somente biblioteca padrão; não depende de Maven, Gradle ou bibliotecas externas.

```console
git clone https://github.com/alefkaue/artifact-hash-guard.git
cd artifact-hash-guard
javac -encoding UTF-8 --release 21 -d out src/ArtifactHashGuard.java tests/ArtifactHashGuardTest.java
java -cp out ArtifactHashGuardTest
jar --create --file artifact-hash-guard.jar --main-class ArtifactHashGuard -C out .
java -jar artifact-hash-guard.jar verify examples/checksums.sha256 examples/artifacts
```

Saída esperada do exemplo:

```text
OK	demo.txt
SUMMARY	checked=1	failed=0
```

Altere o conteúdo de `examples/artifacts/demo.txt` e execute novamente: aparece `MISMATCH`, com código de saída 1. Remova o arquivo para observar `MISSING`. Reponha o conteúdo original para restaurar o resultado OK.

## Manifesto

Cada linha contém SHA-256 hexadecimal de 64 caracteres, **dois espaços** e um caminho relativo com separador `/`. Linhas vazias e comentários iniciados por `#` são ignorados. O manifesto é UTF-8, sem BOM, limitado a 1 MiB. Use hashes obtidos de uma fonte confiável e mantenha o manifesto protegido separadamente dos arquivos.

```text
<sha256 de 64 caracteres>  releases/app.jar
```

O exemplo `demo.txt` usa LF inclusive em checkout Windows, configurado em `.gitattributes`, para manter o hash reproduzível. Nomes com espaços são aceitos; caminhos absolutos, segmentos `.`/`..`, barras invertidas, dois-pontos, controles e entradas duplicadas são rejeitados.

## Saída e códigos

Relatório de texto tabulado em stdout; erros em stderr. `OK`, `MISMATCH` ou `MISSING` por arquivo e uma linha `SUMMARY` ao final.

- **0:** todos os arquivos declarados conferem.
- **1:** pelo menos um arquivo ausente ou com hash diferente.
- **2:** uso inválido, manifesto inválido, erro de acesso, link simbólico ou arquivo alterado durante leitura.

Saída parcial pode existir antes de um erro de leitura; só considere o resultado completo após verificar o código de saída. Arquivos adicionais que não estejam no manifesto não são inventariados nem sinalizados.

## Decisões e limites

O parser valida o manifesto antes da leitura dos artefatos. A ferramenta verifica os componentes dos caminhos e recusa links simbólicos; lê arquivos em blocos de 64 KiB; compara tamanho, data de modificação e identidade antes/depois da leitura. Não segue links no arquivo final durante a abertura.

Essas verificações não substituem isolamento contra corridas em diretórios controlados por um atacante. Junctions/reparse points, sistemas de arquivos remotos e alterações concorrentes exigem avaliação específica. Use uma árvore estável, com diretórios ancestrais confiáveis, ou snapshot anterior.

SHA-256 verifica correspondência de conteúdo; **não comprova autoria, assinatura digital ou ausência de malware**. Se o manifesto também for adulterado, a ferramenta não distingue uma substituição autorizada de uma maliciosa. Não implementa verificação de assinatura JAR.

## Testes e evolução

O runner de integração usa arquivos temporários e verifica integridade, divergência, ausência, caminhos inseguros, duplicatas, manifesto inválido e links simbólicos. Sem permissão para criar links, esse caso é explicitamente ignorado. CI: Windows/Linux, JDK 21/25.

Próxima evolução: manifestos assinados e formato de relatório JSON. Projeto educacional independente, desenvolvido com assistência de IA. Licença MIT.
