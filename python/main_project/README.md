# Info

Skripten är testade med:
- pynacl: 1.5.0
- rich: 13.9.2
- argparse: 1.4.0
- dnsdumpster: 0.10
- openpyxl: 3.1.5

och Python 3.12.5 py Windows 11.

Cryptonite och SDE innehåller båda en GUI, och CLI parser. Du kan komma åt skripten och READMEs genom mapparna
eller kör dom från main.py här.

Cryptonite och SDE har båda lite mer avancerade funktioner, ex. att generera och kompilera en .c fil som krypterar shellcode och sedan dekrypterar och kör koden under runtime, eller att SDE genererar en lista med subdomäner utifrån en inofficiel DNSDumpster API, och sedan testar mot dem m.h.a en ThreadPool (dock är den seg).

Jag valde att fokusera på dessa två verktyg mer då jag hade lite idétorka och kända att jag hade intressanta funktioner som visade min kunskap väl.


**OBS: VINS la jag till bara för att utöka main skriptet, det är bara inte en del av inlämningen.**
