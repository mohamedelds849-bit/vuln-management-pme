# LEARN — Gestion des vulnérabilités basée sur le risque (à lire en entier avant un entretien)

## 1. Le projet en une minute (pitch oral)

« Un scanner de vulnérabilités, c'est facile à lancer et ça donne des milliers de lignes. La
vraie question d'une entreprise, c'est : *lesquelles je corrige cette semaine ?* J'ai construit
un pipeline qui répond à ça pour une PME fictive. Il prend les scans Trivy de sa pile web
(nginx, WordPress, MariaDB : de vraies images publiques), il ajoute deux signaux publics qui
disent si une faille est vraiment exploitée, le catalogue KEV de la CISA et le score EPSS,
puis il décide une priorité et un délai avec un arbre inspiré de SSVC, en tenant compte de
l'exposition de chaque actif. Il garde la mémoire d'un run à l'autre : date de détection,
échéance, date de correction, délai moyen. Il sort un rapport pour le dirigeant, un CSV de
tickets pour l'hébergeur, les exceptions en OpenVEX, et une CI qui passe au rouge quand un
P1 est en retard.

Sur le vrai run : 9 540 lignes de scanner, 5 lignes P1, qui sont en fait une seule CVE
OpenSSL à corriger sur deux images. Et 65 % du bruit venait d'un seul paquet, les en-têtes
du noyau dans l'image WordPress, documenté par une exception avec un propriétaire et une date
d'expiration. »

## 2. Les mots à connaître

| Mot | Explication simple |
|---|---|
| **CVE** | Identifiant public d'une faille (CVE-2025-15467). Une CVE touche un logiciel ; le scanner la retrouve sur chaque *paquet* qui contient ce logiciel, d'où plusieurs lignes pour une même CVE. |
| **CVSS** | Score de gravité *technique* de 0 à 10 (ce que la faille permet si on l'exploite). Ne dit pas si quelqu'un l'exploite. |
| **EPSS** | Probabilité (0 à 1) que la CVE soit exploitée dans les 30 jours, calculée chaque jour par FIRST à partir de données réelles d'attaques. 0,52 = 52 %. Le percentile dit où elle se place parmi toutes les CVE. |
| **KEV** | « Known Exploited Vulnerabilities » : liste de la CISA (agence américaine) des CVE *dont l'exploitation a été observée*. 1 739 entrées en octobre 2026. Être dans le KEV, c'est une certitude ; ne pas y être ne prouve rien. |
| **SSVC** | Méthode de décision de la CISA : au lieu d'un score, un arbre de questions (exploitée ? exposée ? impact ?) qui aboutit à une action : Track, Track*, Attend, Act. |
| **SLA** | Délai maximum de correction qu'on se fixe, par niveau de priorité (ici 7, 30, 90, 180 jours). |
| **Trivy** | Scanner open source (Aqua) qui lit une image de conteneur ou un dossier, liste les paquets et les croise avec les bases de CVE. Sort du JSON. |
| **Image de conteneur** | Un « paquet » complet d'un logiciel et de son système (ex. `wordpress:6.8-php8.2-apache` = Debian + Apache + PHP + WordPress). Les hébergeurs modernes font tourner ça. |
| **linux-libc-dev** | Paquet Debian contenant les *en-têtes* du noyau (fichiers `.h` pour compiler). Il ne contient pas le noyau : un conteneur utilise le noyau de la machine hôte. Le scanner lui attribue pourtant toutes les CVE noyau. |
| **VEX / OpenVEX** | « Vulnerability Exploitability eXchange » : format standard pour dire « cette CVE est signalée sur ce produit mais ne s'applique pas, voici pourquoi ». OpenVEX est la version JSON ouverte. |
| **Ledger (registre)** | Fichier JSON qui garde chaque faille avec sa date de première détection, son échéance, sa date de correction. Sans lui, pas de notion de retard ni de délai moyen. |
| **MTTR** | Mean Time To Remediate : délai moyen entre détection et correction, par priorité. |
| **Gate (porte) CI** | Règle qui met le job GitHub Actions en rouge (P1 en retard, nouveau P1 sur un actif Internet). |

## 3. Comment ça marche, étape par étape

1. **Scanner.** `trivy image nginx:1.27 --format json` : Trivy télécharge l'image depuis le
   registre (pas besoin de Docker), liste les paquets Debian et sort une ligne par (CVE,
   paquet) avec la version installée, la version corrigée s'il y en a une, la sévérité et le
   CVSS. `scripts/slim_scan.py` enlève les descriptions (39 Mo → 4 Mo pour WordPress).
2. **Normaliser** (`vmp/ingest.py`). Chaque ligne devient un `Finding` : actif, CVE, paquet,
   versions, CVSS v3 (NVD d'abord), statut distribution (`fixed`, `affected`, `will_not_fix`).
   Clé unique = actif | CVE | paquet.
3. **Enrichir** (`vmp/feeds.py`). Le KEV (JSON) et l'EPSS (CSV du jour) sont téléchargés une
   fois ; chaque finding reçoit `kev = oui/non` et `epss = probabilité`. Si un flux a plus de
   7 jours, le rapport le dit.
4. **Décider** (`vmp/decide.py`). Trois axes + la criticité de l'actif :
   exploitation (KEV → *active* ; EPSS ≥ 10 % → *likely* ; sinon *unlikely*),
   exposition (Internet / interne / isolé, écrite dans `policy.yml`),
   impact (CVSS ≥ 9 ou CRITICAL → *total* ; ≥ 7 ou HIGH → *élevé* ; sinon *partiel*).
   Huit règles lues de haut en bas donnent P1 à P4, chacune avec sa phrase « pourquoi ».
5. **Exceptions** (`vmp/policy.py`). Une exception = CVE (ou `*` + paquet), statut,
   propriétaire, justification d'au moins 5 mots, date d'expiration. Sans l'un des cinq, le
   pipeline refuse la politique. Expirée, la faille rouvre.
6. **Registre** (`vmp/ledger.py`). Nouvelle faille → `first_seen` = aujourd'hui, `due` =
   aujourd'hui + SLA. Revue → `last_seen`. Absente d'un actif *scanné* → `fixed`, délai
   calculé. Priorité aggravée (CVE entrée au KEV) → échéance raccourcie, jamais rallongée.
7. **Sorties** (`vmp/report.py`). `report.html` : l'essentiel pour la direction, par actif,
   suivi dans le temps, annexe technique, exceptions, méthode. `tickets.csv` : une ligne par
   mise à jour de paquet (une mise à jour ferme N CVE). `openvex.json`. `summary.json`.
8. **Gate** (`vmp/gate.py`). Le code de sortie de `python -m vmp run` est 1 si une règle
   `fail_on` est vraie : la CI devient rouge sans script en plus.

## 4. L'histoire du bruit noyau (à raconter, c'est le cœur de l'entretien)

Premier run : 9 540 lignes, dont 3 au KEV. Je regarde les 3 : toutes des CVE du **noyau
Linux** (CVE-2026-31431, -53266, -53362), toutes sur le paquet `linux-libc-dev` de l'image
WordPress. Ce paquet ne contient que des en-têtes pour compiler ; aucun code noyau ne
s'exécute depuis une image, un conteneur tourne sur le noyau de l'hôte. Donc dans *cette*
image, ces CVE ne s'appliquent pas, et c'est l'hébergeur qui doit patcher son noyau.

Si je supprime ces lignes dans le code, personne ne le saura et dans six mois on ne saura plus
pourquoi. J'ai donc ajouté les **exceptions au niveau composant** dans `policy.yml` :
`cve: "*"`, `package: linux-libc-dev`, `not_affected`, propriétaire « hébergeur », expire le
31 janvier 2027, justification écrite. Résultat : 6 258 lignes couvertes par une règle visible
dans le rapport et exportée en OpenVEX, le KEV « à traiter » passe à 0, et le premier vrai P1
apparaît : CVE-2025-15467, OpenSSL 9.8, EPSS 52 %, deux mises à jour à faire cette semaine.

Deuxième leçon, sur l'EPSS : CVE-2004-0230 (TCP, 2004) a un EPSS de 80 % et CVE-2011-3389
(BEAST) de 73 %, toutes deux LOW et sans correctif. Ma première règle les mettait en P2.
C'est faux pour une PME : une faille de 2004 non corrigeable n'est pas une urgence à 30 jours.
J'ai changé la règle : exploitation probable mais impact partiel → P3. Un arbre de décision
se règle sur de vraies données, comme une règle de détection.

## 5. Questions d'entretien (avec réponses)

**Q1. Pourquoi ne pas trier par CVSS, comme tout le monde ?**
Parce que le CVSS mesure la gravité technique, pas la probabilité. Sur ce run, 1 425 lignes
sont CRITICAL ou HIGH : personne ne corrige 1 425 choses. KEV et EPSS ramènent à ce qui est
exploité, et l'exposition de l'actif ramène à *mon* contexte. Le CVSS reste dans l'arbre, en
dernier (impact).

**Q2. C'est quoi SSVC, et en quoi votre arbre en diffère ?**
Un arbre de décision de la CISA : exploitation, exposition, automatisable, impact humain →
Track / Track* / Attend / Act. Je n'ai pas les données « automatisable » ni « prévalence
mission » pour une PME, donc trois axes (exploitation, exposition, impact) plus la criticité
métier de l'actif, et quatre sorties P1 à P4 avec un SLA. Les huit règles sont dans
`docs/METHOD.md`, et un test vérifie que la priorité ne s'améliore jamais quand l'exploitation
s'aggrave.

**Q3. Pourquoi 10 % pour l'EPSS ? 7 jours pour le P1 ?**
10 % est le seuil courant du guide EPSS et des éditeurs. 7 jours : la directive BOD 22-01 de la
CISA donne 2 semaines aux agences fédérales pour un nouveau KEV ; une PME avec 4 actifs peut
faire mieux. Ce sont des choix, écrits dans `policy.yml`, pas dans le code : un test change le
seuil à 90 % et vérifie que le P1 disparaît.

**Q4. Un paquet sans correctif, vous en faites quoi ?**
Action `mitigate` : la priorité et l'échéance ne changent pas (le risque n'attend pas
l'éditeur), mais la réponse attendue est une mesure compensatoire (règle WAF, module
désactivé, restriction réseau) et une veille. Le statut Debian (`will_not_fix`,
`fix_deferred`) est copié dans la raison. Si le risque est accepté, on l'écrit : exception
`accepted` avec propriétaire et expiration.

**Q5. 6 258 exceptions d'un coup, ce n'est pas tricher ?**
C'est une seule règle, visible dans le rapport et dans `openvex.json`, avec un propriétaire,
une justification et une date. L'inverse serait tricher : filtrer en silence dans le code. Et
la règle dit qui traite le vrai problème (le noyau de l'hôte).

**Q6. Pourquoi un registre, le scanner ne suffit pas ?**
Le scanner dit l'état d'aujourd'hui. Pour dire « en retard », il faut la date de première
détection ; pour dire « corrigé en 20 jours », il faut la date de disparition. Le registre
donne aussi la réouverture (retour arrière d'une image) et l'escalade (CVE qui entre au KEV).

**Q7. Que se passe-t-il si un scan manque ?**
L'actif est ignoré avec un avertissement, ses failles restent ouvertes. Un scan absent n'est
jamais une correction : c'est testé.

**Q8. KEV vide pour une CVE, ça veut dire pas exploitée ?**
Non. Le KEV ne liste que ce que la CISA a confirmé. C'est pour ça que l'EPSS est le second
signal, et que le CVSS reste dans l'arbre.

**Q9. Vos images sont-elles celles de l'hébergeur ?**
Non : images publiques upstream à un tag, le digest exact est dans les métadonnées du scan.
L'hébergeur peut avoir des images patchées. C'est un lab sur de vraies données, pas un audit
d'un vrai hébergeur.

**Q10. Pourquoi Trivy et pas Nessus / OpenVAS ?**
Trivy est gratuit, scanne images et dépendances sans agent, et c'est l'outil que j'ai vraiment
fait tourner. Je n'ai pas écrit de parseur Nessus parce que je ne pourrais pas le tester.
Nessus ou OpenVAS scannent des *hôtes* (ports, services) ; ce serait l'étape suivante, avec
une autorisation écrite.

**Q11. Qu'est-ce que la CI fait vraiment ?**
Job `tests` : 102 tests, hors ligne. Job `weekly` : chaque lundi, Trivy (image officielle
épinglée par digest, à cause de la compromission de mars 2026) rescanne les 3 images,
télécharge le KEV et l'EPSS du jour, lance le pipeline, publie rapport et registre en
artefacts, et le job est rouge si un P1 est en retard ou si un nouveau P1 apparaît sur un
actif Internet. Au 12 octobre, ce job n'a pas encore tourné.

**Q12. Qu'est-ce que vos tests ont trouvé ?**
Une injection HTML dans le rapport : `select_autoescape` se base sur l'extension du fichier
et mon gabarit s'appelle `.j2`, donc rien n'était échappé ; un nom de paquet venu d'un scan
aurait pu injecter du HTML. Et un plantage quand l'EPSS n'a pas de percentile. Les deux sont
dans REVIEW.md.

**Q13. Comment ça s'intègre avec vos autres projets ?**
Même PME fictive que l'audit GRC et les playbooks IR. Trivy voit les paquets ; le pipeline
AppSec voit le code ; l'audit RSSI voit l'exposition externe. Ensemble : code, dépendances,
exposition, et ici la décision « quoi corriger quand ».

**Q14. Si l'exception expire et que personne ne fait rien ?**
Le rapport l'affiche dans « Exceptions expirées » et la faille rouvre avec son SLA ; le KEV
noyau redevient P1 et la CI passe au rouge. Il n'y a pas d'e-mail automatique, c'est une
limite écrite.

**Q15. Ça tient pour 500 serveurs ?**
Non, le registre JSON grossit (4,7 Mo pour un run). Pour une flotte il faudrait une base et
une déduplication par CVE source. Pour une PME avec quelques actifs, c'est le bon niveau.

**Q16. Combien de temps, et qu'est-ce que vous referiez ?**
Une journée de construction et de tests. Je ferais lire mon OpenVEX par Trivy lui-même
(`--vex`) pour fermer la boucle, et je rescannerais chaque semaine pendant un mois pour avoir
de vrais délais moyens au lieu d'une simulation.

## 6. Ce que Mohamed doit faire lui-même avant d'en parler

- Relancer `python -m pytest -q` et `python -m vmp run --today 2026-10-12` sur sa machine, ouvrir
  `reports/report.html`, lire le tableau « Par actif » et les 5 P1.
- Lancer le workflow `weekly` une fois (Actions → Run workflow), noter le numéro du run et le
  résultat dans le README, et pouvoir dire si la gate était rouge et pourquoi.
- Savoir expliquer sans notes : pourquoi `linux-libc-dev` n'est pas le noyau ; la différence
  KEV / EPSS / CVSS ; les 8 règles de l'arbre ; pourquoi une faille sans correctif garde son SLA.
- Ouvrir `policy.yml`, changer l'exposition de `db` en `internet`, relancer, et expliquer ce qui
  change (la CVE CRITICAL de MariaDB passe en P2).

## 7. Lignes de CV (format §7 du DIRECTOR-AUDIT : max 3 lignes, chiffres vrais, une réserve)

- **FR** — **Gestion des vulnérabilités basée sur le risque** (Python, Trivy, CISA KEV, EPSS,
  SSVC, OpenVEX) : pipeline qui trie les scans Trivy d'une pile web PME (nginx, WordPress,
  MariaDB, vraies images) par exploitation réelle (KEV), probabilité (EPSS) et exposition de
  l'actif ; 9 540 lignes de scan ramenées à 5 P1 (une CVE OpenSSL) avec échéances (SLA),
  registre de suivi, exceptions documentées en OpenVEX, rapport dirigeant et gate CI. 102 tests ;
  PME fictive, images publiques.
- **EN** — **Risk-based vulnerability management pipeline** (Python, Trivy, CISA KEV, EPSS,
  SSVC, OpenVEX): triages Trivy scans of an SME web stack (nginx, WordPress, MariaDB, real
  images) by observed exploitation (KEV), likelihood (EPSS) and asset exposure; 9 540 scanner
  findings reduced to 5 P1 (one OpenSSL CVE) with SLAs, a remediation ledger, documented
  exceptions exported as OpenVEX, an owner-level report and a CI gate. 102 tests; fictitious
  SME, public images.

**À ne jamais dire :**
- « j'ai audité l'hébergeur / les serveurs d'une entreprise » (images publiques, PME fictive) ;
- « 0 vulnérabilité », « tout est corrigé », « les 6 258 CVE noyau sont fausses » (elles sont
  réelles, elles ne s'appliquent pas à ce paquet) ;
- « EPSS prouve qu'une faille est exploitée » (c'est une probabilité) ;
- « compatible Nessus / OpenVAS / Grype » (Trivy seulement) ;
- « délai moyen de correction de 20 jours » sans préciser que le second run est simulé ;
- « pipeline en production chez un client ».
