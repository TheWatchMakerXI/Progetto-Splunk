# Progetto - Splunk

# Indice

1. Introduzione
2. Sintesi Esecutiva
3. Metodologia
4. Analisi dei Log
5. Report Conclusivo
6. Conclusioni e Prossimi Passi
7. Glossario dei Termini Tecnici
8. Appendici

# 1. Introduzione

Questo report presenta un'analisi approfondita dei log di sistema raccolti attraverso Splunk, con l'obiettivo di identificare potenziali minacce alla sicurezza e attività sospette all'interno della nostra infrastruttura IT. L'analisi si concentra su vari aspetti della sicurezza, tra cui tentativi di accesso non autorizzato, attività di ricognizione e potenziali attacchi mirati.

# 2. Sintesi Esecutiva

L'analisi dettagliata dei log dei nostri sistemi ha portato alla luce alcune attività potenzialmente malevole che suggeriscono tentativi di attacco intenzionali e mirati. Questi eventi evidenziano rischi per la sicurezza dei nostri dati e infrastrutture. Le attività sospette rilevate comprendono tentativi di accesso non autorizzato tramite attacchi di forza bruta su SSH, attività di ricognizione avanzata tramite enumerazione di sessioni e processi, automazione anomala di azioni sul sito web e possibili attacchi di credential stuffing e SQL injection.

# 3. Metodologia

L'analisi è stata condotta utilizzando Splunk, una piattaforma avanzata per l'analisi dei log. Sono state eseguite query mirate per identificare pattern sospetti nei log di sistema, con particolare attenzione ai tentativi di accesso falliti, alle sessioni SSH, agli errori del server e alle attività anomale sul sito web. Le query Splunk utilizzate sono dettagliate nell'Appendice A.

# 4. Analisi dei Log

## 4.1 Tentativi di Accesso Brute Force su SSH

**Osservazioni:** Nei log di accesso SSH, abbiamo riscontrato diversi tentativi di login falliti che seguono il modello tipico di un attacco di **forza bruta**. Questo attacco mira a ottenere accesso al sistema tentando un gran numero di combinazioni di credenziali. Sono emersi alcuni indirizzi IP ricorrenti, che evidenziano la presenza di bot o attaccanti automatizzati.

## 4.2 Ricognizione tramite Enumerazione di Sessioni e Processi

**Osservazioni:** L'analisi dei log ha mostrato diversi accessi che sembrano mirare a raccogliere dettagli su processi e sessioni attivi. Questo pattern è comune in fase di **ricognizione**, quando un attaccante cerca di ottenere informazioni che potrebbero essere utilizzate in un attacco successivo, mirato a sfruttare vulnerabilità specifiche.

## 4.3 Attività Sospette di Automazione sul Sito Web

**Osservazioni:** L'analisi dei log HTTP mostra una frequenza sospetta di azioni come "addtocart" e "changequantity," che potrebbero indicare la presenza di bot malevoli. Questi bot potrebbero essere utilizzati per **scraping dei dati** o **frodi tramite azioni automatizzate**, simulando il comportamento di utenti reali.

# 5. Report Conclusivo

Il report conclusivo include una sintesi dettagliata delle minacce identificate, dei rischi associati e delle azioni raccomandate per mitigare tali rischi. Sono state identificate diverse categorie di attacchi potenziali, tra cui tentativi di accesso brute force, attività di ricognizione, automazione sospetta e possibili attacchi di credential stuffing e SQL injection.

# 6. Conclusioni e Prossimi Passi

L'analisi dei log rivela che il sistema è stato oggetto di tentativi di attacco su più fronti, suggerendo che la nostra infrastruttura attira attivamente interesse da parte di attaccanti esterni. Per rafforzare la sicurezza dei nostri sistemi e prevenire possibili compromissioni, è cruciale adottare le seguenti misure:

1. **Blocco IP e autenticazione avanzata** per limitare l'accesso SSH a utenti verificati.
2. **Monitoraggio avanzato** delle attività di enumerazione e alerting su azioni sospette.
3. **Controllo e limitazione delle API** e protezione anti-bot sul sito web per ridurre il rischio di automazione malevola e scraping.
4. **Implementazione di meccanismi di difesa** per SQL injection e monitoraggio dei tentativi di credential stuffing.

# 7. Glossario dei Termini Tecnici

Di seguito sono riportati i principali termini tecnici utilizzati nel report:

- **Brute Force**: Tecnica di attacco che tenta di indovinare password o chiavi provando sistematicamente tutte le possibili combinazioni.
- **SSH (Secure Shell)**: Protocollo di rete crittografico per l'accesso remoto sicuro a sistemi informatici.
- **Credential Stuffing**: Tipo di attacco informatico in cui vengono utilizzate coppie di nomi utente e password rubate per accedere fraudolentemente ad altri account utente.
- **SQL Injection**: Tecnica di attacco che sfrutta vulnerabilità nel codice dell'applicazione per manipolare o recuperare dati dal database.
- **API (Application Programming Interface)**: Set di definizioni e protocolli per la creazione e l'integrazione di software applicativi.
- **CAPTCHA**: Test utilizzato per determinare se l'utente è un essere umano o un computer.
- **2FA (Two-Factor Authentication)**: Metodo di sicurezza che richiede due forme diverse di autenticazione per accedere a un account.

# 8. Appendici

## Appendice A: Query Splunk Utilizzate

### A.1 Identificazione dei tentativi di accesso falliti

```
source="tutorialdata.zip:*" sourcetype="secure.log" | search "failed password" | search user

```

### A.2 Sessioni SSH aperte con successo per l'utente "djohnson"

```
source="tutorialdata.zip:*" sourcetype="secure.log" | search sshd | search "session opened for user djohnson"

```

### A.3 Dettagli delle sessioni SSH aperte per "djohnson"

```
source="tutorialdata.zip:*" sourcetype="secure.log" | rex "Accepted password for (?<user_id>\\S+)" | where user_id="djohnson"
| table _time user_id | rename _time as "Timestamp", user_id as "ID Utente" | sort - _time

```

### A.4 Tentativi di accesso falliti da IP specifico

```
source="tutorialdata.zip:*" sourcetype="secure.log" | search "86.212.199.60" | search "failed" | search user | search port

```

### A.5 Estrazione dettagli tentativi di accesso falliti

```
source="tutorialdata.zip:*" sourcetype="secure.log" | search "86.212.199.60" | search "failed password"
| rex "Failed password for (?:invalid user )?(?<username>\\S+) from (?<src_ip>\\S+) port (?<port>\\d+)"
| table _time username port | rename _time as "Timestamp", username as "Nome Utente", port as "Numero di Porta" | sort - _time

```

### A.6 IP con più di 5 tentativi di accesso falliti

```
source="tutorialdata.zip:*" sourcetype="secure.log" | rex "Failed password for (?:invalid user )?(?<username>\\S+) from (?<src_ip>\\S+)"
| stats count as attempts by src_ip | where attempts > 5
| table src_ip attempts | rename src_ip as "Indirizzo IP", attempts as "Numero di Tentativi" | sort - attempts

```

### A.7 Log con "Internal Server Error"

```
source="tutorialdata.zip:*" sourcetype="secure.log" | search "HTTP 1.1" "500"

```

### A.8 Organizzazione errori "500"

```
source="tutorialdata.zip:*" sourcetype="secure.log" | search "500"
| table _time host uri status | rename _time as "Timestamp", host as "Host", uri as "URL", status as "Stato" | sort - _time

```

## Appendice B: Esempi di Log Rilevanti

Questa sezione includerebbe esempi specifici di log che hanno evidenziato le attività sospette discusse nel report principale. Per motivi di privacy e sicurezza, i dati sensibili sarebbero oscurati.

## Appendice C: Statistiche Dettagliate

Qui verrebbero inserite tabelle e grafici dettagliati che mostrano le statistiche complete relative alle attività sospette rilevate, inclusi:

- Distribuzione temporale dei tentativi di accesso falliti
- Top 10 degli indirizzi IP sorgente per tentativi di accesso non autorizzati
- Frequenza degli errori 500 nel tempo
- Distribuzione delle porte utilizzate negli attacchi
