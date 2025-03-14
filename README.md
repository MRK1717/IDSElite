# IDS Elite – Sistem Avansat de Detectare a Intruziunilor

## Descriere
**IDS Elite** este o platformă robustă de detectare a intruziunilor, dezvoltată în C, care analizează traficul de rețea în timp real. 
Proiectul integrează capturarea pachetelor cu libpcap, procesarea paralelă folosind pthread și o analiză profundă a pachetelor pentru identificarea comportamentelor suspecte. 
Sistemul include și un modul de analiză simulată de tip machine learning, demonstrând abilitatea de a implementa soluții avansate de securitate.

## Caracteristici Principale
- **Capturare Pachete în Timp Real:** Utilizează biblioteca **libpcap** pentru captarea și filtrarea pachetelor IP.
- **Procesare Multi-Thread:** Distribuie sarcina de analiză a pachetelor pe mai multe thread-uri, asigurând performanță chiar și la trafic intens.
- **Deep Packet Inspection (DPI):** Extragerea și analiza datelor din header-ele IP și TCP pentru identificarea activităților suspecte.
- **Analiză Simulată de Machine Learning:** Markează pachetele suspecte pe baza unui prag de lungime, simulând tehnici ML pentru detecție.
- **Logare Detaliată:** Evenimentele sunt logate cu timestamp-uri într-un fișier (`ids_log.txt`), facilitând analiza ulterioară.

## Cerințe
- **Sistem de Operare:** Linux, Unix sau macOS
- **Compilator:** GCC
- **Biblioteci Necesare:**  
  - `libpcap` (instalabil pe Debian/Ubuntu cu: `sudo apt-get install libpcap-dev`)
  - `pthread` (de obicei este inclusă în sistemele POSIX)
- **Permisiuni:** Rularea programului pentru capturarea pachetelor poate necesita drepturi de administrator.

## Instalare și Compilare
1. **Clonarea repository-ului:**
   ```bash
   git clone git@github.com:MRK1717/IDSElite.git
   cd IDSElite
