/*
 * ids_elite.c
 *
 * IDS Elite – Sistem Avansat de Detectare a Intruziunilor
 *
 * Acest proiect captează pachete din rețea utilizând libpcap, le procesează
 * în mod paralel cu pthread și le analizează pentru a detecta comportamente suspecte.
 * Analiza include: deep packet inspection (DPI), extragerea metadatelor din IP/TCP,
 * și o simulare de analiză ML (dacă pachetul depășește un prag de lungime).
 *
 * Compile:
 *     gcc ids_elite.c -lpcap -lpthread -o ids_elite
 *
 * Rulare:
 *     sudo ./ids_elite [interface]
 *     (dacă nu specifici interface-ul, se folosește dispozitivul implicit)
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>

#define QUEUE_SIZE 100
#define ETHERNET_HEADER_SIZE 14
#define SUSPICIOUS_PACKET_THRESHOLD 1000 // Prag dummy pentru analiza ML

// Variabilă globală pentru oprirea capturării
volatile sig_atomic_t stop_capture = 0;

// Structura pentru stocarea unui pachet capturat
typedef struct PacketData {
    struct pcap_pkthdr header;
    u_char *packet;
} PacketData;

// Coada circulară pentru pachete
PacketData *packet_queue[QUEUE_SIZE];
int queue_front = 0;
int queue_rear = 0;
int queue_count = 0;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

// Pentru logare, se utilizează un fișier și un mutex
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
FILE *log_file = NULL;

// Funcție de logare cu timestamp
void log_message(const char *format, ...) {
    va_list args;
    pthread_mutex_lock(&log_mutex);
    if (log_file) {
        time_t now = time(NULL);
        char time_str[26];
        ctime_r(&now, time_str);
        time_str[strcspn(time_str, "\n")] = '\0';  // Elimină newline
        fprintf(log_file, "[%s] ", time_str);
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
        fprintf(log_file, "\n");
        fflush(log_file);
    }
    pthread_mutex_unlock(&log_mutex);
}

// Funcție de adăugare a unui pachet în coadă
void enqueue_packet(PacketData *pkt) {
    pthread_mutex_lock(&queue_mutex);
    if (queue_count < QUEUE_SIZE) {
        packet_queue[queue_rear] = pkt;
        queue_rear = (queue_rear + 1) % QUEUE_SIZE;
        queue_count++;
        pthread_cond_signal(&queue_cond);
    } else {
        // Coada este plină – pachetul este abandonat
        log_message("Packet dropped: queue full");
        free(pkt->packet);
        free(pkt);
    }
    pthread_mutex_unlock(&queue_mutex);
}

// Funcție de scoatere a unui pachet din coadă
PacketData* dequeue_packet() {
    PacketData *pkt = NULL;
    pthread_mutex_lock(&queue_mutex);
    while (queue_count == 0 && !stop_capture) {
        pthread_cond_wait(&queue_cond, &queue_mutex);
    }
    if (queue_count > 0) {
        pkt = packet_queue[queue_front];
        queue_front = (queue_front + 1) % QUEUE_SIZE;
        queue_count--;
    }
    pthread_mutex_unlock(&queue_mutex);
    return pkt;
}

// Funcție dummy de analiză ML: marchează ca suspect dacă lungimea pachetului > prag
int ml_analysis(const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->len > SUSPICIOUS_PACKET_THRESHOLD) {
        return 1;
    }
    return 0;
}

// Funcție de analiză a pachetului: extrage informații din IP/TCP și loghează evenimente
void analyze_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->len < ETHERNET_HEADER_SIZE) return; // Pachet prea scurt

    // Sărim peste header-ul Ethernet
    const u_char *ip_packet = packet + ETHERNET_HEADER_SIZE;
    struct ip *ip_hdr = (struct ip*)ip_packet;
    int ip_header_length = ip_hdr->ip_hl * 4;
    if (ip_header_length < 20) return; // Lungime IP invalidă

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Analiză în funcție de protocol
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        const u_char *tcp_packet = ip_packet + ip_header_length;
        struct tcphdr *tcp_hdr = (struct tcphdr*)tcp_packet;
        int tcp_header_length = tcp_hdr->th_off * 4;
        log_message("TCP Packet: %s:%d -> %s:%d, Total Length: %d",
                    src_ip, ntohs(tcp_hdr->th_sport),
                    dst_ip, ntohs(tcp_hdr->th_dport),
                    header->len);
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        log_message("UDP Packet: %s -> %s, Length: %d", src_ip, dst_ip, header->len);
    } else {
        log_message("Other IP Packet: %s -> %s, Protocol: %d, Length: %d",
                    src_ip, dst_ip, ip_hdr->ip_p, header->len);
    }

    // Efectuăm o analiză dummy de tip ML
    if (ml_analysis(header, packet)) {
        log_message("ALERT: Suspicious packet detected! Source: %s, Destination: %s, Length: %d",
                    src_ip, dst_ip, header->len);
    }
}

// Funcția de procesare a pachetelor (executată într-un thread separat)
void *packet_processor(void *arg) {
    while (!stop_capture) {
        PacketData *pkt = dequeue_packet();
        if (pkt) {
            analyze_packet(&(pkt->header), pkt->packet);
            free(pkt->packet);
            free(pkt);
        }
    }
    return NULL;
}

// Callback-ul pentru libpcap – se apelează pentru fiecare pachet capturat
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    PacketData *pkt = (PacketData*)malloc(sizeof(PacketData));
    if (!pkt) {
        fprintf(stderr, "Memory allocation failed for packet data.\n");
        return;
    }
    pkt->header = *header;
    pkt->packet = (u_char*)malloc(header->len);
    if (!pkt->packet) {
        free(pkt);
        fprintf(stderr, "Memory allocation failed for packet payload.\n");
        return;
    }
    memcpy(pkt->packet, packet, header->len);
    enqueue_packet(pkt);
}

// Variabilă globală pentru handler-ul pcap
pcap_t *pcap_handle = NULL;

// Signal handler pentru SIGINT (Ctrl+C) – întrerupe capturarea
void handle_sigint(int sig) {
    stop_capture = 1;
    if (pcap_handle) {
        pcap_breakloop(pcap_handle);
    }
    pthread_cond_broadcast(&queue_cond);
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = NULL;
    struct bpf_program fp;
    char filter_exp[] = "ip";  // Filtru: doar pachete IP

    // Setăm handler-ul pentru SIGINT
    signal(SIGINT, handle_sigint);

    // Deschidem fișierul de logare
    log_file = fopen("ids_log.txt", "a");
    if (!log_file) {
        fprintf(stderr, "Nu s-a putut deschide fișierul de log.\n");
        return 1;
    }

    // Alegem interfața: argumentul de linie de comandă sau dispozitivul implicit
    if (argc >= 2) {
        dev = argv[1];
    } else {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "pcap_lookupdev: %s\n", errbuf);
            return 1;
        }
    }
    printf("Capturing on device: %s\n", dev);
    log_message("IDS Elite pornește pe interfața: %s", dev);

    // Deschidem interfața pentru captură
    pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return 1;
    }

    // Compilăm și aplicăm filtrul BPF
    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Eroare la pcap_compile\n");
        return 1;
    }
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "Eroare la pcap_setfilter\n");
        return 1;
    }

    // Creăm un thread pentru procesarea pachetelor
    pthread_t processor_thread;
    if (pthread_create(&processor_thread, NULL, packet_processor, NULL) != 0) {
        fprintf(stderr, "Eroare la crearea thread-ului de procesare\n");
        return 1;
    }

    // Începem capturarea pachetelor (pcap_loop va apela callback-ul pentru fiecare pachet)
    pcap_loop(pcap_handle, 0, packet_handler, NULL);

    // Așteptăm terminarea thread-ului de procesare și eliberăm resursele
    pthread_join(processor_thread, NULL);
    pcap_close(pcap_handle);
    fclose(log_file);
    printf("IDS Elite s-a oprit.\n");
    return 0;
}
