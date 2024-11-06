#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <sys/time.h>

#define MAX_OS_NAME 256

typedef struct {
    char os_name[MAX_OS_NAME];
    int seq;
    int win_size;
    int ttl;
    int df;
    int ops;
} os_fingerprint;

static unsigned short calculate_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Créer la socket ICMP
int create_icmp_socket() {
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("Failed to create raw ICMP socket");
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

// Créer une socket TCP brute pour SYN Scan
int create_tcp_socket() {
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("Failed to create raw TCP socket");
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

// Envoyer un paquet ICMP
void send_icmp_packet(int sockfd, const char *dest_ip, int ttl, struct timeval *send_time) {
    struct sockaddr_in dest_addr;
    struct icmphdr icmp_hdr;
    char packet[sizeof(struct icmphdr) + 56];  // ICMP header + data

    // Initialiser les structures
    memset(&icmp_hdr, 0, sizeof(struct icmphdr));
    memset(packet, 0, sizeof(packet));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);

    // Remplir l'en-tête ICMP
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.un.echo.id = getpid();
    icmp_hdr.un.echo.sequence = ttl;
    memcpy(packet, &icmp_hdr, sizeof(struct icmphdr));

    // Calculer et appliquer la somme de contrôle
    icmp_hdr.checksum = calculate_checksum(packet, sizeof(packet));
    memcpy(packet, &icmp_hdr, sizeof(struct icmphdr));

    // Enregistrer le temps d'envoi
    gettimeofday(send_time, NULL);

    // Envoyer le paquet
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Sendto failed for ICMP");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Paquet ICMP envoyé à %s avec TTL = %d\n", dest_ip, ttl);
}

// Envoyer un paquet TCP SYN pour capturer les informations `seq`, `win_size`, etc.
void send_tcp_syn_packet(int sockfd, const char *source_ip, const char *dest_ip, int port) {
    struct sockaddr_in dest_addr;
    char packet[4096];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct pseudo_header {
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t tcp_length;
    } psh;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int));
    memset(packet, 0, 4096);

    // Remplir la structure d'adresse de destination
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);  // Port destination
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);

    // Remplir l'en-tête IP
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = dest_addr.sin_addr.s_addr;
    iph->check = calculate_checksum((unsigned short *)packet, sizeof(struct iphdr));

    // Remplir l'en-tête TCP
    tcph->source = htons(12345);  // Port source arbitraire
    tcph->dest = htons(80);     // Port destination (ex: 80 ou autre)
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;  // Longueur de l'en-tête TCP
    tcph->syn = 1;
    tcph->window = htons(14600);  // Taille de la fenêtre TCP
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // Pseudo header nécessaire pour calculer la somme de contrôle TCP
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = dest_addr.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char pseudogram[psize];

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->check = calculate_checksum((unsigned short *)pseudogram, psize);

    // Vérification du port destination avant d'envoyer
    printf("Envoi du paquet TCP SYN sur le port %d (destination)\n", ntohs(tcph->dest));

    // Envoyer le paquet TCP SYN
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Erreur lors de l'envoi du paquet TCP SYN");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Paquet TCP SYN envoyé à %s:%d\n", dest_ip, port);
}

// Obtenir l'adresse IP locale
int get_local_ip(char *buffer) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket error");
        return -1;
    }

    const char *google_dns_ip = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(google_dns_ip);
    serv.sin_port = htons(dns_port);

    if (connect(sock, (const struct sockaddr *)&serv, sizeof(serv)) < 0) {
        perror("Connect error");
        close(sock);
        return -1;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, (struct sockaddr *)&name, &namelen) == -1) {
        perror("Getsockname error");
        close(sock);
        return -1;
    }

    const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
    if (p == NULL) {
        perror("inet_ntop error");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

// Fonction principale pour envoyer et recevoir des paquets ICMP et TCP SYN
void ft_os(os_fingerprint *os, char *target_ip) {
    int sock_icmp, sock_tcp;
    char buffer[4096];
    struct sockaddr_in source;
    socklen_t source_len = sizeof(source);
    struct timeval send_time;

    // Obtenir l'adresse IP locale
    char source_ip[20];
    if (get_local_ip(source_ip) < 0) {
        return;
    }
    printf("Adresse IP locale : %s\n", source_ip);

    // Créer une socket ICMP brute
    sock_icmp = create_icmp_socket();
    // Envoyer le paquet ICMP
    send_icmp_packet(sock_icmp, target_ip, 64, &send_time);  // TTL est fixé à 64 ici

    // Créer une socket TCP brute pour le scan SYN
    sock_tcp = create_tcp_socket();
    // Envoyer le paquet TCP SYN sur le port 80
    send_tcp_syn_packet(sock_tcp, source_ip, target_ip, 80);

    // Ajouter un timeout de 5 secondes pour la réception des paquets ICMP
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock_icmp, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Ajouter un timeout de 2 secondes pour la réception des paquets TCP
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sock_tcp, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Réception de la réponse ICMP
    int bytes_received = recvfrom(sock_icmp, buffer, sizeof(buffer), 0, (struct sockaddr *)&source, &source_len);
    if (bytes_received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("Aucune réponse ICMP reçue (timeout).\n");
        } else {
            perror("Erreur de réception ICMP");
        }
    } else {
        struct iphdr *iph_response = (struct iphdr *)buffer;
        struct icmphdr *icmp_response = (struct icmphdr *)(buffer + (iph_response->ihl * 4));

        if (icmp_response->type == ICMP_ECHOREPLY) {
            printf("Réponse ICMP Echo reçue depuis %s\n", target_ip);
            os->ttl = iph_response->ttl;
            printf("TTL de la réponse : %d\n", os->ttl);
        }
    }

    // Réception de la réponse TCP SYN-ACK ou RST avec un timeout de 2 secondes
    bytes_received = recvfrom(sock_tcp, buffer, sizeof(buffer), 0, (struct sockaddr *)&source, &source_len);
    if (bytes_received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("Aucune réponse TCP reçue (timeout de 2 secondes).\n");
        } else {
            perror("Erreur de réception TCP");
        }
    } else {
        struct iphdr *iph_response = (struct iphdr *)buffer;
        struct tcphdr *tcph_response = (struct tcphdr *)(buffer + (iph_response->ihl * 4));

        // Extraire les informations TCP
        os->seq = ntohl(tcph_response->seq);
        os->win_size = ntohs(tcph_response->window);
        os->df = (ntohs(iph_response->frag_off) & 0x4000) ? 1 : 0;  // DF flag
        os->ops = tcph_response->doff;  // Options TCP

        printf("Numéro de séquence TCP : %d\n", os->seq);
        printf("Taille de la fenêtre TCP : %d\n", os->win_size);
        printf("DF (Don't Fragment) : %d\n", os->df);
        printf("Options TCP : %d\n", os->ops);
    }

    // Fermer les sockets
    close(sock_icmp);
    close(sock_tcp);
}

// Programme principal
// Programme principal
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <IP cible>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    os_fingerprint os_info;
    memset(&os_info, 0, sizeof(os_fingerprint));

    ft_os(&os_info, target_ip);

    printf("\nRésultats de l'analyse de l'OS :\n");
    printf("TTL : %d (0x%x)\n", os_info.ttl, os_info.ttl);
    printf("Numéro de séquence TCP (SEQ) : %d (0x%x)\n", os_info.seq, os_info.seq);
    printf("Taille de la fenêtre TCP : %d (0x%x)\n", os_info.win_size, os_info.win_size);
    printf("DF (Don't Fragment) : %d (0x%x)\n", os_info.df, os_info.df);
    printf("Options TCP : %d (0x%x)\n", os_info.ops, os_info.ops);

    return 0;
}
