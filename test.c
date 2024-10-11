#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>    // Pour struct iphdr
#include <netinet/tcp.h>   // Pour struct tcphdr
#include <unistd.h>
#include <errno.h>

// Lecture des réponses TCP
int read_tcp_messages(int sockfd) {
    unsigned char buffer[4096];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    int received_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_len);
    if (received_bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("Aucune réponse reçue dans le délai imparti.\n");
            return -1;
        }
        perror("Erreur de réception");
        return -1;
    }

    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(buffer + (ip_hdr->ihl * 4));

    // Vérifier les flags TCP
    if (tcp_hdr->syn && tcp_hdr->ack) {
        printf("SYN-ACK reçu de %s\n", inet_ntoa(sender.sin_addr));
        return 1; // Port ouvert
    } else if (tcp_hdr->rst) {
        printf("RST reçu de %s\n", inet_ntoa(sender.sin_addr));
        return 0; // Port fermé
    }

    return -1; // Pas de réponse pertinente
}

// Définition correcte de la structure pseudo_header
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Calcul de la somme de contrôle (checksum)
uint16_t csum(void *addr, int size) {
    uint16_t *buff;
    uint32_t sum;

    buff = (uint16_t *)addr;
    for (sum = 0; size > 1; size -= 2)
        sum += *buff++;
    if (size == 1)
        sum += *(uint8_t*)buff;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (~sum);
}

// Fonction pour obtenir l'adresse IP locale
int get_local_ip(char *buffer) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    const char* kGoogleDnsIp = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons(dns_port);

    int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
    if (err < 0) {
        perror("Erreur de connexion");
        return -1;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
    if (err < 0) {
        perror("Erreur lors de l'obtention de l'adresse locale");
        return -1;
    }

    inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
    close(sock);
    return 0;
}

int main() {
    int port = 4242;
    int sock;
    char packet[4096], pseudo_packet[4096];
    struct sockaddr_in dest;
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    printf("sizeof(struct iphdr) = %ld\n", sizeof(struct iphdr));  // 20 octets
    printf("sizeof(struct tcphdr) = %ld\n", sizeof(struct tcphdr));  // 20 octets

    // Obtenir l'adresse IP locale
    char source_ip[20];
    if (get_local_ip(source_ip) < 0) {
        return 1;
    }
    printf("Adresse IP locale : %s\n", source_ip);

    // Créer une socket brute
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Erreur de création de la socket");
        return 1;
    }
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int));

    // Initialiser le paquet à zéro
    memset(packet, 0, 4096);

    // Adresse de destination
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);  // Port destination
    dest.sin_addr.s_addr = inet_addr("10.51.1.16");  // Adresse IP cible

    // Construire l'en-tête IP
    iph->ihl = 5;  // Taille de l'en-tête IP
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htonl(54321);
    iph->frag_off = htons(0x4000);  // Ne pas fragmenter
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(source_ip);  // Adresse IP source
    iph->daddr = dest.sin_addr.s_addr;
    iph->check = csum((unsigned short *)packet, sizeof(struct iphdr));

    // Construire l'en-tête TCP
    tcph->source = htons(42000);  // Port source
    tcph->dest = htons(port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;	
    tcph->syn = 1;  // Activer le flag SYN
    tcph->window = htons(1024);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // Pseudo-en-tête pour la somme de contrôle TCP
    struct pseudo_header psh;
    psh.source_address = inet_addr(source_ip);  // Utiliser l'adresse IP locale
    psh.dest_address = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    tcph->check = csum((unsigned short *)pseudo_packet, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

    // Envoyer le paquet SYN
    int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
    if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("Erreur d'envoi du paquet");
        return 1;
    }
    printf("Paquet SYN envoyé avec succès.\n");

    // Lire la réponse
    while (1) {
        struct timeval timeout;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

        int result = read_tcp_messages(sock);
        if (result >= 0) {
            printf("Résultat: %d\n", result);
            break;
        }
    }

    close(sock);
    return 0;
}
