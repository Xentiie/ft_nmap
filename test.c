#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>    // Pour struct iphdr
#include <netinet/tcp.h>   // Pour struct tcphdr
#include <unistd.h>


int read_tcp_messages(int sockfd) {
    unsigned char buffer[4096];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    int received_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_len);
    if (received_bytes < 0) {
        perror("Erreur de réception");
        return -1;
    }

    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(buffer + (ip_hdr->ihl * 4));

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
uint16_t	csum(void *addr, int size) {
	uint16_t	*buff;
	uint32_t	sum;

	buff = (uint16_t *)addr;
	for (sum = 0; size > 1; size -= 2)
		sum += *buff++;
	if (size == 1)
		sum += *(uint8_t*)buff;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return (~sum);
}

int main() {
    int sock;
    char packet[4096], pseudo_packet[4096];
    struct sockaddr_in dest;
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    printf("sizeof(struct iphdr) = %ld\n", sizeof(struct iphdr));  // 20 octets
    printf("sizeof(struct tcphdr) = %ld\n", sizeof(struct tcphdr));  // 20 octets

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
    dest.sin_port = htons(7222);  // Port destination
    dest.sin_addr.s_addr = inet_addr("74.207.244.221");  // Adresse IP cible

    // Construire l'en-tête IP
    iph->ihl = 5;  // Taille de l'en-tête IP en blocs de 4 octets (5 * 4 = 20 octets)
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));  // Longueur totale du paquet
    iph->id = htonl(54321);  // Identifiant du paquet
    iph->frag_off = htons(0x4000);  // Ne pas fragmenter (DF flag)
    iph->ttl = 255;  // Time to live
    iph->protocol = IPPROTO_TCP;  // Protocole TCP
    iph->check = 0;  // Calculer plus tard la somme de contrôle IP
    iph->saddr = inet_addr("192.168.1.100");  // Adresse IP source
    iph->daddr = dest.sin_addr.s_addr;  // Adresse IP cible

    // Afficher la longueur totale du paquet
    printf("Longueur totale du paquet (network byte order) : %d\n", ntohs(iph->tot_len));

    // Calculer la somme de contrôle IP
    iph->check = csum((unsigned short *)packet, sizeof(struct iphdr));

    // Construire l'en-tête TCP
    tcph->source = htons(12345);  // Port source
    tcph->dest = htons(80);  // Port destination
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;  // Taille de l'en-tête TCP en blocs de 4 octets (5 * 4 = 20 octets)
    tcph->syn = 1;  // Activer le flag SYN
    //tcph->ack = 0;
    //tcph->fin = 0;
    //tcph->rst = 0;
    //tcph->psh = 0;
    tcph->window = htons(5840);  // Taille de la fenêtre
    tcph->check = 0;  // Calculer plus tard la somme de contrôle TCP
    tcph->urg_ptr = 0;

    // Pseudo-en-tête pour la somme de contrôle TCP
    struct pseudo_header psh;
    psh.source_address = inet_addr("192.168.1.100");  // Adresse IP source
    psh.dest_address = dest.sin_addr.s_addr;  // Adresse IP cible
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    // Créer le buffer pour le pseudo-en-tête + l'en-tête TCP
    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    // Calculer la somme de contrôle TCP
    tcph->check = csum((unsigned short *)pseudo_packet, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

    // Calcul de la taille totale du paquet à envoyer
    int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
    printf("Taille du paquet à envoyer : %d octets\n", packet_size);

    // Envoyer le paquet SYN
    if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("Erreur d'envoi du paquet");
        return 1;
    }

    printf("Paquet SYN envoyé avec succès.\n");



    while(1){
        //printf("Hello, World!\n");
        int result = read_tcp_messages(sock);

        printf("Result: %d\n", result);
        


    }
    // Fermer la socket
    close(sock);
    return 0;
}
