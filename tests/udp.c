#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>   // Pour ICMP
#include <unistd.h>
#include <errno.h>
#include <netdb.h>  // Pour getservbyport()

// Fonction pour obtenir l'adresse IP locale
int get_local_ip(char *buffer) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    const char* kGoogleDnsIp = "8.8.8.8";  // On utilise 8.8.8.8 pour obtenir l'adresse locale
    int dns_port = 53;  // Port arbitraire pour le test

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons(dns_port);

    int err = connect(sock, (const struct sockaddr *)&serv, sizeof(serv));
    if (err < 0) {
        perror("Erreur de connexion");
        return -1;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr *)&name, &namelen);
    if (err < 0) {
        perror("Erreur lors de l'obtention de l'adresse locale");
        return -1;
    }

    inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
    close(sock);
    return 0;
}

// Calcul de la somme de contrôle (checksum)
unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    unsigned short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

// Fonction pour récupérer le nom du service associé à un numéro de port
const char* get_service_name(int port, const char* protocol) {
    struct servent *service = getservbyport(htons(port), protocol);
    if (service) {
        return service->s_name;  // Retourne le nom du service
    }
    return "Service inconnu";  // Retourne ceci si le service n'est pas trouvé
}

int main() {
    int sock;
    char packet[4096], buffer[4096];
    struct sockaddr_in dest, source;
    socklen_t source_len = sizeof(source);
    char source_ip[20];

    // Obtenir l'adresse IP locale
    if (get_local_ip(source_ip) < 0) {
        return 1;
    }
    printf("Adresse IP locale : %s\n", source_ip);

    int dest_port = 80;  // Port cible

    // Créer une socket brute pour envoyer et recevoir les paquets UDP
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("Erreur de création de la socket");
        return 1;
    }

    // Initialiser le paquet à zéro
    memset(packet, 0, 4096);

    // Adresse de destination
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dest_port);  // Port destination
    dest.sin_addr.s_addr = inet_addr("8.8.8.8");  // Adresse IP cible

    // Construire l'en-tête IP
    struct iphdr *iph = (struct iphdr *)packet;
    iph->ihl = 5;  // Taille de l'en-tête IP (5 * 4 = 20 octets)
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));  // Longueur totale du paquet
    iph->id = htonl(54321);  // Identifiant du paquet
    iph->frag_off = 0;
    iph->ttl = 255;  // Time to live
    iph->protocol = IPPROTO_UDP;  // Protocole UDP
    iph->check = 0;  // Calculer plus tard la somme de contrôle IP
    iph->saddr = inet_addr(source_ip);  // Adresse IP source
    iph->daddr = dest.sin_addr.s_addr;

    // Calculer la somme de contrôle IP
    iph->check = csum((unsigned short *)packet, sizeof(struct iphdr));

    // Construire l'en-tête UDP
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    udph->source = htons(12345);  // Port source
    udph->dest = htons(dest_port);  // Port destination
    udph->len = htons(sizeof(struct udphdr));  // Longueur de l'en-tête UDP
    udph->check = 0;  // Somme de contrôle, peut être ignorée pour UDP

    // Récupérer le nom du service pour le port cible
    const char *service_name = get_service_name(dest_port, "udp");
    printf("Service pour le port %d (UDP) : %s\n", dest_port, service_name);

    // Envoyer le paquet UDP
    if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("Erreur d'envoi du paquet");
        return 1;
    }

    printf("Paquet UDP envoyé avec succès.\n");

    // Lire la réponse (ICMP ou UDP)
    while (1) {
        int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source, &source_len);
        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("Aucune réponse reçue, le port est probablement ouvert ou filtré.\n");
                break;
            } else {
                perror("Erreur de réception");
                break;
            }
        }

        struct iphdr *iph_response = (struct iphdr *)buffer;
        struct icmphdr *icmp_response = (struct icmphdr *)(buffer + (iph_response->ihl * 4));

        // Vérifier si c'est un message ICMP Port Unreachable
        if (iph_response->protocol == IPPROTO_ICMP && icmp_response->type == ICMP_DEST_UNREACH && icmp_response->code == ICMP_PORT_UNREACH) {
            printf("Le port est fermé (ICMP Port Unreachable reçu).\n");
            break;
        }

        // Si une réponse UDP est reçue, on peut en conclure que le port est ouvert
        if (iph_response->protocol == IPPROTO_UDP) {
            printf("Réponse UDP reçue, le port est ouvert.\n");
            break;
        }
    }

    // Fermer la socket
    close(sock);
    return 0;
}
