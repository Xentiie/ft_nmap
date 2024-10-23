#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

// Fonction pour récupérer la version d'un service
void get_service_version(const char *hostname, int port) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[1024];

    // Créer une socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Erreur lors de la création de la socket");
        exit(EXIT_FAILURE);
    }

    // Résoudre l'hôte
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "Erreur : hôte introuvable\n");
        exit(EXIT_FAILURE);
    }

    // Configurer l'adresse du serveur
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    // Connexion au serveur
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Erreur lors de la connexion");
        exit(EXIT_FAILURE);
    }

    // Envoyer une requête HTTP simple pour récupérer la bannière
    const char *http_request = "HEAD / HTTP/1.1\r\nHost: google.com\r\n\r\n";
    write(sockfd, http_request, strlen(http_request));

    // Lire la réponse du serveur
    memset(buffer, 0, sizeof(buffer));
    int bytes_received = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes_received < 0) {
        perror("Erreur lors de la lecture de la réponse");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Afficher la bannière (version du serveur)
    printf("Réponse du serveur :\n%s\n", buffer);

    // Fermer la connexion
    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *hostname = argv[1];
    int port = atoi(argv[2]);

    get_service_version(hostname, port);

    return 0;
}
