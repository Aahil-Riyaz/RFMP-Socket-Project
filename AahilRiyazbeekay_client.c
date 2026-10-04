// CSEC-201 Project - RFMP C client
// simple version of the python client
// no encryption, it only sends openRead to get a file from the server
//
// compile on windows: gcc AahilRiyazbeekay_client.c -o client_c.exe -lws2_32
// compile on linux/mac: gcc AahilRiyazbeekay_client.c -o client_c

#include <stdio.h>
#include <string.h>

// windows and linux use different socket libraries
#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#define closesocket close
#endif

#define PORT 5000

char buffer[8192];

// keep reading until the message ends with )
int receive_packet(int sock) {
	int total = 0;
	while (total < sizeof(buffer) - 1) {
		int n = recv(sock, buffer + total, sizeof(buffer) - 1 - total, 0);
		if (n <= 0) {
			break;
		}
		total = total + n;
		if (buffer[total - 1] == ')') {
			break;
		}
	}
	buffer[total] = '\0';
	return total;
}

int main() {
	int sock;
	struct sockaddr_in server;
	char filename[100];
	char packet[200];

#ifdef _WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa); // start winsock (windows only)
#endif

	// create a TCP socket
	sock = socket(AF_INET, SOCK_STREAM, 0);

	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.s_addr = inet_addr("127.0.0.1");

	// connect to the server
	if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		printf("could not connect to the server\n");
		return 1;
	}

	// ### setup phase, 0 = not secure
	strcpy(packet, "(SS,RFMP,v1.0,0)");
	send(sock, packet, strlen(packet), 0);
	receive_packet(sock);
	if (strcmp(buffer, "(CC)") != 0) {
		printf("server did not confirm: %s\n", buffer);
		closesocket(sock);
		return 1;
	}
	printf("connected to server (not secure)\n");

	// ### operation phase, only openRead
	printf("file to read: ");
	scanf("%99s", filename);

	sprintf(packet, "(CM,openRead,%s)", filename);
	send(sock, packet, strlen(packet), 0);
	receive_packet(sock);

	if (strncmp(buffer, "(SC,", 4) == 0) {
		buffer[strlen(buffer) - 1] = '\0'; // remove the last )
		printf("------ %s ------\n", filename);
		printf("%s\n", buffer + 4); // skip "(SC,"
		printf("-------------------\n");
	} else {
		printf("error from server: %s\n", buffer);
	}

	// ### closing phase
	strcpy(packet, "(END)");
	send(sock, packet, strlen(packet), 0);
	receive_packet(sock);
	printf("server: %s\n", buffer);

	closesocket(sock);
#ifdef _WIN32
	WSACleanup();
#endif
	return 0;
}
