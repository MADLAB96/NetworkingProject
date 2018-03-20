//Mitchell Dzurisin
//cs447-001

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <iostream>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>

#define BUFFER_LEN 100
#define MESS_BUFF 10000
#define YES "Y"
#define NO "N"
#define MAIL "MAIL FROM:<"
#define RCPT "RCPT TO:<"
#define DATA "DATA "
#define QUIT "QUIT"
#define USERNAME "334 dXNlcm5hbWU6"
#define PASSWORD "334 cGFzc3dvcmQ6"

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int sendall(int s, const char *buf, int *len)
{
    int total = 0;        // how many bytes we've sent
    int bytesleft = *len; // how many we have left to send
    int n;
		// printf("message len: %d\n", *len);
    while(total < *len) {
				// printf("sendall bytes sent: %d\n", total);
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }

    *len = total; // return number actually sent here

    return n==-1?-1:0; // return -1 on failure, 0 on success
}

int main(int argc, char *argv[])
{
	int sockfd, num;
	char buf[BUFFER_LEN];
	std::string command;
	struct addrinfo hints, *res, *af;
	int recieve;
	char s[INET6_ADDRSTRLEN];
	char incCommand[BUFFER_LEN];
	char newPass[BUFFER_LEN];
	bool notAuth = true;

	if (argc != 3) {
	    printf("bad input, try: ./a.out <hostname> <port #>\n");
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((recieve = getaddrinfo(argv[1], argv[2], &hints, &res)) == 0) {
		printf("Recieved address info.\n");
	} else {
		printf("getaddrinfo: %s\n", gai_strerror(recieve));
		exit(1);
	}

	//find a socket (first available) and connect to it
	for(af = res; af != NULL; af = af->ai_next) {
		if ((sockfd = socket(af->ai_family, af->ai_socktype,
				af->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, af->ai_addr, af->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}
		break;
	}

	if (af == NULL) {
		printf("client did not connect\n");
		exit(1);
	}

	inet_ntop(af->ai_family, get_in_addr((struct sockaddr *)af->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(res); //free res address space

	if ((num = recv(sockfd, buf, BUFFER_LEN-1, 0)) == -1) {
	    perror("recv");
	    exit(1);
	}

	buf[num] = '\0';
	char resp[MESS_BUFF];
	std::string thisUsername;
	//----------------------
	// 			HELO LOOP
	//----------------------
	while(notAuth) {
		// initial HELO command.
		strcpy(buf, "HELO server");
		if((num = send(sockfd, buf, BUFFER_LEN-1, 0)) != -1) {
			printf("Sent HELO\n");
		} else {
			perror("send");
		}
		if((num = recv(sockfd, resp, sizeof(resp), 0)) != -1) {
			printf("%s\n", resp);
			strcpy(buf, s);
			send(sockfd, buf, BUFFER_LEN-1, 0);
		} else {
			perror("recv");
		}
		//----------------------
		// 			AUTH LOOP
		//----------------------
		while(1) {
			strcpy(buf, "AUTH");
			if((num = send(sockfd, buf, BUFFER_LEN-1, 0)) != -1) {
				recv(sockfd, resp, sizeof(resp), 0);
				printf("%s\n", resp);
				if (strcmp(resp, USERNAME) == 0) {
					//server is requesting client username
					printf("Login: Enter your username: ");
					std::getline(std::cin, command);
					thisUsername = command;
					strcpy(buf, command.c_str());
					send(sockfd, buf, BUFFER_LEN-1, 0); //send username
					recv(sockfd, resp, sizeof(resp), 0);
					//check for correct response of sent username

					memset(incCommand, 0, sizeof(incCommand));
					for (size_t i = 0; i < 3; i++) { //get code from recv buffer
						incCommand[i] = resp[i];
					}
					printf("%s\n", incCommand);
					if (strcmp(incCommand, "334") == 0) {
						//enter password
						printf("%s\n", resp);
						printf("Login: Enter your password: ");
						std::getline(std::cin, command);
						strcpy(buf, command.c_str());
						//send password
						send(sockfd, buf, BUFFER_LEN-1, 0);
						recv(sockfd, resp, sizeof(resp), 0);
						//check if successful login
						memset(incCommand, 0, sizeof(incCommand));
						for (size_t i = 0; i < 3; i++) { //get code from recv buffer
							incCommand[i] = resp[i];
						}
						if (strcmp(incCommand, "535") == 0) {
							//unsuccessful login (password)
							printf("%s\n", resp);
							printf("Please Retry.\n");
							//Try Again.
							continue;
						} else if(strcmp(incCommand, "235") == 0) {
							//successful Login.
							printf("%s\n", resp);
							notAuth = false;
							break;
						}
					} else if(strcmp(incCommand, "330") == 0) {
						//server says it's new user
						//recieved new password from server
						printf("%s\n", resp);
						for (size_t i = 4; i < 9; i++) { //get new passwords from recv buffer
							newPass[i-4] = resp[i];
						}
						printf("Your new password: %s\n", newPass);
						printf("Wait for reconnect...\n");
						//wait 5 seconds and reconnect.
						for (int i = 0; i < 5; i++) {
							printf("%d...\n", (i + 1));
							usleep(1000000); //one second
						}
						printf("New Connection.\n");
						printf("-------------------------\n");
						break;
					}
				}
			} else {
				perror("send");
			}
		}
	}

	//----------------------
	// 			SEND LOOP
	//----------------------
	while(1) {
		printf("Would you like to send mail? [Y, N]: ");
		std::getline(std::cin, command);
		strcpy(buf, command.c_str());
		//Ask to continue
		if (strcmp(command.c_str(), YES) == 0) {
			//-----------------------
			//			Y: MAIL FROM
			//-----------------------
			// printf("Enter your username: ");
			// std::getline(std::cin, command);

			//format SMTP 'MAIL FROM' string
			command = MAIL + thisUsername;
			command += "@447.edu>";
			strcpy(buf, command.c_str());
			int leng = sizeof(buf);
			if((num = sendall(sockfd, buf, &leng)) != -1) {
				// printf("Sent: %s\n", buf);
			} else {
				perror("send");
			}
			if((num = recv(sockfd, resp, sizeof(resp), 0)) != -1) {
				printf("%s\n", resp);
			} else {
				perror("recv");
			}
			//-----------------------
			//			Y: RCPT TO
			//-----------------------
			printf("Enter reciever address: ");
			std::getline(std::cin, command);
			//format SMTP 'RCPT TO' string
			command = RCPT + command;
			command += ">";
			strcpy(buf, command.c_str());
			leng = sizeof(buf);
			if((num = sendall(sockfd, buf, &leng)) == -1) {
				perror("send");
			}
			if((num = recv(sockfd, resp, sizeof(resp), 0)) == -1) {
				perror("recv");
			}
			//-----------------------
			//			Y: DATA
			//-----------------------
			printf("Enter the message: \n");
			std::string allData = "";
			while (1) {
				std::getline(std::cin, command);
				allData += command;
				allData += '\n';
				if (strcmp(command.c_str(), ".") == 0) {
					break;
				}
			}
			// std::getline(std::cin, command);
			//format SMTP 'DATA' string
			allData = DATA + allData;
			strcpy(buf, allData.c_str());
			leng = sizeof(buf);
			printf("%d\n", leng);
			if((num = sendall(sockfd, buf, &leng)) == -1) {
				perror("send");
			}
			if((num = recv(sockfd, resp, sizeof(resp), 0)) != -1) {
				printf("%s\n", resp);
			} else {
				perror("recv");
			}
		} else if(strcmp(command.c_str(), NO) == 0){
			//-----------------------
			//			N: QUIT
			//-----------------------
			printf("Goodbye.\n");
			strcpy(buf, QUIT);
			if((num = send(sockfd, buf, BUFFER_LEN-1, 0)) == -1) {
				perror("send");
			}
			if((num = recv(sockfd, resp, sizeof(resp), 0)) != -1) {
				printf("%s\n", resp);
				break;
			} else {
				perror("recv");
			}
		}
	}

	close(sockfd);
	return 0;
}
