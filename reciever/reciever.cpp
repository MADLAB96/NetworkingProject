//Mitchell Dzurisin
//cs447-001

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string>
#include <dirent.h>
#include <sys/stat.h>
#include <fstream>
#include <string>
#include <string.h>

#define BUFFER_LEN 1000
#define YES "Y"
#define NO "N"
#define GET3 "Host: <447.edu>"
#define GET4 "Count: "
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

std::string getEmailPath() {
	struct stat st = {0};
	DIR *dirPath;
	struct dirent *dirRead;
	int dirLen = 0;
	std::string path = "./emails";

	//count # of files in path. create new file with 00#++.txt
	std::string tempPath = "";
	dirPath = opendir(path.c_str());
	if(dirPath != NULL) {
		while(dirRead = readdir(dirPath)) {
			dirLen++;
			// printf("%d\n", dirLen);
		}
	}
	tempPath = path;
	tempPath += "/00";
	tempPath += ("" + std::to_string(dirLen - 1));
	tempPath += ".txt";
	return tempPath;
}

int main(int argc, char *argv[])
{
	std::ofstream out;
	int sockfd, num;
	char buf[100];
	struct addrinfo hints, *res, *af;
	int recieve;
	sockaddr_in targetServer;
	char s[INET6_ADDRSTRLEN];
	struct stat st = {0};
	bool notAuth = true;
	char incCommand[BUFFER_LEN];
	char newPass[BUFFER_LEN];

	if(stat("/emails", &st) == -1) {
		int dir = mkdir("./emails", 0777);
		if(dir != -1)
			printf("Created ./emails folder.\n");
		else
			printf("./emails folder already created.\n");
	} else {
		printf("Couldnt create ./emails folder\n");
	}

	if (argc != 3) {
	    printf("bad input, try: ./a.out <hostname> <port #>\n");
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ((recieve = getaddrinfo(argv[1], argv[2], &hints, &res)) == 0) {
		printf("Recieved address info.\n");
	} else {
		printf("getaddrinfo: %s\n", gai_strerror(recieve));
		exit(1);
	}

	//find a socket (first available)
	for(af = res; af != NULL; af = af->ai_next) {
		if ((sockfd = socket(af->ai_family, af->ai_socktype,
				af->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}
		break;
	}

	inet_ntop(af->ai_family, get_in_addr((struct sockaddr *)af->ai_addr),
			s, sizeof s);

	if (af == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		exit(1);
	}

	freeaddrinfo(res);

	std::string thisUsername;
	int emailCount;
	int temp;
	int leng;
	std::string command;
	std::string usern; //username
	std::string hn; //hostname
	std::string dn; //download number
	buf[num] = '\0';
	char otherBuf[BUFFER_LEN];
	char resp[1000];
	char resp1[1000];

	//----------------------
	// 			HELO
	//----------------------
	strcpy(buf, "HELO server");
	if(temp = sendto(sockfd, buf, sizeof(buf), 0, af->ai_addr, af->ai_addrlen)!= -1) {
		// printf("Sent: %s\n", buf);
	} else {
		perror("sendto");
		exit(1);
	}
	if(temp = recvfrom(sockfd, resp1, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen)!= -1) {
		printf("Recieved: %s\n", resp1);
		sendto(sockfd, s, sizeof(s), 0, af->ai_addr, af->ai_addrlen);
	} else {
		perror("recvfrom");
		exit(1);
	}

	while(notAuth) {
		//----------------------
		// 			AUTH LOOP
		//----------------------
		while (1) {
			strcpy(buf, "AUTH");
			if(temp = sendto(sockfd, buf, sizeof(buf), 0, af->ai_addr, af->ai_addrlen)!= -1) {
 				recvfrom(sockfd, resp, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen);
				printf("%s\n", resp);
				if (strcmp(resp, USERNAME) == 0) {
					//server is requesting client username
					printf("Login: Enter your username: ");
					std::getline(std::cin, command);
					strcpy(buf, command.c_str());
					thisUsername = command;
					//send username
					sendto(sockfd, buf, sizeof(buf), 0, af->ai_addr, af->ai_addrlen);
					recvfrom(sockfd, resp, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen);
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
						sendto(sockfd, buf, sizeof(buf), 0, af->ai_addr, af->ai_addrlen);
						recvfrom(sockfd, resp, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen);
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
							recvfrom(sockfd, resp, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen);
							printf("%s\n", resp);
							emailCount = resp[9] - '0';
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
				perror("sendto");
				exit(1);
			}
		}
	}
	//----------------------
	// 			GET LOOP
	//----------------------
	while(1) {
		//------------------------------
		// 		RECIEVE MAIL
		// 		-after authentication
		//------------------------------
		printf("Would you like to recieve mail? [Y, N]: ");
		std::getline(std::cin, command);
		if (strcmp(command.c_str(), YES) == 0) {
			//-----------------------
			//			Y: GET
			//-----------------------
			// printf("Enter reciever username: ");
			// std::getline(std::cin, usern);
			//format HTTP GET string
			command = "GET /db/";
			command += thisUsername;
			strcpy(buf, command.c_str());
			if(temp = sendto(sockfd, buf, sizeof(buf), 0, af->ai_addr, af->ai_addrlen) == -1) {
				perror("sendto");
			} else {
				//check for correct responce
				if (temp = recvfrom(sockfd, resp, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen) != -1) {
					if (strcmp(resp, "200 OK") == 0) {
						printf("Server Found the username.\n");
					} else if (strcmp(resp, "404 Not Found") == 0) {
						printf("Could not find username you entered.\n");
						continue;
					}
				} else {
					perror("recvfrom");
				}
			}
			strcpy(buf, "/ HTTP/1.1");
			if(temp = sendto(sockfd, buf, sizeof(buf), 0, af->ai_addr, af->ai_addrlen) == -1) {
				perror("sendto");
			} else {
				//check for correct responce
			}
			// std::getline(std::cin, hn);
			command = (GET3);
			strcpy(buf, command.c_str());
			if((temp = sendto(sockfd, buf, sizeof(buf), 0, af->ai_addr, af->ai_addrlen)) == -1) {
				perror("sendto");
			} else {
				//check for correct responce
			}
			printf("Enter desired email downloads: ");
			std::getline(std::cin, dn);
			// int enteredDn = dn - '0';
			// if (enteredDn <= emailCount) {
			// 	//trying to download a valid amount.
			// } else {
			// 	//trying to download more than available
			// }
			std::string desiredC(dn);
			command = (GET4 + dn);
			strcpy(buf, command.c_str());
			if((temp = sendto(sockfd, buf, sizeof(buf), 0, af->ai_addr, af->ai_addrlen)) != -1) {
				perror("sendto");
			} else {
				//check for correct responce
			}
			recvfrom(sockfd, resp, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen);
			if(strcmp(resp, "404 Bad Request") == 0) {
				printf("Server not found, please try again.\n");
			} else if(strcmp(resp, "400 Bad Request") == 0) {
				recvfrom(sockfd, resp, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen);
				printf("Poor request, please try again.\n");
			} else {
				recvfrom(sockfd, resp, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen);
				recvfrom(sockfd, resp, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen);
				//Resonse line 1
				std::string fullResponse(resp);
				std::string filePath = getEmailPath();
				printf("New file path: %s \n", filePath.c_str());
				out.open(filePath);
				out << resp << '\n';
				//Resonse line 2
				recvfrom(sockfd, resp, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen);
				out << resp << '\n';
				//Resonse line 3
				recvfrom(sockfd, resp, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen);
				out << "Last-Modified: " << resp << '\n';
				//Resonse line 4
				out << "Count: " << desiredC << '\n' << '\n';
				//Responce email file
				while(1) {
					recvfrom(sockfd, resp, sizeof(resp), 0, af->ai_addr, &af->ai_addrlen);
					if(strcmp(resp, "END") == 0)
						break;
					out << resp << '\n';
				}
				out.close();
			}
		} else if(strcmp(command.c_str(), NO) == 0)	{
			strcpy(buf, "QUIT");
			sendto(sockfd, buf, sizeof(buf), 0, af->ai_addr, af->ai_addrlen);
			exit(0);
		}
	}

	close(sockfd);
	return 0;
}
