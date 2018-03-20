//Mitchell Dzurisin
//cs447-001

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <cmath>
#include <ctime>
#include <dirent.h>
#include <errno.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#define PASSWORD_LEN 5
#define ENCODED_PASSWORD_LEN 12
#define BUFFER_LEN 100
#define MESSG_LEN 1000
#define HELO "HELO"
#define AUTH "AUTH"
#define MAIL "MAIL"
#define RCPT "RCPT"
#define DATA "DATA"
#define QUIT "QUIT"
#define OK   "200 OK"
#define USERNAME "334 dXNlcm5hbWU6"
#define PASSWORD "334 cGFzc3dvcmQ6"

char* portTCP;
char* portUDP;

std::string thisIP;

struct log_arg {
	std::string from_ip;
	std::string to_ip;
	std::string prot;
	std::string comm;
	std::string mess;
	std::string desc;
};

struct accept_arg {
	int fd;
	char *s;
};


// get sockaddr, IPv4 or IPv6: needed for everything
void *get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int sendall(int s, const char *buf, int *len) {
    int total = 0;        // how many bytes we've sent
    int bytesleft = *len; // how many we have left to send
    int n;
		printf("message len: %d\n", *len);
    while(total < *len) {
				printf("sendall bytes sent: %d\n", total);
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }

    *len = total; // return number actually sent here

    return n==-1?-1:0; // return -1 on failure, 0 on success
}

std::string emailStrAdd(std::string eStr, std::string addiStr) {
	std::string emailStr = eStr;
	emailStr += addiStr;
	emailStr += "\n";
	std::cout << "FullEmail: \n" << emailStr;
	return emailStr;
}

//used for finding file for storing username/passwords
int findHidden(std::string username) {
	DIR *dir = opendir("./db");
	struct dirent *entry = readdir(dir);
	// std::cout << "searching db for file: ./db/" << username << '\n';
	while (entry != NULL)
	{
		if (entry->d_type == DT_REG) {
			std::string tempDirName(entry->d_name);
			if (!username.compare(tempDirName)) {
				// std::cout << "found file: ./db/" << username << '\n';
				closedir(dir);
				return 1;
			}
		}
		entry = readdir(dir);
	}
	closedir(dir);
	return 0;
}

void serverLog(struct log_arg newLog) {
	//timestamp from-ip to-ip protocol-command message-code description
	std::string log;
	std::ofstream out;
	std::string filepath = "./db/.server_log";
	//get current time
	std::time_t t = std::time(nullptr);

	//check if file is in db
	if (findHidden(filepath) == 1) {
		//first time opening
		// printf("Creating log file.\n");
		out.open(filepath);
	} else {
		// printf("Opening log file.\n");
		out.open(filepath, std::ofstream::out | std::ofstream::app);
	}
	//form string
	log = std::ctime(&t);
	log.pop_back();
	log += " ";
	log += newLog.from_ip;
	log += " ";
	log += newLog.to_ip;
	log += " ";
	log += newLog.prot;
	log += " ";
	log += newLog.mess;
	//output string
	out << log << std::endl;
	out.close();
}


//used for finding directories for storing emails
int indir(std::string username) {
	DIR *dir = opendir("./db");
	struct dirent *entry = readdir(dir);
	std::cout << "searchin db for directory: ./db/" << username << '\n';
	while (entry != NULL)
	{
		if (entry->d_type == DT_DIR) {
			std::string tempDirName(entry->d_name);
			if (!username.compare(tempDirName)) {
				std::cout << "found directory: ./db/" << username << '\n';
				closedir(dir);
				return 1;
			}
		}
		entry = readdir(dir);
	}
	closedir(dir);
	return 0;
}

static void _mkdir(const char *dir) {
        char tmp[256];
        char *p = NULL;
        size_t len;

        snprintf(tmp, sizeof(tmp),"%s",dir);
        len = strlen(tmp);
        if(tmp[len - 1] == '/')
                tmp[len - 1] = 0;
        for(p = tmp + 1; *p; p++)
                if(*p == '/') {
                        *p = 0;
                        mkdir(tmp, S_IRWXU);
                        *p = '/';
                }
        mkdir(tmp, S_IRWXU);
}

std::string encodePassword(const char *newPass) {
	BIO *bio, *b64;
	BUF_MEM *ptr;
	char *encodePass;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	// bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, newPass, sizeof(newPass));
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &ptr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	encodePass = (*ptr).data;

	std::string newEncodedPass(encodePass);
	std::cout << "EncodePassword() returns -> " << newEncodedPass << '\n';
	return newEncodedPass;
}

void addToDB(std::string rcpt, std::string data) {
	std::ofstream out;
	struct stat st = {0};
	DIR *dirPath;
	struct dirent *dirRead;
	int dirLen = 0;
	std::string path = "./db/";
	std::time_t t = std::time(nullptr);

	path += rcpt;
	std::cout << path.c_str() << '\n';
	if(stat(path.c_str(), &st) == -1) {
		_mkdir(path.c_str());
		printf("DB created (%s). \n", path.c_str());
	} else {
		printf("DB folder already created. (%s)\n", path.c_str());
	}

	//count # of files in path. create new file with 00#++.txt
	std::string tempPath = "";
	dirPath = opendir(path.c_str());
	if(dirPath != NULL) {
		while(dirRead = readdir(dirPath)) {
			dirLen++;
		}
	}
	tempPath = path;
	tempPath += "/00";
	tempPath += ("" + std::to_string(dirLen - 1));
	tempPath += ".email";
	printf("New file path: %s \n", tempPath.c_str());
	out.open(tempPath);
	out << "Date: " << std::ctime(&t);
	out << data;
}

int countEmails(std::string username) {
	std::ofstream out;
	struct stat st = {0};
	DIR *dirPath;
	struct dirent *dirRead;
	int dirLen = 0;
	std::string path = "./db/";
	std::time_t t = std::time(nullptr);

	path += username;
	std::cout << path.c_str() << '\n';
	if(stat(path.c_str(), &st) == -1) {
		_mkdir(path.c_str());
		printf("DB created (%s). \n", path.c_str());
	} else {
		printf("DB folder already created. (%s)\n", path.c_str());
	}

	//count # of files in path. create new file with 00#++.txt
	std::string tempPath = "";
	dirPath = opendir(path.c_str());
	if(dirPath != NULL) {
		while(dirRead = readdir(dirPath)) {
			dirLen++;
		}
	}
	printf("unread %d\n", dirLen);

	return (dirLen - 2);
}

void deleteEmails(std::string username) {
	// struct stat st = {0};
	// DIR *dirPath;
	// struct dirent *dirRead;
	// int dirLen = 0;
	// std::string path = "./db/";
	//
	// path += username;
	// std::cout << path.c_str() << '\n';
	// // if(stat(path.c_str(), &st) == -1) {
	// // 	_mkdir(path.c_str());
	// // 	printf("DB created (%s). \n", path.c_str());
	// // } else {
	// // 	printf("DB folder already created. (%s)\n", path.c_str());
	// // }
	//
	// //count # of files in path. create new file with 00#++.txt
	// std::string tempPath = "";
	// dirPath = opendir(path.c_str());
	// if(dirPath != NULL) {
	// 	while(dirRead = readdir(dirPath)) {
	// 		dirLen++;
	// 	}
	// }
	// return dirLen;
}

std::string createUsername(std::string username) {
	std::ofstream out;
	std::string fileName = username;
	fileName = "." + fileName + "_pass";
	std::string filePath = username;
	filePath = "./db/." + filePath + "_pass";

	if (findHidden(fileName) == 1) {
		//.user_pass not created.
		std::cout << "File already created: " << filePath << '\n';
		return 0;
	} else {
		//create new file
		out.open(filePath);
		//create password for new user
		char newString[PASSWORD_LEN];
	  int randInt;
	  const char charlist[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	  srand(time(NULL));
	  for (int i = 0; i < PASSWORD_LEN; i++) {
	    randInt = rand() % 62;
	    newString[i] = charlist[randInt];
	  }
		newString[PASSWORD_LEN] = '\0';
	  std::string newPassword(newString); //new password is stored here.
		std::cout << "New Random password: " << newPassword << '\n';
		std::string newEncodedPass = encodePassword(newString);
		out << newEncodedPass << '\n';
		std::cout << "new password encoded: " << newEncodedPass << '\n';
		out.close();
		//encoding end
		std::cout << "Created file: " << filePath << '\n';
		//return 1 for success
		return newPassword;
	}
}

int authUN(std::string username) {
	//check for username file.
	std::string fileString = username;
	std::string fileName = username;
	fileName = "." + fileName + "_pass";
	fileString = "./db/." + fileString + "_pass";

	//return 0 for new user
	if (findHidden(fileName) != 1) {
		//.user_pass not present.
		std::cout << "File not found: " << fileString << '\n';
		return 0;
	} else {
		//return 1 for success
		std::cout << "Found file: " << fileString << '\n';
		return 1;
	}
}

int authPW(std::string username, std::string password) {
	std::ifstream in;
	std::string fileString = username;
	fileString = "./db/." + fileString + "_pass";

	in.open(fileString);
	std::string storedPass;
	in >> storedPass;
	std::string encodedPassword = encodePassword(password.c_str());
	//because of newline characters substr
	storedPass = storedPass.substr(0,ENCODED_PASSWORD_LEN);
	encodedPassword = encodedPassword.substr(0,ENCODED_PASSWORD_LEN);

	printf("Checking encoded passwords.\n");
	//return 0 for new user, which shouldn't happen.
	if (strcmp(storedPass.c_str(), encodedPassword.c_str()) == 0) {
		//return 1 for successful login
		printf("Password Encoded Match.\n");
		in.close();
		return 1;
	} else {
		//return 0 for unsuccessful login
		std::cout << "encoded passwords do not match (" << storedPass << ", " << encodedPassword << ")\n";
		in.close();
		return 0;
	}
}

void *acceptHandler(void *thread_arg) {
	struct accept_arg *thr_arg = (struct accept_arg *)thread_arg;
	int thr_fd = (intptr_t)thr_arg->fd;
	// int thr_fd = (intptr_t)thread_arg;
	char *s = thr_arg->s;

	int auth;
	char buf[MESSG_LEN];
	bool ifCommand = true;
	char command[BUFFER_LEN];
	bool ifGreeted = false;
	bool ifAuth = false;
	std::string fullEmail = "";
	std::string rcptAddr = "";
	struct log_arg sendLog;
	struct log_arg recvLog;

	//setup logging struct.
	std::string cliIP(s);
	sendLog.to_ip = cliIP;
	recvLog.from_ip = cliIP;
	sendLog.prot = "SMTP";
	recvLog.prot = "SMTP";

	if(send(thr_fd, "Hello", 5, 0) == -1) {
		perror("send");
	}
	while(1) {
			if(recv(thr_fd, buf, sizeof(buf), 0) != -1) {
				printf("Recieved %lu: %s\n",sizeof(buf), buf);
				memset(command, 0, sizeof(command));

				std::string recvtemp(buf);
				recvLog.mess = recvtemp;
				serverLog(recvLog);

				for (size_t i = 0; i < 4; i++) { //get command from recv buffer
					command[i] = buf[i];
				}

				printf("Command: %s\n", command);

				if (strcmp(command, HELO) == 0) {
					printf("Command recieved: HELO, sending 200\n");
					std::string switchTemp = "250 HELO";
					if((send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0)) !=-1) {
						//small hack to get our own IP
						recv(thr_fd, buf, sizeof(buf), 0);
						//log start
						thisIP = buf;
						sendLog.from_ip = thisIP;
						recvLog.to_ip = thisIP;
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						ifGreeted = true;
						printf("send responce to HELO command\n");
						memset(command, 0, sizeof(command));
						continue;
					}
				} else if(strcmp(command, AUTH) == 0) {
					std::string switchTemp = "334 dXNlcm5hbWU6";
					if(!ifGreeted) {
						switchTemp = "503 Bad sequence of command: HELO first.";
						send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0);
						//log start
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						continue;
					}
					//send appropriate response code(s).
					if((send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0)) !=-1) {
						//log start
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						//first time username
						recv(thr_fd, buf, sizeof(buf), 0);
						// log start
						recvLog.mess = buf;
						serverLog(recvLog);
						// log end
						std::string username(buf);
						if ((auth = authUN(username)) == 1) {
							//successful username
							//send resp
							//get and check password
							switchTemp = "334 cGFzc3dvcmQ6";
							send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0);
							recv(thr_fd, buf, sizeof(buf), 0);
							// log start
							recvLog.mess = buf;
							serverLog(recvLog);
							// log end
							std::string recvPass(buf);
							std::cout << recvPass << '\n';
							if ((auth = authPW(username, recvPass)) == 1) {
								switchTemp = "235 Successful Login";
								send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0);
								//log start
								sendLog.mess = switchTemp;
								serverLog(sendLog);
								//log end
								ifAuth = true;
								continue;
							} else {
								switchTemp = "535 Auth Credentials Invalid";
								//log start
								sendLog.mess = switchTemp;
								serverLog(sendLog);
								//log end
								send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0);
								continue;
							}
						} else {
							//unsuccessful username
							//create username/password
							std::string newPass;
							newPass = createUsername(username);
							newPass = "330 " + newPass;
							//send resp (new password)
							//log start
							sendLog.mess = switchTemp;
							serverLog(sendLog);
							//log end
							send(thr_fd, newPass.c_str(), sizeof(newPass), 0);
							std::cout << "Sent new password to client: " << newPass << '\n';
							continue;
						}
						continue;
					}
				} else if(strcmp(command, MAIL) == 0) {
					std::string switchTemp = "250 MAIL";
					if(!ifGreeted) {
						switchTemp = "503 Bad sequence of command: HELO first.";
						//log start
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0);
						continue;
					}
					if(!ifAuth) {
						switchTemp = "530 Authentication Required";
						//log start
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0);
						continue;
					}
					//Save buffer to email string + '\n'
					//send appropriate response code(s).
					if((send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0)) !=-1) {
						fullEmail = emailStrAdd(fullEmail, std::string(buf));
						printf("sent response to MAIL FROM command\n");
						continue;
					}
				} else if(strcmp(command, RCPT) == 0) {
					std::string switchTemp = "250 RCPT";
					if(!ifGreeted) {
						switchTemp = "503 Bad sequence of command: HELO first.";
						//log start
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0);
						continue;
					}
					if(!ifAuth) {
						switchTemp = "530 Authentication Required";
						//log start
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0);
						continue;
					}
					//Save buffer to email string + '\n'
					//send appropriate response code(s).
					if((send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0)) !=-1) {
						//log start
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						std::string temp(buf);
						rcptAddr = temp.substr(temp.find(":") + 1);
						fullEmail = emailStrAdd(fullEmail, std::string(buf));
						printf("sent response to RCPT TO command\n");
						continue;
					}
				} else if(strcmp(command, DATA) == 0) {
					std::string switchTemp = "354 DATA";
					if(!ifGreeted) {
						switchTemp = "503 Bad sequence of command: HELO first.";
						//log start
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0);
						continue;
					}
					if(!ifAuth) {
						switchTemp = "530 Authentication Required";
						//log start
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0);
						continue;
					}
					//Save buffer to email string + '\n'
					//send appropriate response code(s).
					// recv(thr_fd, buf, sizeof(buf), 0);
					if((send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0)) !=-1) {
						//log start
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						fullEmail = emailStrAdd(fullEmail, std::string(buf));
						addToDB(rcptAddr, fullEmail);
						fullEmail = "";
						printf("sent response to RCPT TO command\n");
						continue;
					}
				} else if(strcmp(command, QUIT) == 0) {
					std::string switchTemp = "200 QUIT";
					if(!ifGreeted) {
						switchTemp = "503 Bad sequence of command: HELO first.";
						//log start
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0);
						continue;
					}
					//Save buffer to email string + '\n'
					//send appropriate response code(s).
					if((send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0)) !=-1) {
						//log start
						sendLog.mess = switchTemp;
						serverLog(sendLog);
						//log end
						printf("sent response to QUIT TO command\n");
						break;
					}
				} else {
					// printf("Sent responce of bad request 500\n");
					std::string switchTemp = "500 Bad Command\n";
					//log start
					sendLog.mess = switchTemp;
					serverLog(sendLog);
					//log end
					send(thr_fd, switchTemp.c_str(), sizeof(switchTemp), 0);
					continue;
				}
			} else {
				perror("recv");
			}
		}
	close(thr_fd);
	return 0;
}

void revcFromHandler(int *sockfdUDP, struct sockaddr_storage UPD_connAddr, socklen_t UDP_fromLen, char* s) {
	char reqUN[BUFFER_LEN];
	char reqPW[BUFFER_LEN];
	char UDP_buf[BUFFER_LEN];
	std::string httpGet = "";
	std::string tempComm;
	char username[BUFFER_LEN];
	char httpHostname[BUFFER_LEN];
	char command[BUFFER_LEN];
	int emailCount;
	int respN;
	bool ifAuth = false;
	int auth;
	struct log_arg sendLog;
	struct log_arg recvLog;

	//setup logging struct.
	std::string cliIP(s);
	sendLog.to_ip = cliIP;
	recvLog.from_ip = cliIP;
	sendLog.prot = "HTTP";
	recvLog.prot = "HTTP";

	printf("Incoming UDP message\n");
	strcpy(UDP_buf, OK);
	if ((respN = sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen)) != -1) {
		//log start
		sendLog.mess = UDP_buf;
		serverLog(recvLog);
		//log start
		printf("Sent 200 OK\n");
		//small hack to get our own IP
		recvfrom(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, &UDP_fromLen);
		thisIP = UDP_buf;
		sendLog.from_ip = thisIP;
		recvLog.to_ip = thisIP;
		serverLog(recvLog);
	}
	while(1) {
		if((respN = recvfrom(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, &UDP_fromLen)) != -1) {
			printf("Recieved %lu: %s\n",sizeof(UDP_buf), UDP_buf);
			memset(command, 0, sizeof(command));
			//log start
			sendLog.mess = UDP_buf;
			serverLog(recvLog);
			//log start
			for (size_t i = 0; i < 3; i++) { //get command from recv buffer
				command[i] = UDP_buf[i];
			}
			//-----------------------
			//		    AUTH
			//-----------------------
			if (strcmp(command, "AUT") == 0) {
				strcpy(reqUN, "334 dXNlcm5hbWU6");
				//request username form client.
				sendto(*sockfdUDP, reqUN, sizeof(reqUN), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
				//log start
				sendLog.mess = UDP_buf;
				serverLog(sendLog);
				//log start
				//get username from client.
				recvfrom(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, &UDP_fromLen);
				//log start
				sendLog.mess = UDP_buf;
				serverLog(recvLog);
				//log start
				std::string recvUN(UDP_buf);
				if ((auth = authUN(recvUN)) == 1) {
					strcpy(reqPW, "334 cGFzc3dvcmQ6");
					//successful username Authentication
					//request password form client
					sendto(*sockfdUDP, reqPW, sizeof(reqPW), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
					//log start
					sendLog.mess = UDP_buf;
					serverLog(sendLog);
					//log start
					recvfrom(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, &UDP_fromLen);
					//log start
					sendLog.mess = UDP_buf;
					serverLog(recvLog);
					//log start
					std::string recvPass(UDP_buf);
					if ((auth = authPW(recvUN, recvPass)) == 1) {
						strcpy(UDP_buf, "235 Successful Login");
						sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
						//log start
						sendLog.mess = UDP_buf;
						serverLog(sendLog);
						//log start
						ifAuth = true;
						//send number of emails to download.
						std::string fullUsername = "<";
						fullUsername = fullUsername + recvUN + "@447.edu>";
						int emailcount = countEmails(fullUsername);
						printf("Emails Left%d\n", emailcount);
						std::string unread = "You have " + std::to_string(emailcount) + " unread emails.";
						strcpy(UDP_buf, unread.c_str());
						sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
						continue;
					} else {
						strcpy(UDP_buf, "535 Auth Credentials Invalid");
						sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
						//log start
						sendLog.mess = UDP_buf;
						serverLog(sendLog);
						//log start
						continue;
					}
					//get password from client.
				} else {
					//unsuccessful username
					//create username/password
					std::string newPass;
					newPass = createUsername(recvUN);
					newPass = "330 " + newPass;
					strcpy(UDP_buf, newPass.c_str());
					//send resp (new password)
					sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
					//log start
					sendLog.mess = UDP_buf;
					serverLog(sendLog);
					//log start
					std::cout << "Sent new password to client: " << newPass << '\n';
					continue;
				}
			}

			//-----------------------
			//		HTTP GET START
			//-----------------------
			if (strcmp(command, "GET") == 0) {
				//-----------------------
				//		HTTP 1.1 LINE 1
				//-----------------------
				size_t i = 8;
				size_t j = 0;
				while (UDP_buf[i] != '\0') {
					username[j] = UDP_buf[i];
					i++;
					j++;
				}
				tempComm = UDP_buf;
				httpGet += (tempComm);
				printf("username %s\n", username);
				std::string strUN(username);
				std::string emailAddress = "<" + strUN + "@447.edu>";
				if(indir(emailAddress) != 1) {
					strcpy(UDP_buf, "404 Not Found");
					sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
					//log start
					sendLog.mess = UDP_buf;
					serverLog(sendLog);
					//log start
					continue;
				} else {
					strcpy(UDP_buf, "200 OK");
					sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
					//log start
					sendLog.mess = UDP_buf;
					serverLog(sendLog);
					//log start
				}
				//-----------------------
				//		HTTP 1.1 LINE 1.5
				//-----------------------
				recvfrom(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, &UDP_fromLen);
				//log start
				sendLog.mess = UDP_buf;
				serverLog(recvLog);
				//log start
				tempComm = UDP_buf;
				httpGet += (tempComm + '\n');
				printf("Frag2: %s\n", tempComm.c_str());
				//-----------------------
				//		HTTP 1.1 LINE 2
				//-----------------------
				recvfrom(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, &UDP_fromLen);
				//log start
				sendLog.mess = UDP_buf;
				serverLog(recvLog);
				//log start
				tempComm = UDP_buf;
				strcpy(httpHostname, tempComm.c_str());
				httpGet += (tempComm + '\n');
				if(strcmp(httpHostname, "Host: <447.edu>") != 0) {
					strcpy(UDP_buf, "404 Not Found");
					sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
					//log start
					sendLog.mess = UDP_buf;
					serverLog(sendLog);
					//log start
					continue;
				} else {
					strcpy(UDP_buf, "200 OK");
					sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
					//log start
					sendLog.mess = UDP_buf;
					serverLog(sendLog);
					//log start
				}
				//-----------------------
				//		HTTP 1.1 LINE 3
				//-----------------------
				recvfrom(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, &UDP_fromLen);
				//log start
				sendLog.mess = UDP_buf;
				serverLog(recvLog);
				//log start
				tempComm = UDP_buf;
				httpGet += (tempComm + '\n');
				std::cout << httpGet;
				emailCount = UDP_buf[7] - '0';
				if(!(emailCount > 0)) {
					strcpy(UDP_buf, "400 Bad Request");
					sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
					//log start
					sendLog.mess = UDP_buf;
					serverLog(sendLog);
					//log start
					continue;
				} else {
					strcpy(UDP_buf, "200 OK");
					//log start
					sendLog.mess = UDP_buf;
					serverLog(sendLog);
					//log start
					sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
				}
				//-----------------------------
				//		SEND FULL HTTP RESPONCE
				//-----------------------------
				if(strcmp(httpHostname, "Host: <447.edu>") != 0) {
					strcpy(UDP_buf, "404 Not Found");
					sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
					//log start
					sendLog.mess = UDP_buf;
					serverLog(sendLog);
					//log start
				} else {
					//Responce line1
					std::string responceGET = "HTTP/ 1.1 200 OK";
					strcpy(UDP_buf, responceGET.c_str());
					sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
					//Responce line2
					responceGET = "Server: <447.edu>";
					strcpy(UDP_buf, responceGET.c_str());
					sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
					//Responce line3
					std::ifstream inf;
					std::string fp = "./db/" + emailAddress + "/00" + std::to_string(emailCount) + ".email";
					inf.open(fp, std::ifstream::in);
					std::string fullLine;
					std::getline(inf, fullLine);
					//log start
					sendLog.mess = fullLine;
					serverLog(sendLog);
					//log start
					responceGET = fullLine.substr((size_t)6);
					strcpy(UDP_buf, responceGET.c_str());
					sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
					//Responce  email
					inf.close();

					for (int i = 1; i <= emailCount; i++) {
						fp = "./db/" + emailAddress + "/00" + std::to_string(i) + ".email";
						inf.open(fp, std::ifstream::in);
						//dateline
						std::getline(inf, fullLine);
						strcpy(UDP_buf, fullLine.c_str());
						sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);

						while(std::getline(inf, fullLine)) {
							if (fullLine.length() > 5) {
								responceGET = fullLine.substr((size_t)5);
								strcpy(UDP_buf, responceGET.c_str());
								sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
							} else {
								strcpy(UDP_buf, responceGET.c_str());
								sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
							}
						}
						strcpy(UDP_buf, "\n");
						sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
						inf.close();
					}

					strcpy(UDP_buf, "END");
					sendto(*sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, UDP_fromLen);
				}
			}
			if (strcmp(command, "QUI") == 0) {
				printf("recieved QUIT command\n");
				break;
			}
		}
	}
}

int main(int argc, char* argv[]) {
	char* portTCP;
	char* portUDP;
	int portNumTCP;
	int portNumUDP;
	int sockfdTCP, sockfdUDP, new_TCP, new_UDP;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hintsTCP, hintsUDP, *servinfoTCP, *servinfoUDP, *p;
	struct sockaddr_storage their_addr, UPD_connAddr;
	socklen_t sin_size, UDP_fromLen;
	sockaddr_in add_in;
	struct stat st = {0};
	fd_set readfds;
	fd_set mainfds;
	pthread_t thread = 0;
	int one=1;
	char s[INET6_ADDRSTRLEN];
	char buf[BUFFER_LEN];
	int rvTCP, rvUDP;

	//if /db not created yet create it.
	//this would only work on Linux I believe
	if(stat("/db", &st) == -1) {
		int dir = mkdir("./db", 0777);
		if(dir != -1)
			printf("Created DB folder.\n");
		else
			printf("DB folder already created.\n");
	} else {
		printf("Couldnt create DB folder\n");
	}

	memset(&hintsTCP, 0, sizeof hintsTCP);
	hintsTCP.ai_family = AF_UNSPEC;
	hintsTCP.ai_socktype = SOCK_STREAM;
	hintsTCP.ai_flags = AI_PASSIVE;

	memset(&hintsUDP, 0, sizeof hintsUDP);
	hintsUDP.ai_family = AF_INET;
	hintsUDP.ai_socktype = SOCK_DGRAM;
	hintsUDP.ai_flags = AI_PASSIVE;

	if(argc == 3) {
		portTCP = argv[1];
		portUDP = argv[2];
		portNumTCP = atoi(portTCP);
		portNumUDP = atoi(portUDP);
		std::cout << "TCP port number entered: " << portNumTCP
				  << "\nUDP port number entered: " << portNumUDP
				  << "\n";
	} else {
		std::cout << "Bad input.\n./example <TCP port> <UDP port>\n";
		return 0;
	}

	//TCP address information.
	if ((rvTCP = getaddrinfo(NULL, portTCP, &hintsTCP, &servinfoTCP)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rvTCP));
		return 1;
	}
	// UDP address information.
	if ((rvUDP = getaddrinfo(NULL, portUDP, &hintsUDP, &servinfoUDP)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rvUDP));
		return 1;
	}

	// TCP: bind to first available socket
	for(p = servinfoTCP; p != NULL; p = p->ai_next) {
		if ((sockfdTCP = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfdTCP, SOL_SOCKET, SO_REUSEADDR, &one,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfdTCP, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfdTCP);
			perror("server: bind");
			continue;
		}
		break;
	}

	// UDP: bind to first available socket
	for(p = servinfoUDP; p != NULL; p = p->ai_next) {
		if ((sockfdUDP = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}
		if (bind(sockfdUDP, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfdUDP);
			perror("server: bind");
			continue;
		}
		break;
	}

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfdTCP, 10) == -1) {
		perror("listen");
		exit(1);
	}

	//clear fds
	FD_ZERO(&readfds);

	//keep track of biggest file descrpitor
	int fdmax = sockfdTCP;
	int nready;
	printf("server: waiting for connections...\n");
	char UDP_buf[BUFFER_LEN];
	int max_sd;

	while(1) {  // main accept()/recvfrom() loop
		//add UDP and TCP sockets to set
		FD_SET(sockfdUDP, &readfds);
		FD_SET(sockfdTCP, &readfds);

		sin_size = sizeof their_addr;
		UDP_fromLen = sizeof UPD_connAddr;

		if (select(fdmax+2, &readfds, NULL, NULL, NULL) == -1) {
				if(errno == EINTR) {
					continue;
				} else {
					perror("select");
					exit(0);
				}
    }
		//go through connections looking for incoming data.
		if(FD_ISSET(sockfdUDP, &readfds)) { //found one udp
			//for UDP connection
			if(recvfrom(sockfdUDP, UDP_buf, sizeof(UDP_buf), 0, (struct sockaddr *)&UPD_connAddr, &UDP_fromLen) != -1) {
				printf("GOT to recvfrom\n");
				inet_ntop(UPD_connAddr.ss_family,	get_in_addr((struct sockaddr *)&UPD_connAddr), s, sizeof s);
				printf("server: got communication from %s\n", s);
				if(strcmp(UDP_buf, "HELO server") == 0) {
					revcFromHandler(&sockfdUDP, UPD_connAddr, UDP_fromLen, s);
				}
			} else {
				printf("recvfrom error");
				continue;
			}
		}
		if(FD_ISSET(sockfdTCP, &readfds)) { //found one tcp
			if((new_TCP = accept(sockfdTCP, (struct sockaddr *)&their_addr, &sin_size)) != -1) {
				inet_ntop(their_addr.ss_family,	get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
				printf("server: got connection from %s\n", s);
				FD_SET(new_TCP, &mainfds);
				struct accept_arg arg;
				arg.fd = (intptr_t)new_TCP;
				arg.s = s;
				pthread_create(&thread, 0, acceptHandler, (void*)&arg);
			} else {
				perror("accept");
				continue;
			}
		}
	}
	close(sockfdTCP);
	close(sockfdUDP);
	return 0;
}
