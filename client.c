#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include "chatroom.h"

#define MAX 1024 // max buffer size
#define PORT 6789  // port number

static int sockfd;
static int stop_recv = 0;
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

void generate_menu(){
	printf("Hello dear user pls select one of the following options:\n");
	printf("EXIT\t-\t Send exit message to server - unregister ourselves from server\n");
    printf("WHO\t-\t Send WHO message to the server - get the list of current users except ourselves\n");
    printf("#<user>: <msg>\t-\t Send <MSG>> message to the server for <user>\n");
    printf("Or input messages sending to everyone in the chatroom.\n");
}

void *recv_server_msg_handler(void* _) {
    /********************************/
	/* receive message from the server and desplay on the screen*/
	/**********************************/
	// TODO: Stop recv() if server quit and restarts

	char buffer[MAX];

	while (stop_recv == 0)
	{
		memset(buffer, 0, sizeof(buffer));
		
		if (recv(sockfd, buffer, sizeof(buffer), 0) < 0)
		{
			perror("multi-threaded recv");
			exit(3);
		}
		// pthread_mutex_lock(&mutex1);
		printf("%s", buffer);
		// pthread_mutex_unlock(&mutex1);
	}

	pthread_exit(NULL);
}

int main(){

	// pthread_mutex_lock(&mutex1);
	
    int n;
	int nbytes;
	struct sockaddr_in server_addr, client_addr;
	char buffer[MAX], username[C_NAME_LEN], password[MAX];
	
	/******************************************************/
	/* create the client socket and connect to the server */
	/******************************************************/

	// create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		perror("create client socket");
		exit(3);
	}
	printf("Socket successfully created...\n");

	memset(&server_addr, 0, sizeof(&server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	// connect to server
	if (connect(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0)
	{
		perror("connect with server");
		exit(3);
	}
	printf("Connected to the server...\n");

	generate_menu();

	// recieve welcome message to enter the nickname
    bzero(buffer, sizeof(buffer));
    if (nbytes = recv(sockfd, buffer, sizeof(buffer), 0)==-1){
        perror("recv");
    }
    printf("%s", buffer);

	/*************************************/
	/* Input the nickname and send a message to the server */
	/* Note that we concatenate "REGISTER" before the name to notify the server it is the register/login message*/
	/* e.g. "tom" becomes "REGISTERtom" */
	/*******************************************/

	n = 0;
	while ((username[n++] = getchar()) != '\n');
	username[--n] = '\0';
	n = 0;

	strcpy(buffer, "REGISTER");
	strcat(buffer, username);
	if ((nbytes = send(sockfd, buffer, sizeof(buffer), 0)) < 0)
	{
		perror("send");
		exit(3);
	}
	printf("Register/Login message sent to server.\n\n");

	// recieve enter password message to enter the password
    bzero(buffer, sizeof(buffer));
    if (nbytes = recv(sockfd, buffer, sizeof(buffer), 0)==-1){
        perror("recv");
    }
    printf("%s", buffer);

	if (strncmp(buffer, "Since this is your first login", 30) == 0)
	{
		// new user: enter any new password
		bzero(buffer, sizeof(buffer));
		strcpy(buffer, "RECVPW");
	}
	else
	{
		// existing user: validate user with password
		bzero(buffer, sizeof(buffer));
		strcpy(buffer, "VALIDATE");
	}
	
	// user registration/ validation: enter password
	n = 0;
	while ((password[n++] = getchar()) != '\n');
	password[--n] = '\0';
	n = 0;
	strcat(buffer, password);
	if ((nbytes = send(sockfd, buffer, sizeof(buffer), 0)) < 0)
	{
		perror("send");
		exit(3);
	}
	printf("Password sent to server.\n\n");

    // valid password:
	// receive welcome message "welcome xx to joint the chatroom. A new account has been created." (registration case) or "welcome back! The message box contains:..." (login case)
	// invalid password:
	// receive message "Your password is incorrect" OR "Error occurred in password retrieval in the server side"
	bzero(buffer, sizeof(buffer));
    if (recv(sockfd, buffer, sizeof(buffer), 0)==-1){
        perror("recv");
    }
    printf("%s", buffer);

	if (strncmp(buffer, "Welcome", 7) == 0)
	{
		// valid password, can login and use the app successfully
		/*****************************************************/
		/* Create a thread to receive message from the server*/
		/* pthread_t recv_server_msg_thread;*/
		/*****************************************************/

	}
	else
	{
		// invalid password
		// close socket
		if (close(sockfd) < 0)
		{
			perror("close");
			exit(3);
		}
		// force exit the user
		exit(0);
	}

	pthread_t recv_server_msg_thread;

	pthread_create(&recv_server_msg_thread, NULL, &recv_server_msg_handler, NULL);
    
	// chat with the server
	for (;;) {
		bzero(buffer, sizeof(buffer));
		n = 0;
		while ((buffer[n++] = getchar()) != '\n')
			;
		// pthread_mutex_lock(&mutex1);

		if ((strncmp(buffer, "EXIT", 4)) == 0) {
			printf("Client Exit...\n");
			
			/********************************************/
			/* Send exit message to the server and exit */
			/* Remember to terminate the thread and close the socket */
			/********************************************/
			
			if (send(sockfd, buffer, sizeof(buffer), 0)<0){
				puts("Sending MSG_EXIT failed");
				exit(1);
			}

			// kill thread
			stop_recv = 1;
			pthread_join(recv_server_msg_thread, NULL);

			// close socket
			if (close(sockfd) < 0)
			{
				perror("close");
				exit(3);
			}

			// printf("Exit message sent to server\nIt's OK to close the window now OR enter ctrl+c"); // sent by server already
		}
		else if (strncmp(buffer, "WHO", 3) == 0) {
			printf("Getting user list, pls hold on...\n");
			if (send(sockfd, buffer, sizeof(buffer), 0)<0){
				puts("Sending MSG_WHO failed");
				exit(1);
			}
			printf("If you want to send a message to one of the users, pls send with the format: '#username:message'\n");
		}
		else if (strncmp(buffer, "#", 1) == 0) {
			// If the user want to send a direct message to another user, e.g., aa wants to send direct message "Hello" to bb, aa needs to input "#bb:Hello"
			
			if (send(sockfd, buffer, sizeof(buffer), 0)<0){
				printf("Sending direct message failed...");
				exit(1);
			}

		}
		else {
			/*************************************/
			/* Sending broadcast message. The send message should be of the format "username: message"*/
			/**************************************/

			char msg[MAX];
			strcpy(msg, username);
			strcat(msg, ": ");
			strcat(msg, buffer);
			if ((nbytes = send(sockfd, msg, sizeof(msg), 0)) < 0)
			{
				perror("send");
				exit(3);
			}
		}

		// pthread_mutex_unlock(&mutex1);
	}
	return 0;
}

