#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "chatroom.h"
#include <poll.h>

#define MAX 1024					 // max buffer size
#define PORT 6789					 // server port number
#define MAX_USERS 50				 // max number of users
#define MSGBOX_SUFFIX ".txt"		 // file type of message box
#define PW_FILE_SUFFIX ".pw.txt"	 // file type of password file
static unsigned int users_count = 0; // number of registered users

static user_info_t *listOfUsers[MAX_USERS] = {0}; // list of users

/*
* Function Declaration
*/

/* Add user to userList */
void user_add(user_info_t *user);
/* Determine whether the user has been registered  */
int isNewUser(char *name);
/* Get user name from userList */
char *get_username(int sockfd);
/* Get user sockfd by name */
int get_sockfd(char *name);
/* Build a new user */
user_info_t *build_new_user(int sockfd, const char *name, int state);
/* Get existing user by username */
user_info_t *get_existing_user(const char *name);
/* Get message box name for a user */
char *get_msg_box_name(const char *name);
/* Create a message box for a new user */
int create_msg_box(const char *name);
/* Write a message to receiver's message box */
int write_to_msgbox(const char *msg, user_info_t *receiver);
/* Broadcast message to all ONLINE users */
void broadcast_msg(const char *msg);
/* Broadcast message to all ONLINE users except the given user */
void broadcast_msg_except(const char *msg, user_info_t *user);
/* Send individual message to a specific user */
int send_individual_msg(const char msg[MAX], user_info_t *receiver, user_info_t *sender);
/* Receive offline messages from message box */
int receive_offline_messages(user_info_t *user);
/* Construct the WHO message and store in msg */
void construct_WHO_msg(char *msg, user_info_t *requester);
/* Breakdown a DM command and extract the sender, receiver, dest. socket fd, and message */
void breakdown_dm_command(char *sendname, char *destname, int *destsock, char *msg, const char *buffer, int sourcesock);
/* Get password file name for a user */
char *get_pw_file_name(const char *name);
/* Register user password given username */
int register_user_password(const char *username, const char *password);
/* Validate existing user by password */
int validate_user_password(user_info_t *user, const char *typed_password);
/* Retrieve password */
char *retrieve_user_password(user_info_t *user);

void add_to_pfds(struct pollfd *pfds[], int newfd, int *fd_count, int *fd_size);
void del_from_pfds(struct pollfd pfds[], int i, int *fd_count);

/*
* Function Definition
*/

/* Add user to userList */
void user_add(user_info_t *user)
{
	if (users_count == MAX_USERS)
	{
		printf("sorry the system is full, please try again later\n");
		return;
	}
	
	/***************************/
	/* add the user to the list */
	/**************************/

	// add user info to list of users and increment users_count by 1
	listOfUsers[users_count++] = user;
	
	printf("added user %s to the list\n", user->username);

	return;

}

/* Determine whether the user has been registered  */
// Return value:
// -1: True, it is a new user
// 0: False, it is not a new user
int isNewUser(char *name)
{
	int i;
	int flag = -1;
	
	/*******************************************/
	/* Compare the name with existing usernames */
	/*******************************************/

	for (i = 0; i < users_count; ++i)
	{
		// user found?
		if (strcmp(listOfUsers[i]->username, name) == 0)
		{
			flag = 0;
			break;
		}
	}

	return flag;
}

/* Get user name from userList 
* Note: This user must be ONLINE, i.e. ss must be valid (no duplication)
*/
char *get_username(int ss)
{
	int i;
	static char uname[MAX] = ""; // empty by default

	/*******************************************/
	/* Get the user name by the user's sock fd */
	/*******************************************/

	for (i = 0; i < users_count; ++i)
	{
		// user found?
		if (listOfUsers[i]->sockfd == ss)
		{
			strcpy(uname, listOfUsers[i]->username);
			break;
		}
	}

	printf("get user name: %s\n", uname);
	return uname;
}

/* Get user sockfd by name */
int get_sockfd(char *name)
{
	int i;
	int sock = -1; // -1 by default

	/*******************************************/
	/* Get the user sockfd by the user name */
	/*******************************************/

	for (i = 0; i < users_count; ++i)
	{
		// user found?
		if (listOfUsers[i]->state != REGISTRATION && strcmp(listOfUsers[i]->username, name) == 0)
		{
			sock = listOfUsers[i]->sockfd;
			break;
		}
	}

	return sock;
}

// The following two functions are defined for poll()
// Add a new file descriptor to the set
void add_to_pfds(struct pollfd *pfds[], int newfd, int *fd_count, int *fd_size)
{
	// If we don't have room, add more space in the pfds array
	if (*fd_count == *fd_size)
	{
		*fd_size *= 2; // Double it

		*pfds = (pollfd*) realloc(*pfds, sizeof(**pfds) * (*fd_size));
	}

	(*pfds)[*fd_count].fd = newfd;
	(*pfds)[*fd_count].events = POLLIN; // Check ready-to-read

	(*fd_count)++;
}

// Remove an index from the set
void del_from_pfds(struct pollfd pfds[], int i, int *fd_count)
{
	// Copy the one from the end over this one
	pfds[i] = pfds[*fd_count - 1];

	(*fd_count)--;
}

/* Build a new user (and allocate memory in heap) */
user_info_t *build_new_user(int sockfd, const char *name, int state) 
{
	user_info_t *new_user = (user_info_t*) malloc(sizeof(user_info_t));
	new_user->sockfd = sockfd;
	strcpy(new_user->username, name);
	new_user->state = state;
	
	return new_user;
}

/* Get existing user by username */
user_info_t *get_existing_user(const char *name)
{
	for (int i = 0; i < users_count; ++i)
	{
		if (strcmp(listOfUsers[i]->username, name) == 0)
		{
			return listOfUsers[i];
		}
	}

	// failed to find the existing user - logic error
	perror("Failed to find the existing user");
	exit(3);
}

/* Get message box name for a user */
char *get_msg_box_name(const char *name)
{
	static char filename[MAX];
	strcpy(filename, name);
	strcat(filename, MSGBOX_SUFFIX);
	return filename;
}

/* Create a message box for a new user 
* Return value:
* 0: Created message box file successfully
* -1: Error in creating message box file
*/
int create_msg_box(const char *name)
{
	printf("message box name: %s\n", get_msg_box_name(name));
	
	FILE* fp = fopen(get_msg_box_name(name), "w");

	if (fp == NULL)
	{
		perror("Creating file");
		return -1;
	}

	fclose(fp);
	printf("Created a message box for user %s successfully\n", name);
	return 0;
}

/* Write a message to receiver's message box 
* [IMPORTANT] Note: The message msg itself should contain \n for end of line.
*
* Return value:
* 0: Wrote message successfully
* -1: Error occurred in writing message
*/
int write_to_msgbox(const char *msg, user_info_t *receiver)
{
	// open message box in append mode
	FILE *fp = fopen(get_msg_box_name(receiver->username), "a");

	if (fp == NULL)
	{
		perror("Opening file");
		return -1;
	}

	// append content
	if (fputs(msg, fp) < 0)
	{
		perror("Writing message to file");
		return -1;
	}
	
	fclose(fp);
	printf("Wrote message to the message box of user %s successfully\n", receiver->username);
	return 0;
}

/* Broadcast message to all ONLINE users */
void broadcast_msg(const char *msg)
{
	printf("Broadcasting message: %s", msg);

	// send the same message to all users in the list
	for (int i = 0; i < users_count; ++i) {
		if (listOfUsers[i]->state == ONLINE)
		{
			send_individual_msg(msg, listOfUsers[i], NULL);
		}
	}
	return;
}

/* Broadcast message to all ONLINE users except the given user */
void broadcast_msg_except(const char *msg, user_info_t *user)
{
	printf("Broadcasting message to users except %s: %s", user->username, msg);

	for (int i = 0; i < users_count; ++i) {
		if (listOfUsers[i] == user || listOfUsers[i]->state == OFFLINE || listOfUsers[i]->state == VALIDATION || listOfUsers[i]->state == REGISTRATION)
		{
			continue;
		}
		send_individual_msg(msg, listOfUsers[i], NULL);
	}
	return;
}

/* Send individual message to a specific user
*
* [IMPORTANT] Note: To send private message, use a PM wrapper to msg to add prefix
*
* Return value:
* 0: Sent message successfully (user has received)
* 1: User is offline, stored message to his/her message box
* -1: Error occurred
*/
int send_individual_msg(const char msg[MAX], user_info_t *receiver, user_info_t *sender)
{
	printf("Sending individual message: %s\n", msg);
	// user is online?
	if (receiver->state == ONLINE)
	{
		int num_bytes = send(receiver->sockfd, msg, MAX, 0);
		// error with send()?
		if (num_bytes == -1)
		{
			char error_msg[MAX] = "send to ";
			strcat(error_msg, receiver->username);
			perror(error_msg);
			return -1;
		}
		printf("Number of bytes sent is %d\n", num_bytes);
		return 0;
	}
	
	// user is offline
	write_to_msgbox(msg, receiver);
	
	// tell sender the message is written to receiver's mailbox
	if (sender != NULL)
	{
		char offline_msg[MAX];
		strcpy(offline_msg, receiver->username);
		strcat(offline_msg, " is offline. Leaving message successfully.\n");
		send_individual_msg(offline_msg, sender, NULL);
		return 1;
	}

	perror("unknown sender to receiver mailbox");
	return -1;

}

/* Receive offline messages from message box 
*
* Return value:
* 0: Received offline messages successfully
* -1: Error occurred
*/
int receive_offline_messages(user_info_t *user)
{
	// open message box
	FILE *fp = fopen(get_msg_box_name(user->username), "r");

	if (fp == NULL)
	{
		perror("Opening file");
		return -1;
	}

	// read line by line from message box
	// 
	// note: fgets() will return NULL as well in case of error
	// We will clear the file content in message box after this
	// So it's possible that the file content is removed without sending msg due to error in fgets()
	// In the case where connection with client is lost, the message will be deleted and not recovered
	char buffer[MAX];
	memset(buffer, 0, sizeof(buffer));
	while (fgets(buffer, MAX, fp) != NULL) {
		
		// send message to user
		send_individual_msg(buffer, user, NULL);

		memset(buffer, 0, sizeof(buffer));
	}

	fclose(fp);
	
	// clear file contents
	fp = fopen(get_msg_box_name(user->username), "w");
	if (fp == NULL)
	{
		perror("Opening file for clearing file contents");
		return -1;
	}
	fclose(fp);

	return 0;
}

/* Construct the WHO message and store in msg */
void construct_WHO_msg(char *msg, user_info_t *requester)
{
	for (int i = 0; i < users_count; ++i) {
		if (listOfUsers[i]->state == REGISTRATION || strcmp(listOfUsers[i]->username, requester->username) == 0)
		{
			continue;
		}

		// append names
		strcat(msg, listOfUsers[i]->username);
		if (listOfUsers[i]->state == ONLINE)
		{
			strcat(msg, "*\t");
		}
		else
		{
			strcat(msg, "\t");
		}
	}

	// remove last "\t", and append "* means this user online\n"
	if (strlen(msg) > 0)
	{
		msg[strlen(msg) - 1] = '\n';
	}
	else
	{
		strcat(msg, "\n");
	}
	strcat(msg, "* means this user online\n");
	return;
}

/* Breakdown a DM command and extract the sender, receiver, dest. socket fd, and message from buffer and sourcesock 
*
* destsock becomes -1 if destname was not found
*/
void breakdown_dm_command(char *sendname, char *destname, int *destsock, char *msg, const char *buffer, int sourcesock)
{
	// comptue sendname
	strcpy(sendname, get_username(sourcesock));
	
	// compute destname and msg
	const char *ptr_to_colon = strchr(buffer, ':');
	int num_char_before_colon = strlen(buffer) - strlen(ptr_to_colon);
	strncpy(destname, buffer+1, num_char_before_colon-1); // skip '#'
	destname[num_char_before_colon-1] = '\0';
	strcpy(msg, ptr_to_colon+1); // skip ':'
	
	// compute destsock
	*destsock = get_sockfd(destname);
	
	return;
}

/* Get password file name for a user */
char *get_pw_file_name(const char *name)
{
	static char filename[MAX];
	strcpy(filename, name);
	strcat(filename, PW_FILE_SUFFIX);
	return filename;
}

/* Register user password given username 
*
* Return value:
* 0: Success
* -1: Error in creating or writing file
*/
int register_user_password(const char *username, const char *password)
{
	printf("pw file name: %s\n", get_pw_file_name(username));
	
	FILE* fp = fopen(get_pw_file_name(username), "w");

	if (fp == NULL)
	{
		perror("Creating file");
		return -1;
	}

	// writing pw
	if (fputs(password, fp) < 0)
	{
		perror("Writing password to pw file");
		return -1;
	}

	fclose(fp);
	printf("Created a pw file for user %s successfully\n", username);
	return 0;
}

/* Validate existing user by password
*
* Return value:
* 1: Password is valid
* 0: Password is invalid
* -1: Potential error in retrieving password
*/
int validate_user_password(user_info_t *user, const char *typed_password)
{
	char *real_password = retrieve_user_password(user);

	if (strcmp(real_password, typed_password) != 0) {
		if (strcmp(real_password, "ERROR!\n\n") == 0) {
			printf("Error occurred in password retrieval\n");
			return -1;
		}
		printf("Invalid password, attempted to login as %s\n", user->username);
		return 0;
	}

	printf("User %s supplied valid password\n", user->username);
	return 1;
}

/* Retrieve password */
char *retrieve_user_password(user_info_t *user)
{
	static char password[MAX];

	// open message box
	FILE *fp = fopen(get_pw_file_name(user->username), "r");

	if (fp == NULL)
	{
		perror("Opening file");
		strcpy(password, "ERROR!\n\n");
		return password;
	}

	// read line by line from message box
	// 
	// note: fgets() will return NULL as well in case of error
	if (fgets(password, MAX, fp) == NULL) {
		strcpy(password, "\0");
	}

	fclose(fp);

	return password;
}

int main()
{
	int listener;  // listening socket descriptor
	int newfd;	   // newly accept()ed socket descriptor
	int addr_size; // length of client addr
	struct sockaddr_in server_addr, client_addr;

	char buffer[MAX]; // buffer for client data
	int nbytes;
	int fd_count = 0;
	int fd_size = 5;
	struct pollfd *pfds = (pollfd*) malloc(sizeof *pfds * fd_size);

	int yes = 1; // for setsockopt() SO_REUSEADDR, below
	int i, j, u, rv;

	/**********************************************************/
	/*create the listener socket and bind it with server_addr*/
	/**********************************************************/

	// init listener socket
	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener == -1) {
		printf("Failed to create listener...\n");
		exit(3);
	}
	printf("Created listener successfully\n");

	// init server address
	memset(&server_addr, 0, sizeof(&server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	// bind listener to PORT
	if (bind(listener, (struct sockaddr*) &server_addr, sizeof(server_addr)) != 0) {
		printf("Failed to bind listener to port %d...\n", PORT);
		exit(3);
	}
	printf("Bind listener to port %d successfully\n", PORT);

	// Now server is ready to listen and verification
	if ((listen(listener, 5)) != 0)
	{
		printf("Listen failed...\n");
		exit(3);
	}
	printf("Server listening...\n");

	// Add the listener to set
	pfds[0].fd = listener;
	pfds[0].events = POLLIN; // Report ready to read on incoming connection
	fd_count = 1;			 // For the listener

	// main loop
	for (;;)
	{
		/***************************************/
		/* use poll function */
		/**************************************/

		int poll_count = poll(pfds, fd_count, -1);
		// poll error
		if (poll_count == -1)
		{
			perror("poll");
			exit(3);
		}

		// run through the existing connections looking for data to read
		for (i = 0; i < fd_count; i++)
		{
			printf("LOG: pfds[%d] - socket fd %d\n", i, pfds[i].fd);
			if (pfds[i].revents & POLLIN)
			{
				// we got one!!
				if (pfds[i].fd == listener)
				{
					/**************************/
					/* we are the listener and we need to handle new connections from clients */
					/****************************/
					
					// accept connection request and create connection socket
					addr_size = sizeof(client_addr);
					newfd = accept(listener, (struct sockaddr*) &client_addr, (socklen_t*) &addr_size);

					// error in accept()?
					if (newfd < -1)
					{
						perror("accept");
					}
					// error-free newfd
					else
					{
						// add newfd to pfds
						add_to_pfds(&pfds, newfd, &fd_count, &fd_size);
						printf("pollserver: new connection from %s on socket %d\n",
							inet_ntoa(client_addr.sin_addr), newfd);

						// send welcome message
						bzero(buffer, sizeof(buffer));
						strcpy(buffer, "Welcome to the chat room!\nPlease enter a nickname.\n");
						if (send(newfd, buffer, sizeof(buffer), 0) == -1)
							perror("send");
					}
				}
				else
				{
					// handle data from a client
					bzero(buffer, sizeof(buffer));
					if ((nbytes = recv(pfds[i].fd, buffer, sizeof(buffer), 0)) <= 0)
					{
						// got error or connection closed by client
						if (nbytes == 0)
						{
							// connection closed
							printf("pollserver: socket %d hung up\n", pfds[i].fd);
						}
						else
						{
							perror("recv");
						}
						close(pfds[i].fd); // Bye!
						del_from_pfds(pfds, i, &fd_count);
					}
					else
					{
						printf("LOG: %d bytes received from pfds[%d]\n", nbytes, i);
						// we got some data from a client
						if (strncmp(buffer, "REGISTER", 8) == 0)
						{
							printf("Got register/login message\n");

							/********************************/
							/* Get the user name and add the user to the userlist*/
							/**********************************/

							// extract name starting from the buffer[8]
							char name[MAX];
							strcpy(name, buffer + 8);

							if (isNewUser(name) == -1)
							{
								
								/********************************/
								/* it is a new user and we need to handle the registration*/
								/**********************************/

								user_info_t *new_user = build_new_user(pfds[i].fd, name, REGISTRATION);
								user_add(new_user);

								/********************************/
								/* create message box (e.g., a text file) for the new user */
								/**********************************/

								create_msg_box(name);

								// ask for new user password
								bzero(buffer, sizeof(buffer));
								strcpy(buffer, "Since this is your first login, please enter a new password\n");
								strcat(buffer, "(NOTE: It cannot be changed! It can be empty!)\n");
								if (send(pfds[i].fd, buffer, sizeof(buffer), 0) == -1)
								{
									perror("send");
								}

							}
							else
							{

								/********************************/
								/* it's an existing user and we need to handle the login. Note the state of user,*/
								/**********************************/

								// assume this is the real user
								// if it is not, revert the change in user states later
								user_info_t *user = get_existing_user(name);
								user->state = VALIDATION;
								user->sockfd = pfds[i].fd; // important to update new sockfd!!

								// ask for new user password
								bzero(buffer, sizeof(buffer));
								strcpy(buffer, "Please enter your password for validation:\n");
								if (send(user->sockfd, buffer, sizeof(buffer), 0) == -1)
								{
									perror("send");
								}
							}
						}
						else if (strncmp(buffer, "RECVPW", 6) == 0)
						{

							user_info_t *new_user = get_existing_user(get_username(pfds[i].fd));
							// change state from VALIDATION to ONLINE
							new_user->state = ONLINE;

							// extract pw from the buffer[6]
							char password[MAX];
							strcpy(password, buffer + 6);

							// register password
							if (register_user_password(new_user->username, password) == -1)
								perror("register new user password");

							// broadcast the welcome message (send to everyone except the listener)
							bzero(buffer, sizeof(buffer));
							strcpy(buffer, "Welcome ");
							strcat(buffer, new_user->username);
							strcat(buffer, " to join the chat room!\n");

							/*****************************/
							/* Broadcast the welcome message*/
							/*****************************/

							broadcast_msg_except(buffer, new_user);

							/*****************************/
							/* send registration success message to the new user*/
							/*****************************/

							strcat(buffer, "A new account has been created.\n");
							send_individual_msg(buffer, new_user, NULL);
						}
						else if (strncmp(buffer, "VALIDATE", 8) == 0)
						{

							user_info_t *user = get_existing_user(get_username(pfds[i].fd));

							// extract pw from the buffer[8]
							char password[MAX];
							strcpy(password, buffer + 8);

							// validate user
							int validation_result = validate_user_password(user, password);
							if (validation_result == 1)
							{
								// correct password
								
								// change state from VALIDATION to ONLINE
								user->state = ONLINE;

								/********************************/
								/* send the offline messages to the user and empty the message box*/
								/**********************************/

								send_individual_msg("Welcome back! The message box contains:\n", user, NULL);
								receive_offline_messages(user);

								// broadcast the welcome message (send to everyone except the listener)
								bzero(buffer, sizeof(buffer));
								strcat(buffer, user->username);
								strcat(buffer, " is online!\n");
								
								/*****************************/
								/* Broadcast the welcome message*/
								/*****************************/
								broadcast_msg_except(buffer, user);
							}
							else
							{
								if (validation_result == 0)
								{
									// invalid password
									bzero(buffer, sizeof(buffer));
									strcpy(buffer, "Your password is incorrect\nYou will be forced quited\n");
									if (send(user->sockfd, buffer, sizeof(buffer), 0) == -1)
									{
										perror("send");
									}
								}
								else {
									// error in password retrieval
									bzero(buffer, sizeof(buffer));
									strcpy(buffer, "Error occurred in password retrieval in the server side\nYou will be forced quited\n");
									if (send(user->sockfd, buffer, sizeof(buffer), 0) == -1)
									{
										perror("send");
									}
								}
								// revert user states
								printf("User failed to login. Removing user from system\n");

								/*********************************/
								/* Change the state of this user to offline*/
								/**********************************/
								
								user->state = OFFLINE;
								user->sockfd = -2; // -2 means user is OFFLINE

								// close the socket and remove the socket from pfds[]
								close(pfds[i].fd);
								del_from_pfds(pfds, i, &fd_count);
							}
						}
						else if (strncmp(buffer, "EXIT", 4) == 0)
						{
							printf("Got exit message. Removing user from system\n");

							// send leave message to the other members
							bzero(buffer, sizeof(buffer));
							strcpy(buffer, get_username(pfds[i].fd));
							strcat(buffer, " has left the chatroom\n");
							
							/*********************************/
							/* Broadcast the leave message to the other users in the group*/
							/**********************************/

							user_info_t *exiting_user = get_existing_user(get_username(pfds[i].fd));
							broadcast_msg_except(buffer, exiting_user);

							/*********************************/
							/* Change the state of this user to offline*/
							/**********************************/

							// signal client to exit application
							send_individual_msg(
								"Exit message sent to server\nIt's OK to close the window now OR enter ctrl+c\n",
								exiting_user,
								NULL
							);

							exiting_user->state = OFFLINE;
							exiting_user->sockfd = -2; // -2 means user is OFFLINE

							// close the socket and remove the socket from pfds[]
							close(pfds[i].fd);
							del_from_pfds(pfds, i, &fd_count);
						}
						else if (strncmp(buffer, "WHO", 3) == 0)
						{
							// concatenate all the user names except the sender into a char array
							printf("Got WHO message from client.\n");
							char WHO_msg[MAX];
							bzero(WHO_msg, sizeof(WHO_msg));

							/***************************************/
							/* Concatenate all the user names into the tab-separated char WHO_msg and send it to the requesting client*/
							/* The state of each user (online or offline)should be labelled.*/
							/***************************************/

							user_info_t *user = get_existing_user(get_username(pfds[i].fd));
							construct_WHO_msg(WHO_msg, user);
							send_individual_msg(WHO_msg, user, NULL);
						}
						else if (strncmp(buffer, "#", 1) == 0)
						{
							// send direct message
							// get send user name:
							printf("Got direct message.\n");
							// get which client sends the message
							char sendname[MAX];
							// get the destination username
							char destname[MAX];
							// get dest sock
							int destsock = -1;
							// get the message
							char msg[MAX];

							/**************************************/
							/* Get the source name xx, the target username and its sockfd*/
							/*************************************/

							breakdown_dm_command(sendname, destname, &destsock, msg, buffer, pfds[i].fd);

							if (destsock == -1)
							{
								/**************************************/
								/* The target user is not found. Send "no such user..." messsge back to the source client*/
								/*************************************/

								send_individual_msg(
									"There is no such user. Please check your input format.\n", 
									get_existing_user(sendname),
									NULL
								);
								
							}
							else
							{
								// The target user exists.
								// concatenate the message in the form "xx to you: msg"
								char sendmsg[MAX];
								strcpy(sendmsg, sendname);
								strcat(sendmsg, " to you: ");
								strcat(sendmsg, msg);

								/**************************************/
								/* According to the state of target user, send the msg to online user or write the msg into offline user's message box*/
								/* For the offline case, send "...Leaving message successfully" message to the source client*/
								/*************************************/

								send_individual_msg(sendmsg, get_existing_user(destname), get_existing_user(sendname));

							}

							// if (send(destsock, sendmsg, sizeof(sendmsg), 0) == -1)
							// {
							// 	perror("send");
							// }
						}
						else
						{
							printf("Got broadcast message from user\n");

							/*********************************************/
							/* Broadcast the message to all users except the one who sent the message*/
							/*********************************************/

							broadcast_msg_except(buffer, get_existing_user(get_username(pfds[i].fd)));
						}
					}
				} // end handle data from client
			}	  // end got new incoming connection
		}		  // end looping through file descriptors
	}			  // end for(;;)

	return 0;
}
