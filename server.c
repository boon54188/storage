#include "server.h"


int main(void)
{
	int sockfd;
	pthread_t udp_tid;
	struct sockaddr_in serv_addr;
	struct sockaddr_in udp_ser_addr;
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == ERR)
		pri_err("socket");

	bzero(&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	udp_ser_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	udp_ser_addr.sin_port = htons(5000);
	//inet_pton(AF_INET, IP, &serv_addr.sin_addr);
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	udp_ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(udp_sock < 0) {
		perror("socket udp");
		exit(1);
	}
	if(bind(udp_sock, (struct sockaddr *)&udp_ser_addr, (socklen_t)sizeof(struct sockaddr)) < 0) {
		perror("bind");
		exit(1);
	}
	pthread_create(&udp_tid, NULL, pthread_udp,&udp_sock);

	//端口重用
	int on = 1;
	if((setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) == ERR)
		pri_err("setsockopt");
	if((bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) == ERR)
		pri_err("bind");
	if((listen(sockfd, MAX_USER)) == ERR)
		pri_err("listen");

	printf("waitting client connection…………\n");

	accept_client(sockfd);
	return 0;
}

void accept_client(int sockfd)
{
	int newfd, count_fd = 0;
	struct sockaddr_in client_addr;
	socklen_t len = sizeof(struct sockaddr_in);

	while(1)
	{
		if((newfd = accept(sockfd, (struct sockaddr *)&client_addr, &len)) == ERR)
			pri_err("accept");
		printf("user:%s	connect, port %d\n", inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port));

		while(count_fd < MAX_USER)
		{
			if(clients[count_fd].sockfd == SOCKET_OK)
			{
				clients[count_fd].sockfd = newfd;
				DEBUG("clients[%d]sockfd = %d\n", clients[count_fd].sockfd);
				break;
			}
		}
		if((pthread_create(&clients[count_fd].tid, NULL, pthread_func,&clients[count_fd].sockfd)) == ERR)
			pri_err("pthread_create");
		count_fd++;
	}
	close(sockfd);
	close(newfd);
}

void client_exit(sLoginInfo *send, int exit_sockfd)
{
	int count_fd;
	for(count_fd = 0; count_fd < MAX_USER; count_fd++)
	{
		if(clients[count_fd].sockfd == exit_sockfd)
		{
				break;
		}
	}
	fprintf(stderr,"user:%s	exit.\n",clients[count_fd].user_name);
	memset(&clients[count_fd], 0, sizeof(clients[count_fd]));
	close(exit_sockfd);
}

void *pthread_func(void *arg)
{
	int newfd = *((int *)arg);
	char buf[BUF_SIZE] = {0};
	int nread = 0;
	sLoginInfo send, *p_info;
	p_info = &send;
	while(1)
	{
		nread = read(newfd, &send, sizeof(send));
		if(nread <= 0)
		{
			DEBUG("recv msg is empty\n");
			break;
		}

		analyze_type(p_info, newfd);
		memset(&send, 0, sizeof(send));
	}
	client_exit(p_info, newfd);
}

void analyze_type(sLoginInfo *send, int newfd)
{
	int count;
	for(count = 0; count < pair[count].flag != 0;count++)
	{
		if(send->type == pair[count].flag)
		{
			pair[count].func(send, newfd);
			break;
		}
	}
}

void register_user(sLoginInfo *send, int newfd)
{
	pthread_mutex_lock(&g_mutex);
	char *file[3];
	char read_buf[BUF_SIZE] = {0};
	char all_buf[BUF_SIZE] = {0};
	int i,back_type = 0;
	int fd, nwrite, enter_write;
	int user_login_flag = 0;
	off_t off_len = 0;

	if((fd = open(FILENAME,O_CREAT|O_RDWR|O_APPEND,0644)) == ERR)
		pri_err("open");

	while(1)
	{
		lseek(fd, off_len, SEEK_SET);
		if(read(fd, read_buf, BUF_SIZE) == 0)
		{
			break;
		}else{
			i = 0;
			char str[BUF_SIZE] = {0};
			strcpy(str, read_buf);
			file[i++] = strtok(read_buf,":");
			while(file[i++] = strtok(NULL,":"))
				;
			if(strcmp(file[0], send->login_name) == OK)
			{
				user_login_flag = REGIST_EXITED;
				break;
			}
			off_len += strlen(str) + 2;
			memset(str, 0, sizeof(str));
		}
	}
	if(user_login_flag == REGIST_EXITED)
	{
		send->type = REGIST_EXITED; //type 51
		write(newfd, send,sizeof(sLoginInfo));
	}else{
		sprintf(all_buf, "%s:%s",send->login_name,send->login_passwd);
		nwrite = write(fd, all_buf,strlen(all_buf)+1);
		enter_write = write(fd, "\n", 1);
		if(nwrite != 0 && enter_write != 0)
		{
			send->type = REGIST_SUCCESS;//type 52
			write(newfd, send, sizeof(sLoginInfo));
		}else{
			send->type = REGIST_FAILED;//type 50
			write(newfd, send, sizeof(sLoginInfo));
		}
	}
	pthread_mutex_unlock(&g_mutex);
	close(fd);
}

void check_login(sLoginInfo *send, int newfd)
{
	char *file[3];
	char read_buf[BUF_SIZE] = {0};
	char all_buf[BUF_SIZE];
	int i = 0;
	int fd, nwrite, enter_write;
	int user_login_flag = 0;
	off_t off_len = 0;

	if((fd = open(FILENAME, O_RDONLY,0644)) == ERR)
		pri_err("open file");
	while(1)
	{
		lseek(fd, off_len, SEEK_SET);
		if(read(fd, read_buf,BUF_SIZE) == 0)
			break;
		off_len += strlen(read_buf) + 2;
		i = 0;
		file[i++] = strtok(read_buf,":");
		while(file[i++] = strtok(NULL, ":"))
			;
		if(strcmp(file[0], send->login_name) == OK)
		{
			if(strcmp(file[1], send->login_passwd) == OK)
			{
				if(init_user(file))
					send->type = USER_LOGIN_FAILED_ONLINE;//user online
				else
				{
					send->type = USER_LOGIN_SUCCESS;
				}
				break;
			}else{

				send->type = USER_LOGIN_PASSWD_ERROR;//passwd error
				break;
			}
		}else{
			send->type = USER_LOGIN_FAILED;//no user name
		}
		memset(read_buf, 0,sizeof(read_buf));
	}
	write(newfd, send, sizeof(sLoginInfo));
	get_online_user(send,newfd );
	close(fd);
}

void get_online_user(sLoginInfo *send, int newfd)
{
	int count, fd;
	char buf[BUF_SIZE] = {0};
	char user_buf[BUF_SIZE] = {0};
	char no_user_online[] = {"on user online, only you!"};
	for(count = 0; count < MAX_USER; count++)
	{
		if((clients[count].sockfd != newfd) && (clients[count].online == IS_ONLINE))
		{
			printf("%s\n", clients[count].user_name);
			send->type = USER_ONLINE;	
			send->srnm = clients[count].online;
			memcpy(send->login_name, clients[count].user_name, 25);
			write(newfd, send, sizeof(sLoginInfo));
			printf("send one\n");
			//strcat(user_buf,buf);
		}
	}
	//if(strcmp(user_buf,"") == OK)
	//	write(newfd, no_user_online, strlen(no_user_online)+1);
	//else
	//	write(newfd, user_buf, strlen(user_buf)+ 1);
}

void private_chat(sLoginInfo *send, int newfd)
{
	char dest[BUF_SIZE] = {0};
	char no_user_online[] = {"user on online!"};
	
	if(get_sockfd(send->login_name) == OK)
		write(newfd, no_user_online, strlen(no_user_online)+1);//error newfd
	else
	//	format_buf(dest,send->buf, newfd);
		;
		write(newfd, dest, strlen(dest)+1);//error newfd
}

void pri_err(char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

void *pthread_udp(void *arg)
{
	int sock = *(int *)arg;
	int len = sizeof(struct sockaddr);
	struct sockaddr_in recv_addr;
	struct udp_list *current;
	struct udp_list *current_user;
	struct udp_list *head = NULL;
	recv_addr.sin_family = AF_INET;	
	sLoginInfo msg;	
	sLoginInfo return_msg;	
	fd_set read;
		
	while(1) {
		FD_ZERO(&read);
		FD_SET(sock, &read);
		select(sock+1, &read, NULL, NULL, NULL);
		if(FD_ISSET(sock, &read)) {
			memset(&msg, 0, sizeof(sLoginInfo));
			recvfrom(sock, &msg, sizeof(sLoginInfo), 0, (struct sockaddr *)&recv_addr, (socklen_t *)&len);
			if((msg.type != HEART_DATA) && (msg.type != CHAT_RETURN)) { //接收到的是非心跳包和序列号时返回序列号
				return_msg.type = CHAT_RETURN;
				if(sendto(sock, &return_msg, sizeof(sLoginInfo), 0, (struct sockaddr *)&recv_addr, (socklen_t )(sizeof(struct sockaddr)))< 0){
					perror("sendto");	
					exit(1);
				}
			}
			switch(msg.type) {
			case HEART_DATA:
				printf("add %s to list\n", msg.login_name);
				printf("HEART_DATA\n");
				head = add_list(head, &msg, &recv_addr);	//将用户和用户的IP，端口加入链表
				if(sendto(sock, &msg, sizeof(sLoginInfo), 0, (struct sockaddr *)&recv_addr, (socklen_t )(sizeof(struct sockaddr)))< 0){
					perror("sendto");	
					exit(1);
				}
				printf("sendto OK\n");
				break;
			case PUBLIC_CHAT:
				printf("recv PUBLIC_CHAT\n");
				current = find_user(head, &recv_addr); //根据接受到的地址和端口查找用户
				memcpy(msg.login_name, current->login_name, 25);//将用户名字写入要发送MSG
				bianli_list(head, &recv_addr, sock, &msg);//便利链表，发给除发送用户的其他用户
				/*****fa song gei meige kehu *****/
				break;	
			case CHAT_REQ:
				current = check_list(head, msg.login_name);//找到要通信的用户
				current_user = find_user(head, &recv_addr);//找到请求通信的用户
				/*******bijiao recv_addr li de IP he yonghyu de shifouyizhi*****/
				if(recv_addr.sin_addr.s_addr == current->user_udp_ip) { //外网IP相同，NAT通信
					msg.type = CHAT_NAT;
					msg.port = current->user_udp_port; //发给请求者要通信用户的IP和端口
					printf("A port is %d\n", msg.port);
					msg.recv_ip = current->user_udp_ip;
					printf("Aip is %d.%d.%d.%d\n", msg.recv_ip&0xff,(msg.recv_ip>>8)&0xff,(msg.recv_ip>>16)&0xff,(msg.recv_ip>>24)&0xff);
					sendto(sock, &msg, sizeof(sLoginInfo), 0, (struct sockaddr *)&recv_addr, (socklen_t )len);

					msg.port = recv_addr.sin_port; //发给要通信的用户 请求通信用户的IP和端口
					msg.recv_ip = recv_addr.sin_addr.s_addr;
					recv_addr.sin_port = current->user_udp_port;
					recv_addr.sin_addr.s_addr = current->user_udp_ip;
					printf("user name:%s\n",current->login_name);
					memcpy(msg.login_name, current_user->login_name, 25);
					printf("B port is %d\n", msg.port);
					printf("Bip is %d.%d.%d.%d\n", msg.recv_ip&0xff,(msg.recv_ip>>8)&0xff,(msg.recv_ip>>16)&0xff,(msg.recv_ip>>24)&0xff);
					sendto(sock, &msg, sizeof(sLoginInfo), 0, (struct sockaddr *)&recv_addr, (socklen_t )len);
					printf("type is CHAT_NAT\n");
				}
				else {
					msg.type = CHAT_INET;//外网IP不一直，INET通信,给2个用户返回CHAT_INET type
					sendto(sock, &msg, sizeof(sLoginInfo), 0, (struct sockaddr *)&recv_addr, (socklen_t )len);
					memcpy(msg.login_name, current_user->login_name, USER_INFO_SIZE);
					recv_addr.sin_port = current->user_udp_port;
					recv_addr.sin_addr.s_addr = current->user_udp_ip;
					sendto(sock, &msg, sizeof(sLoginInfo), 0, (struct sockaddr *)&recv_addr, (socklen_t )len);
					printf("type is CHAT_INET\n");
				}
				break;

			case PRIVAT_CHAT: //收到消息进行转发
				current_user = check_list(head, msg.login_name);//找到接收消息的用户
				current = find_user(head, &recv_addr);   //找到发消息的用户
				printf("发送的用户是 ：%s\n", msg.login_name);
				memcpy(msg.login_name, current->login_name, USER_INFO_SIZE);
				recv_addr.sin_port = current_user->user_udp_port;  //将消息发出去
				recv_addr.sin_addr.s_addr = current_user->user_udp_ip;
				msg.srnm = current_user->srnm+1;
				current_user->srnm += 1;
				sendto(sock, &msg, sizeof(sLoginInfo), 0, (struct sockaddr *)&recv_addr, (socklen_t )len);
				break;

			case SEND_FILE:
				current_user = check_list(head, msg.login_name); //找到接收的用户后进行转发
				recv_addr.sin_port = current_user->user_udp_port;
				recv_addr.sin_addr.s_addr = current_user->user_udp_ip;
				msg.srnm = current_user->srnm+1;
				current_user->srnm += 1;
				sendto(sock, &msg, sizeof(sLoginInfo), 0, (struct sockaddr *)&recv_addr, (socklen_t )len);
				break;

			default:
				break;
			}

		}

	}
}




