int listen_fd, client_fd;
struct socaddr_in serv_addr;
socket_t client_len = sizeof(struct sockaddr_in);
int epfd, curfds, nfds, n;
struct epoll_event ev;
struct epoll_event events[1000];

epfd = epoll_create(1000);
ev.events = EPOLLIN;
ev.data.ptr
