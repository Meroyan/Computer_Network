#include<iostream>
#include<WinSock2.h>
#include<ws2tcpip.h>
#include<thread>
#include<string>

#pragma comment(lib,"ws2_32.lib")   //socket库

using namespace std;

#define PORT 8888  //端口号
#define BUFFER_SIZE 1024  //缓冲区大小

void receive_messages(SOCKET client_socket);

int main()
{
	// 初始化WinSock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		perror("初始化Socket DLL失败！\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		cout << "初始化Socket DLL成功！\n" << endl;
	}

	int client_socket;
	struct sockaddr_in server_address;	//定义服务器端和客户端地址

	//创建socket
	client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);	//使用IPv4地址，流式套接字，TCP协议
	if (client_socket == -1)	//检查socket是否创建成功
	{
		perror("创建socket失败！\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		cout << "创建socket成功！\n" << endl;
	}

	// 设置地址信息
	memset(&server_address, '0', sizeof(server_address));
	server_address.sin_family = AF_INET;	//地址类型
	//server_address.sin_addr.s_addr = inet_addr("127.0.0.1");	//服务器IP地址
	server_address.sin_port = htons(PORT);	//端口号

	if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr.s_addr) <= 0) {
		perror("连接失败！\n");
		exit(EXIT_FAILURE);
	}

	//连接到服务器
	if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
	{
		perror("连接到服务器失败！\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		cout << "连接成功！欢迎加入聊天室^_^\n" << endl;
	}

	// 启动接收消息线程
	thread receiver(receive_messages, client_socket);
	receiver.detach(); // 分离线程，使其在后台运行

	
	

	while (1)
	{
		cout << "请输入消息：（退出聊天室请输入exit）" << endl;
		string message;
		getline(cin, message);

		// 发送消息到服务器
		if (send(client_socket, message.c_str(), message.size(), 0) == SOCKET_ERROR)
		{
			perror("发送消息失败！\n");
			break;
		}
		if (message == "exit")
		{
			perror("已成功退出聊天室！\n");
			break;
		}
	}

	return 0;
}



void receive_messages(SOCKET client_socket) {
	char buffer[BUFFER_SIZE];
	while (1) {
		int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
		if (bytes_received <= 0) {
			cout << "与服务器的连接已断开。" << endl;
			break;
		}
		
		buffer[bytes_received] = '\0'; // 确保字符串结束
		cout << buffer << endl;
		

	}

	//int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
	//if (bytes_received <= 0) {
	//	cout << "与服务器的连接已断开。" << endl;
	//	return;
	//}
	//else {
	//	buffer[bytes_received] = '\0'; // 确保字符串结束
	//	cout << "收到来自客户端" << client_socket << "的消息: " << buffer << endl;
	//	cout << "请输入消息：（退出聊天室请输入exit）" << endl;
	//}
	
}