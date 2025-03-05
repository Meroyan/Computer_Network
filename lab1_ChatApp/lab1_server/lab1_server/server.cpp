#include<iostream>
#include<WinSock2.h>
#include<ws2tcpip.h>
#include<thread>
#include<ctime>
#include<cstring>

#pragma comment(lib,"ws2_32.lib")   //socket库

using namespace std;

#define PORT 8888  //端口号
#define BUFFER_SIZE 1024  //缓冲区大小
SOCKET server_socket, client_sockets[5];//客户端socket数组

string get_current_timestamp();

DWORD WINAPI handle_client(LPVOID param);


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

	;
	struct sockaddr_in server_address, client_address;	//定义服务器端和客户端地址
	socklen_t client_addr_len = sizeof(client_address);

	//创建socket
	server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);	//使用IPv4地址，流式套接字，TCP协议
	if (server_socket == -1)	//检查socket是否创建成功
	{
		perror("创建socket失败！ \n");
		exit(EXIT_FAILURE);
	}
	else
	{
		cout << "创建socket成功！\n" << endl;
	}

	// 设置地址信息
	memset(&server_address, '0', sizeof(server_address));
	server_address.sin_family = AF_INET;	//地址类型
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);	//接受来自任意IP地址的连接
	server_address.sin_port = htons(PORT);	//端口号

	//绑定socket
	if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
	{
		perror("绑定失败！\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		cout << "成功绑定到端口" << PORT << "！\n" << endl;
	}

	//设置监听
	if (listen(server_socket, 5) != 0)
	{
		perror("监听失败！\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		cout << "监听成功！ \n" << endl;
	}

	cout << "服务器已准备好！等待客户端请求^_^\n" << endl;

	memset(client_sockets, INVALID_SOCKET, sizeof(client_sockets)); // 初始化为无效套接字


	//循环接受客户端连接
	while (1)
	{
		SOCKET client_socket = accept(server_socket, (struct sockaddr*)&client_address, &client_addr_len);
		if (client_socket < 0)
		{
			perror("接受连接失败！\n");
			continue;
		}
		
		string timestamp = get_current_timestamp();
		bool add = 0;
		
		
		for (int i = 0; i < 5; i++)
		{
			if (client_sockets[i] == INVALID_SOCKET)
			{
				client_sockets[i] = client_socket;
				add = 1;
				break;
			}
		}
		if (!add)
		{
			cout << "<错误> - <" << client_socket << "> 当前聊天室已达上限，客户端" << client_socket << "加入失败！[" << timestamp << "]" << endl;

			closesocket(client_socket);
			continue;
		}


		cout << "<连接> - <" << client_socket << "> 欢迎客户" << client_socket << "加入聊天室(>_<)  [" << timestamp << "]" << endl;

		

		//创建线程
		HANDLE Thread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)handle_client, (LPVOID)client_socket, 0, NULL);
		if (Thread == NULL)
		{
			perror("线程创建失败！\n");
			exit(EXIT_FAILURE);
		}
		else
		{
			CloseHandle(Thread);
		}
	}

	closesocket(server_socket);
	WSACleanup();

	return 0;
}

string get_current_timestamp() {
	auto now = chrono::system_clock::now();
	auto time_now = chrono::system_clock::to_time_t(now);

	char buffer[26];  // ctime生成的字符串长度
	ctime_s(buffer, sizeof(buffer), &time_now);

	// 移除换行符
	buffer[strlen(buffer) - 1] = '\0';

	return string(buffer);
}


DWORD WINAPI handle_client(LPVOID param)
{
	SOCKET new_socket = (SOCKET)(LPVOID)param;
	char buffer[BUFFER_SIZE];
	int bytes_read;

	while (1)
	{
		bytes_read = recv(new_socket, buffer, sizeof(buffer) - 1, 0);
		if (bytes_read <= 0)
		{
			string timestamp = get_current_timestamp();
			for (int i = 0; i < 5; i++)
			{
				if (client_sockets[i] == new_socket)
				{
					client_sockets[i] = INVALID_SOCKET; 
					break;
				}
			}
			cout << "<错误> - <" << new_socket << "> 客户端" << new_socket << "断开连接!  [" << timestamp << "]" << endl;
			closesocket(new_socket);

			return 0;
		}
		
		buffer[bytes_read] = '\0';

		string message(buffer);
		string timestamp = get_current_timestamp();
			
		if (message == "exit")
		{
			for (int i = 0; i < 5; i++)
			{
				if (client_sockets[i] == new_socket)
				{
					client_sockets[i] = INVALID_SOCKET;
					break;
				}
			}
			cout << "<退出> - <" << new_socket << "> 客户端" << new_socket << "已退出聊天室!  [" << timestamp << "]" << endl;

			for (int i = 0; i < 5; i++)
			{
				if (client_sockets[i] != INVALID_SOCKET && client_sockets[i] != new_socket)
				{
					char send_message[2048];
					send_message[0] = '\0';
					const char* message1 = "客户端";
					char message2[20];
					sprintf_s(message2, sizeof(message2), "%d", new_socket);
					const char* message3 = "已退出聊天室！";


					strcat_s(send_message, sizeof(send_message), message1);
					strcat_s(send_message, sizeof(send_message), message2);
					strcat_s(send_message, sizeof(send_message), message3);
					strcat_s(send_message, sizeof(send_message), " [");
					strcat_s(send_message, sizeof(send_message), timestamp.c_str());
					strcat_s(send_message, sizeof(send_message), "]");

					send(client_sockets[i], send_message, strlen(send_message), 0);
				}
			}
			closesocket(new_socket);
			return 0;
		}
		
		cout << "<文本> - <" << new_socket << "> 客户端" << new_socket << "发送消息:" << message << " [" << timestamp << "]" << endl;



		for (int i = 0; i < 5; i++) 
		{
			if (client_sockets[i] != INVALID_SOCKET && client_sockets[i] != new_socket) 
			{
				char send_message[2048];
				send_message[0] = '\0';
				const char* message1 = "收到来自客户端";
				char message2[20];
				sprintf_s(message2, sizeof(message2), "%d", new_socket);
				const char* message3 = "的消息：";
				
				
				strcat_s(send_message, sizeof(send_message), message1);
				strcat_s(send_message, sizeof(send_message), message2);
				strcat_s(send_message, sizeof(send_message), message3);
				strcat_s(send_message, sizeof(send_message), buffer);
				strcat_s(send_message, sizeof(send_message), " [");
				strcat_s(send_message, sizeof(send_message), timestamp.c_str());
				strcat_s(send_message, sizeof(send_message), "]");

				send(client_sockets[i], send_message, strlen(send_message), 0);
			}
		}

	}
	

	closesocket(new_socket); // 关闭socket
	return 0;
}