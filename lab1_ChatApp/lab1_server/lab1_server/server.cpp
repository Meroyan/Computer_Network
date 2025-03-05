#include<iostream>
#include<WinSock2.h>
#include<ws2tcpip.h>
#include<thread>
#include<ctime>
#include<cstring>

#pragma comment(lib,"ws2_32.lib")   //socket��

using namespace std;

#define PORT 8888  //�˿ں�
#define BUFFER_SIZE 1024  //��������С
SOCKET server_socket, client_sockets[5];//�ͻ���socket����

string get_current_timestamp();

DWORD WINAPI handle_client(LPVOID param);


int main()
{
	// ��ʼ��WinSock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		perror("��ʼ��Socket DLLʧ�ܣ�\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		cout << "��ʼ��Socket DLL�ɹ���\n" << endl;
	}

	;
	struct sockaddr_in server_address, client_address;	//����������˺Ϳͻ��˵�ַ
	socklen_t client_addr_len = sizeof(client_address);

	//����socket
	server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);	//ʹ��IPv4��ַ����ʽ�׽��֣�TCPЭ��
	if (server_socket == -1)	//���socket�Ƿ񴴽��ɹ�
	{
		perror("����socketʧ�ܣ� \n");
		exit(EXIT_FAILURE);
	}
	else
	{
		cout << "����socket�ɹ���\n" << endl;
	}

	// ���õ�ַ��Ϣ
	memset(&server_address, '0', sizeof(server_address));
	server_address.sin_family = AF_INET;	//��ַ����
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);	//������������IP��ַ������
	server_address.sin_port = htons(PORT);	//�˿ں�

	//��socket
	if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
	{
		perror("��ʧ�ܣ�\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		cout << "�ɹ��󶨵��˿�" << PORT << "��\n" << endl;
	}

	//���ü���
	if (listen(server_socket, 5) != 0)
	{
		perror("����ʧ�ܣ�\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		cout << "�����ɹ��� \n" << endl;
	}

	cout << "��������׼���ã��ȴ��ͻ�������^_^\n" << endl;

	memset(client_sockets, INVALID_SOCKET, sizeof(client_sockets)); // ��ʼ��Ϊ��Ч�׽���


	//ѭ�����ܿͻ�������
	while (1)
	{
		SOCKET client_socket = accept(server_socket, (struct sockaddr*)&client_address, &client_addr_len);
		if (client_socket < 0)
		{
			perror("��������ʧ�ܣ�\n");
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
			cout << "<����> - <" << client_socket << "> ��ǰ�������Ѵ����ޣ��ͻ���" << client_socket << "����ʧ�ܣ�[" << timestamp << "]" << endl;

			closesocket(client_socket);
			continue;
		}


		cout << "<����> - <" << client_socket << "> ��ӭ�ͻ�" << client_socket << "����������(>_<)  [" << timestamp << "]" << endl;

		

		//�����߳�
		HANDLE Thread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)handle_client, (LPVOID)client_socket, 0, NULL);
		if (Thread == NULL)
		{
			perror("�̴߳���ʧ�ܣ�\n");
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

	char buffer[26];  // ctime���ɵ��ַ�������
	ctime_s(buffer, sizeof(buffer), &time_now);

	// �Ƴ����з�
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
			cout << "<����> - <" << new_socket << "> �ͻ���" << new_socket << "�Ͽ�����!  [" << timestamp << "]" << endl;
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
			cout << "<�˳�> - <" << new_socket << "> �ͻ���" << new_socket << "���˳�������!  [" << timestamp << "]" << endl;

			for (int i = 0; i < 5; i++)
			{
				if (client_sockets[i] != INVALID_SOCKET && client_sockets[i] != new_socket)
				{
					char send_message[2048];
					send_message[0] = '\0';
					const char* message1 = "�ͻ���";
					char message2[20];
					sprintf_s(message2, sizeof(message2), "%d", new_socket);
					const char* message3 = "���˳������ң�";


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
		
		cout << "<�ı�> - <" << new_socket << "> �ͻ���" << new_socket << "������Ϣ:" << message << " [" << timestamp << "]" << endl;



		for (int i = 0; i < 5; i++) 
		{
			if (client_sockets[i] != INVALID_SOCKET && client_sockets[i] != new_socket) 
			{
				char send_message[2048];
				send_message[0] = '\0';
				const char* message1 = "�յ����Կͻ���";
				char message2[20];
				sprintf_s(message2, sizeof(message2), "%d", new_socket);
				const char* message3 = "����Ϣ��";
				
				
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
	

	closesocket(new_socket); // �ر�socket
	return 0;
}