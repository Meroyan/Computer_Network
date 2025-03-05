#include<iostream>
#include<WinSock2.h>
#include<ws2tcpip.h>
#include<thread>
#include<string>

#pragma comment(lib,"ws2_32.lib")   //socket��

using namespace std;

#define PORT 8888  //�˿ں�
#define BUFFER_SIZE 1024  //��������С

void receive_messages(SOCKET client_socket);

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

	int client_socket;
	struct sockaddr_in server_address;	//����������˺Ϳͻ��˵�ַ

	//����socket
	client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);	//ʹ��IPv4��ַ����ʽ�׽��֣�TCPЭ��
	if (client_socket == -1)	//���socket�Ƿ񴴽��ɹ�
	{
		perror("����socketʧ�ܣ�\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		cout << "����socket�ɹ���\n" << endl;
	}

	// ���õ�ַ��Ϣ
	memset(&server_address, '0', sizeof(server_address));
	server_address.sin_family = AF_INET;	//��ַ����
	//server_address.sin_addr.s_addr = inet_addr("127.0.0.1");	//������IP��ַ
	server_address.sin_port = htons(PORT);	//�˿ں�

	if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr.s_addr) <= 0) {
		perror("����ʧ�ܣ�\n");
		exit(EXIT_FAILURE);
	}

	//���ӵ�������
	if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
	{
		perror("���ӵ�������ʧ�ܣ�\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		cout << "���ӳɹ�����ӭ����������^_^\n" << endl;
	}

	// ����������Ϣ�߳�
	thread receiver(receive_messages, client_socket);
	receiver.detach(); // �����̣߳�ʹ���ں�̨����

	
	

	while (1)
	{
		cout << "��������Ϣ�����˳�������������exit��" << endl;
		string message;
		getline(cin, message);

		// ������Ϣ��������
		if (send(client_socket, message.c_str(), message.size(), 0) == SOCKET_ERROR)
		{
			perror("������Ϣʧ�ܣ�\n");
			break;
		}
		if (message == "exit")
		{
			perror("�ѳɹ��˳������ң�\n");
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
			cout << "��������������ѶϿ���" << endl;
			break;
		}
		
		buffer[bytes_received] = '\0'; // ȷ���ַ�������
		cout << buffer << endl;
		

	}

	//int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
	//if (bytes_received <= 0) {
	//	cout << "��������������ѶϿ���" << endl;
	//	return;
	//}
	//else {
	//	buffer[bytes_received] = '\0'; // ȷ���ַ�������
	//	cout << "�յ����Կͻ���" << client_socket << "����Ϣ: " << buffer << endl;
	//	cout << "��������Ϣ�����˳�������������exit��" << endl;
	//}
	
}