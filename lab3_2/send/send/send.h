#pragma once
#include <iostream>
#include <cstring>
#include <string.h>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>

#pragma comment(lib,"ws2_32.lib")   //socket��
int in_seq = 1000;

using namespace std;

// ����������󳤶�
#define MAX_DATA_LENGTH 10240
// ���ݰ�ͷ������
#define PKT_HEADER_SIZE 28
// ���ڴ�С
#define WINDOW_SIZE 20

// ��־λ
#define SYN_FLAG 0x01
#define ACK_FLAG 0x02
#define FIN_FLAG 0x04


//#define recv_Port 5555    
#define recv_Port 1111    //router
#define send_Port 6666

SOCKET recv_Socket;
SOCKADDR_IN recv_Addr;
//string recv_IP = "127.0.0.3";
string recv_IP = "127.0.0.2";   //router
int recv_AddrLen = sizeof(recv_Addr);

SOCKET send_Socket;
SOCKADDR_IN send_Addr;
string send_IP = "127.0.0.1";
int send_AddrLen = sizeof(send_Addr);

#define MAX_RETRIES 3            // ������Դ���
#define TIMEOUT_MS 1000          // ��ʱʱ�䣨���룩

// ���ݰ��ṹ
struct Packet {
    uint32_t src_ip;      // ԴIP��ַ
    uint32_t dest_ip;     // Ŀ��IP��ַ
    uint16_t src_port;    // Դ�˿�
    uint16_t dest_port;   // Ŀ�Ķ˿�
    uint32_t seq_num;     // ���к�
    uint32_t ack_num;     // ȷ�Ϻ�
    uint16_t offset;      // ƫ����
    uint16_t flags;       // ��־λ��SYN, ACK, FIN��
    uint16_t data_len;    // ���ݳ���
    uint16_t checksum;    // У���
    char data[MAX_DATA_LENGTH]; // ��������

    Packet() : src_ip(0), dest_ip(0), src_port(0), dest_port(0),
        seq_num(0), ack_num(0), offset(0), flags(0), data_len(0), checksum(0) {
        memset(this->data, 0, MAX_DATA_LENGTH);
    }

    void compute_checksum();
    uint16_t check_checksum();
    void Print_Message();

    // ���ñ�־λ
    void set_SYN() {
        this->flags |= SYN_FLAG;
    }
    void set_ACK() {
        this->flags |= ACK_FLAG;
    }
    void set_FIN() {
        this->flags |= FIN_FLAG;
    }
    


    // �жϱ�־λ
    int is_SYN() {
        return (this->flags & SYN_FLAG) ? 1 : 0;
    }
    int is_ACK() {
        return (this->flags & ACK_FLAG) ? 1 : 0;
    }
    int is_FIN() {
        return (this->flags & FIN_FLAG) ? 1 : 0;
    }
    

};

// ����У���
void Packet::compute_checksum() {
    uint32_t sum = 0;
    uint16_t* data_ptr = reinterpret_cast<uint16_t*>(this); // ���ṹ������ת��Ϊ16λ��ָ��

    // ����Packet�ṹ���ÿ��16λ��2�ֽڣ���
    size_t total_size = sizeof(Packet) / 2; // sizeof(Packet) ������ż������
    for (size_t i = 0; i < total_size; ++i) {
        sum += data_ptr[i];

        // �������������16λ�ӵ���16λ
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // ����ṹ���СΪ���������⴦�����1�ֽڣ�����Ϊ0��
    if (sizeof(Packet) % 2 != 0) {
        sum += reinterpret_cast<uint8_t*>(this)[sizeof(Packet) - 1] << 8;
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // ��תλ���洢�����У��ͣ�
    this->checksum = static_cast<uint16_t>(~(sum & 0xFFFF)); // ȷ����uint16_t����
}


// ���У���
uint16_t Packet::check_checksum() {
    uint32_t sum = 0;
    uint16_t* data_ptr = reinterpret_cast<uint16_t*>(this); // ���ṹ������ת��Ϊ16λ��ָ��

    // ����Packet�ṹ���ÿ��16λ��2�ֽڣ���
    size_t total_size = sizeof(Packet) / 2; // sizeof(Packet) ������ż������
    for (size_t i = 0; i < total_size; ++i) {
        sum += data_ptr[i];

        // �������������16λ�ӵ���16λ
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // ����ṹ���СΪ���������⴦�����1�ֽڣ�����Ϊ0��
    if (sizeof(Packet) % 2 != 0) {
        sum += reinterpret_cast<uint8_t*>(this)[sizeof(Packet) - 1] << 8;
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // ��תλ���洢�����У��ͣ�
    return static_cast<uint16_t>(sum & 0xFFFF); // ��ת��ȷ�����ص���uint16_t����
}

void Packet::Print_Message()
{
    cout << "        "
        << "[src_ip: " << this->src_ip << " ] "
        << "[dest_ip: " << this->dest_ip << " ] "
        << "[src_port: " << this->src_port << " ] "
        << "[dest_port: " << this->dest_port << " ] "
        << "[seq_num: " << this->seq_num << " ] "
        << "[ack_num: " << this->ack_num << " ] "
        << "[data_len: " << this->data_len << " ] "
        << "[offset: " << this->offset << " ] "
        << "[ACK: " << this->is_ACK() << " ] "
        << "[SYN: " << this->is_SYN() << " ] "
        << "[FIN: " << this->is_FIN() << " ] "
        << "[in_seq:" << in_seq << "]"
        << "[checksum:" << this->checksum << "]"
        << endl;
}

