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

#pragma comment(lib,"ws2_32.lib")   //socket库
int in_seq = 1000;

using namespace std;

// 数据内容最大长度
#define MAX_DATA_LENGTH 10240
// 数据包头部长度
#define PKT_HEADER_SIZE 28
// 窗口大小
#define WINDOW_SIZE 20

// 标志位
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

#define MAX_RETRIES 3            // 最大重试次数
#define TIMEOUT_MS 1000          // 超时时间（毫秒）

// 数据包结构
struct Packet {
    uint32_t src_ip;      // 源IP地址
    uint32_t dest_ip;     // 目的IP地址
    uint16_t src_port;    // 源端口
    uint16_t dest_port;   // 目的端口
    uint32_t seq_num;     // 序列号
    uint32_t ack_num;     // 确认号
    uint16_t offset;      // 偏移量
    uint16_t flags;       // 标志位（SYN, ACK, FIN）
    uint16_t data_len;    // 数据长度
    uint16_t checksum;    // 校验和
    char data[MAX_DATA_LENGTH]; // 数据内容

    Packet() : src_ip(0), dest_ip(0), src_port(0), dest_port(0),
        seq_num(0), ack_num(0), offset(0), flags(0), data_len(0), checksum(0) {
        memset(this->data, 0, MAX_DATA_LENGTH);
    }

    void compute_checksum();
    uint16_t check_checksum();
    void Print_Message();

    // 设置标志位
    void set_SYN() {
        this->flags |= SYN_FLAG;
    }
    void set_ACK() {
        this->flags |= ACK_FLAG;
    }
    void set_FIN() {
        this->flags |= FIN_FLAG;
    }
    


    // 判断标志位
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

// 计算校验和
void Packet::compute_checksum() {
    uint32_t sum = 0;
    uint16_t* data_ptr = reinterpret_cast<uint16_t*>(this); // 将结构体数据转换为16位的指针

    // 遍历Packet结构体的每个16位（2字节）段
    size_t total_size = sizeof(Packet) / 2; // sizeof(Packet) 可能是偶数长度
    for (size_t i = 0; i < total_size; ++i) {
        sum += data_ptr[i];

        // 处理溢出：将高16位加到低16位
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // 如果结构体大小为奇数，额外处理最后1字节（补充为0）
    if (sizeof(Packet) % 2 != 0) {
        sum += reinterpret_cast<uint8_t*>(this)[sizeof(Packet) - 1] << 8;
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // 反转位并存储结果（校验和）
    this->checksum = static_cast<uint16_t>(~(sum & 0xFFFF)); // 确保是uint16_t类型
}


// 检查校验和
uint16_t Packet::check_checksum() {
    uint32_t sum = 0;
    uint16_t* data_ptr = reinterpret_cast<uint16_t*>(this); // 将结构体数据转换为16位的指针

    // 遍历Packet结构体的每个16位（2字节）段
    size_t total_size = sizeof(Packet) / 2; // sizeof(Packet) 可能是偶数长度
    for (size_t i = 0; i < total_size; ++i) {
        sum += data_ptr[i];

        // 处理溢出：将高16位加到低16位
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // 如果结构体大小为奇数，额外处理最后1字节（补充为0）
    if (sizeof(Packet) % 2 != 0) {
        sum += reinterpret_cast<uint8_t*>(this)[sizeof(Packet) - 1] << 8;
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // 反转位并存储结果（校验和）
    return static_cast<uint16_t>(sum & 0xFFFF); // 反转并确保返回的是uint16_t类型
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

