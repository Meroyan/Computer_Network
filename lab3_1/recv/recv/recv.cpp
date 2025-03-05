#include "recv.h"

#include <iostream>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <string>

#pragma comment(lib,"ws2_32.lib")   //socket库

using namespace std;
Packet wo1, wo2, wo3;



void recv_Initial()
{
    // 初始化WinSock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        perror("[Recv] 初始化Socket DLL失败！\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "[Recv] 初始化Socket DLL成功！" << endl;
    }

    // 创建 UDP 套接字
    recv_Socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_Socket == INVALID_SOCKET) {
        perror("[Recv] 创建socket失败！\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "[Recv] 创建socket成功！" << endl;
    }

    // 设置非阻塞模式
    unsigned long on = 1;
    ioctlsocket(recv_Socket, FIONBIO, &on);

    // 配置接收端地址
    recv_Addr.sin_family = AF_INET;
    recv_Addr.sin_port = htons(recv_Port);
    if (inet_pton(AF_INET, recv_IP.c_str(), &recv_Addr.sin_addr) <= 0) {
        cerr << "[Recv] 无效的发送端IP地址！" << endl;
        closesocket(recv_Socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // 绑定套接字
    if (bind(recv_Socket, (sockaddr*)&recv_Addr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
        cerr << "[Recv] 绑定socket失败！" << endl;
        closesocket(recv_Socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // 配置发送地址
    send_Addr.sin_family = AF_INET;
    send_Addr.sin_port = htons(send_Port);
    if (inet_pton(AF_INET, send_IP.c_str(), &send_Addr.sin_addr) <= 0) {
        cerr << "[Recv] 无效的接收端IP地址！" << endl;
        closesocket(recv_Socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    cout << "[Recv] 初始化并且绑定socket成功！" << endl;
}

int SEND(Packet& packet)
{
    inet_pton(AF_INET, send_IP.c_str(), &packet.src_ip);
    inet_pton(AF_INET, recv_IP.c_str(), &packet.dest_ip);
    packet.src_port = recv_Port;
    packet.dest_port = send_Port;
    packet.compute_checksum();

    // sendto参数：socket描述符，发送数据缓存区，发送缓冲区的长度，
    // 对调用的处理方式，目标socket的地址，目标地址的长度
    return sendto(recv_Socket, (char*)&packet, sizeof(packet), 0, (SOCKADDR*)&send_Addr, send_AddrLen);
}

int Connect()
{
    // 接收来自发送端的，第一次握手的报文
    while (1) {
        // 接收到第一次握手的报文了
        if (recvfrom(recv_Socket, (char*)&wo1, sizeof(wo1), 0, (SOCKADDR*)&send_Addr, &send_AddrLen) > 0)
        {
            cout << "[Recv] 收到第一次握手的SYN报文" << endl;
            wo1.Print_Message();

            // 检查第一次握手的报文是否正确
            // 理论上，SYN = 1，校验和=0xffff
            if (wo1.is_SYN() && wo1.check_checksum() == 0xffff)
            {
                // 第一次数据包接收到的是正确的，发送第二次握手的数据包
                // 设置wo2，SYN = 1，ACK = 1，
                // wo2.ack_num=wo1.seq_num+1, wo2.seq_num=in_seq+1
                wo2.set_SYN();
                wo2.set_ACK();
                wo2.ack_num = wo1.seq_num + 1;
                wo2.seq_num = ++in_seq;
                
                // 发送第二次数据包成功
                if (SEND(wo2) > 0)
                {
                    cout << "[Recv] 发送第二次握手的SYN-ACK报文" << endl;
                    wo2.Print_Message();
                    //float wo2_send_clock = clock();

                    // 发送第二次数据包成功，等待接收第三次握手的数据包
                    while (1)
                    {
                        // 成功接收到第三次握手的数据包
                        if (recvfrom(recv_Socket, (char*)&wo3, sizeof(wo3), 0, (SOCKADDR*)&send_Addr, &send_AddrLen) > 0)
                        {
                            cout << "[Recv] 收到第三次握手的报文" << endl;
                            wo3.Print_Message();
                            // 接收到的报文是正确的
                            // 接收到的报文wo3应为：ACK = 1，wo3.Ack_num = wo2.seq_num+1，
                            // wo3.seq_num=wo2.ack_num，校验和=0xffff
                            if (wo3.is_ACK() && (wo3.ack_num == (wo2.seq_num + 1))
                                && wo3.check_checksum() == 0xffff)
                            {
                                cout << "[Recv] 三次握手建立成功！" << endl;
                                return 1;
                            }

                            // 接收到的报文非法
                            else
                            {
                                cout << "[Recv] 第三次握手错误！收到不合法的报文" << endl;
                                break;
                            }
                        }

                        //// 如果等待第三次握手的数据包超时
                        //if (clock() - wo2_send_clock > TIMEOUT_MS)
                        //{
                        //    cout << "[Recv] 超时，正在重新发送第二次握手的SYN报文，重试次数：" << resend_count << endl;
                        //    break;
                        //}

                    }

                }

                // 发送第二次数据包不成功
                else
                {
                    cout << "[Recv] 发送第二次握手的SYN-ACK报文失败！" << endl;
                    break;
                }
               

            }

            // 第一次握手的报文非法
            else
            {
                cout << "[Recv] 第一次握手错误！收到不合法的报文" << endl;
                cout << wo1.check_checksum() << endl;
                break;
            }
        }

    }

    
    return 0;
}

void recv_file()
{
    string file_name;
    uint32_t file_length;

    Packet head_send;

    while (1)
    {
        // 如果接收到头部信息
        if (recvfrom(recv_Socket, (char*)&head_send, sizeof(head_send), 0, (SOCKADDR*)&send_Addr, &send_AddrLen) > 0)
        {
            //cout << "[Recv] 收到头部信息的报文" << endl;
            head_send.Print_Message();

            // 检查报文是否正确
            // 理论上，校验和=0xffff，head_send.seq_num==in_seq+1
            if (head_send.check_checksum() == 0xffff )
            {
                // 存储接收到的信息
                string received_data(head_send.data, head_send.data_len);
                // 找到第一个空格的位置，分割文件名和文件大小
                size_t space_pos = received_data.find(' ');
                // 提取文件名（从开头到第一个空格前）
                file_name = received_data.substr(0, space_pos);
                // 提取文件大小（从第一个空格后到字符串末尾）
                string file_size_str = received_data.substr(space_pos + 1);
                // 将文件大小从字符串转换为数值
                file_length = stoi(file_size_str);
                
                // 输出文件名和文件大小
                //cout << "    文件" << file_name << "大小为：" << file_length << " 字节" << endl;
          

                // 设置回复报文
                Packet head_recv;
                head_recv.set_ACK();
                head_recv.seq_num = ++in_seq;
                head_recv.ack_num = head_send.seq_num + 1;

                // 发送回复报文
                if (SEND(head_recv) > 0)
                {
                    //cout << "[Recv] 发送头部确认报文" << endl;
                    //head_recv.Print_Message();
                    break;
                }
            }

            // 报文不对
            else
            {
                cout << "[Recv] 收到不合法的报文" << endl;
                exit(EXIT_FAILURE);
            }

        }

    }

    ofstream Recv_File(file_name, ios::binary);

    // 开始接收文件内容
    int need_packet_num = file_length / MAX_DATA_LENGTH;    // 需要发送的数据包个数
    int last_length = file_length % MAX_DATA_LENGTH;        // 剩余的
    for (int i = 0; i <= need_packet_num; i++)
    {
        while (1) 
        {
            Packet file_send;
            // 如果接收到信息
            if (recvfrom(recv_Socket, (char*)&file_send, sizeof(file_send), 0, (SOCKADDR*)&send_Addr, &send_AddrLen) > 0)
            {
                //cout << "[Recv] 收到  [" << file_name << "]" << i << "/" << need_packet_num << endl;
                //file_send.Print_Message();

                if (file_send.seq_num < in_seq + 2)
                {
                    continue;
                }

                // 检查报文是否正确
                // 理论上，校验和=0xffff，file_send.seq_num==in_seq + 2
                else if (file_send.check_checksum() == 0xffff && (file_send.seq_num == in_seq + 2))
                {
                    // 存储接收到的信息
                    if (i != need_packet_num)
                    {
                        Recv_File.write(file_send.data, MAX_DATA_LENGTH);
                    }
                    else
                    {
                        Recv_File.write(file_send.data, last_length);
                    }

                    // 设置回复报文
                    Packet file_recv;
                    file_recv.set_ACK();
                    file_recv.seq_num = ++in_seq;
                    file_recv.ack_num = file_send.seq_num + 1;

                    // 发送回复报文
                    if (SEND(file_recv) > 0)
                    {
                        //cout << "[Recv] 发送  [" << file_name << "]" << i << " / " << need_packet_num << "的确认报文" << endl;
                        //file_recv.Print_Message();
                        break;
                    }
                }

                // 报文不对
                else
                {
                    cout << "[Recv] 收到不合法的报文" << endl;
                    exit(EXIT_FAILURE);
                }

            }

        }
    }



}

void Disconnect()
{
    // 4次挥手的报文
    Packet hui1, hui2, hui3, hui4;

    while (1)
    {
        // 接收到了第一次挥手的报文
        if (recvfrom(recv_Socket, (char*)&hui1, sizeof(hui1), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
        {
            // 接收到的报文是正确的
            // 接收到的报文hui1应为：FIN = 1，seq_num = in_seq+2，校验和=0xffff
            if (hui1.is_FIN() && hui1.check_checksum() == 0xffff)
            {
                cout << "[Recv] 收到第一次挥手的FIN报文" << endl;
                hui1.Print_Message();

                // 第一次数据包接收到的是正确的，发送第二次挥手的数据包
                // 设置hui2，ACK = 1，
                // hui2.ack_num=hui1.seq_num+1, hui2.seq_num=in_seq+1
                hui2.set_ACK();
                hui2.ack_num = hui1.seq_num + 1;
                hui2.seq_num = ++in_seq;

                // 发送第二次数据包成功
                if (SEND(hui2) > 0)
                {
                    cout << "[Recv] 发送第二次挥手的ACK报文" << endl;
                    hui2.Print_Message();

                    //发送第三次挥手的数据包
                    // 设置hui3，FIN = 1，
                    // hui3.seq_num=in_seq+1
                    hui3.set_FIN();
                    hui3.seq_num = ++in_seq;


                    // 发送第三次数据包成功
                    if (SEND(hui3) > 0)
                    {
                        cout << "[Recv] 发送第三次挥手的FIN报文" << endl;
                        hui3.Print_Message();
                        float hui3_send_clock = clock();

                        while (1)
                        {
                            // 成功接收到第四次挥手的数据包
                            if (recvfrom(recv_Socket, (char*)&hui4, sizeof(hui4), 0, (SOCKADDR*)&send_Addr, &send_AddrLen) > 0)
                            {
                                cout << "[Recv] 收到第四次挥手的报文" << endl;
                                hui4.Print_Message();
                                // 接收到的报文是正确的
                                // 接收到的报文hui4应为：ACK = 1，hui4.Ack_num = hui3.seq_num+1，
                                // 校验和=0xffff
                                if (hui4.is_ACK() && (hui4.ack_num == (hui3.seq_num + 1))
                                    && wo3.check_checksum() == 0xffff)
                                {
                                    cout << "[Recv] 四次挥手成功！" << endl;

                                    closesocket(recv_Socket);
                                    WSACleanup();
                                    cout << "[Recv] 关闭Socket！" << endl;
                                    return;

                                }

                                // 接收到的报文非法
                                else
                                {
                                    cout << "[Recv] 第四次挥手错误！收到不合法的报文" << endl;
                                    break;
                                }
                            }
                        
                            // 等待接收第四次挥手的报文超时，重新发送第三次挥手的报文
                            if (clock() - hui3_send_clock > TIMEOUT_MS)
                            {
                                cout << "[Recv] 超时，正在重新发送第三次挥手的FIN报文" << endl;
                                hui3_send_clock = clock();
                            }

                        }


                    }

                    // 发送第三次数据包不成功
                    else
                    {
                        cout << "[Recv] 发送第三次挥手的FIN报文失败！" << endl;
                        break;
                    }

                }

                // 发送第二次数据包不成功
                else
                {
                    cout << "[Recv] 发送第二次挥手的ACK报文失败！" << endl;
                    break;
                }


            }

            // 第一次挥手的报文非法
            else
            {
                cout << "[Recv] 第一次挥手错误！收到不合法的报文" << endl;
                hui1.Print_Message();
                break;
            }

        }
    }

}

int main()
{
    recv_Initial();
    cout << "-------------初始化完成，等待建立连接中-------------" << endl;

    Connect();
    cout << "-------------成功建立连接-------------" << endl;
    
    while (1)
    {
        int select;
        cout << "提示：接收文件请输入1，断开连接请输入2" << endl;
        cin >> select;

        if (select == 1)
        {
            cout << "-------------等待文件传输中-------------" << endl;
            recv_file();
        
        }

        else if (select == 2)
        {
            cout << "-------------即将断开连接-------------" << endl;
            Disconnect();
            return 0;
        }

        else
        {
            cout << "提示：传输文件请输入1，断开连接请输入2" << endl;
        }
    }

    system("pause");

    return 0;
}
