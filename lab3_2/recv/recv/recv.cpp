#include "recv.h"

#include <iostream>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <string>

#pragma comment(lib,"ws2_32.lib")   //socket��

using namespace std;
Packet wo1, wo2, wo3;

std::vector<Packet> recv_buffer;



void recv_Initial()
{
    // ��ʼ��WinSock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        perror("[Recv] ��ʼ��Socket DLLʧ�ܣ�\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "[Recv] ��ʼ��Socket DLL�ɹ���" << endl;
    }

    // ���� UDP �׽���
    recv_Socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_Socket == INVALID_SOCKET) {
        perror("[Recv] ����socketʧ�ܣ�\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "[Recv] ����socket�ɹ���" << endl;
    }

    // ���÷�����ģʽ
    unsigned long on = 1;
    ioctlsocket(recv_Socket, FIONBIO, &on);

    // ���ý��ն˵�ַ
    recv_Addr.sin_family = AF_INET;
    recv_Addr.sin_port = htons(recv_Port);
    if (inet_pton(AF_INET, recv_IP.c_str(), &recv_Addr.sin_addr) <= 0) {
        cerr << "[Recv] ��Ч�ķ��Ͷ�IP��ַ��" << endl;
        closesocket(recv_Socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // ���׽���
    if (bind(recv_Socket, (sockaddr*)&recv_Addr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
        cerr << "[Recv] ��socketʧ�ܣ�" << endl;
        closesocket(recv_Socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // ���÷��͵�ַ
    send_Addr.sin_family = AF_INET;
    send_Addr.sin_port = htons(send_Port);
    if (inet_pton(AF_INET, send_IP.c_str(), &send_Addr.sin_addr) <= 0) {
        cerr << "[Recv] ��Ч�Ľ��ն�IP��ַ��" << endl;
        closesocket(recv_Socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    cout << "[Recv] ��ʼ�����Ұ�socket�ɹ���" << endl;
}

int SEND(Packet& packet)
{
    inet_pton(AF_INET, send_IP.c_str(), &packet.src_ip);
    inet_pton(AF_INET, recv_IP.c_str(), &packet.dest_ip);
    packet.src_port = recv_Port;
    packet.dest_port = send_Port;
    packet.compute_checksum();

    // sendto������socket���������������ݻ����������ͻ������ĳ��ȣ�
    // �Ե��õĴ���ʽ��Ŀ��socket�ĵ�ַ��Ŀ���ַ�ĳ���
    return sendto(recv_Socket, (char*)&packet, sizeof(packet), 0, (SOCKADDR*)&send_Addr, send_AddrLen);
}

int Connect()
{
    // �������Է��Ͷ˵ģ���һ�����ֵı���
    while (1) {
        // ���յ���һ�����ֵı�����
        if (recvfrom(recv_Socket, (char*)&wo1, sizeof(wo1), 0, (SOCKADDR*)&send_Addr, &send_AddrLen) > 0)
        {
            cout << "[Recv] �յ���һ�����ֵ�SYN����" << endl;
            wo1.Print_Message();

            // ����һ�����ֵı����Ƿ���ȷ
            // �����ϣ�SYN = 1��У���=0xffff
            if (wo1.is_SYN() && wo1.check_checksum() == 0xffff)
            {
                // ��һ�����ݰ����յ�������ȷ�ģ����͵ڶ������ֵ����ݰ�
                // ����wo2��SYN = 1��ACK = 1��
                // wo2.ack_num=wo1.seq_num+1, wo2.seq_num=in_seq+1
                wo2.set_SYN();
                wo2.set_ACK();
                wo2.ack_num = wo1.seq_num + 1;
                wo2.seq_num = ++in_seq;

                // ���͵ڶ������ݰ��ɹ�
                if (SEND(wo2) > 0)
                {
                    cout << "[Recv] ���͵ڶ������ֵ�SYN-ACK����" << endl;
                    wo2.Print_Message();
                    //float wo2_send_clock = clock();

                    // ���͵ڶ������ݰ��ɹ����ȴ����յ��������ֵ����ݰ�
                    while (1)
                    {
                        // �ɹ����յ����������ֵ����ݰ�
                        if (recvfrom(recv_Socket, (char*)&wo3, sizeof(wo3), 0, (SOCKADDR*)&send_Addr, &send_AddrLen) > 0)
                        {
                            cout << "[Recv] �յ����������ֵı���" << endl;
                            wo3.Print_Message();
                            // ���յ��ı�������ȷ��
                            // ���յ��ı���wo3ӦΪ��ACK = 1��wo3.Ack_num = wo2.seq_num+1��
                            // wo3.seq_num=wo2.ack_num��У���=0xffff
                            if (wo3.is_ACK() && (wo3.ack_num == (wo2.seq_num + 1))
                                && wo3.check_checksum() == 0xffff)
                            {
                                cout << "[Recv] �������ֽ����ɹ���" << endl;
                                return 1;
                            }

                            // ���յ��ı��ķǷ�
                            else
                            {
                                cout << "[Recv] ���������ִ����յ����Ϸ��ı���" << endl;
                                break;
                            }
                        }

                        //// ����ȴ����������ֵ����ݰ���ʱ
                        //if (clock() - wo2_send_clock > TIMEOUT_MS)
                        //{
                        //    cout << "[Recv] ��ʱ���������·��͵ڶ������ֵ�SYN���ģ����Դ�����" << resend_count << endl;
                        //    break;
                        //}

                    }

                }

                // ���͵ڶ������ݰ����ɹ�
                else
                {
                    cout << "[Recv] ���͵ڶ������ֵ�SYN-ACK����ʧ�ܣ�" << endl;
                    break;
                }


            }

            // ��һ�����ֵı��ķǷ�
            else
            {
                cout << "[Recv] ��һ�����ִ����յ����Ϸ��ı���" << endl;
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
        // ������յ�ͷ����Ϣ
        if (recvfrom(recv_Socket, (char*)&head_send, sizeof(head_send), 0, (SOCKADDR*)&send_Addr, &send_AddrLen) > 0)
        {
            //cout << "[Recv] �յ�ͷ����Ϣ�ı���" << endl;
            //head_send.Print_Message();

            // ��鱨���Ƿ���ȷ
            // �����ϣ�У���=0xffff��head_send.seq_num==in_seq+1
            if (head_send.check_checksum() == 0xffff)
            {
                // �洢���յ�����Ϣ
                string received_data(head_send.data, head_send.data_len);
                // �ҵ���һ���ո��λ�ã��ָ��ļ������ļ���С
                size_t space_pos = received_data.find(' ');
                // ��ȡ�ļ������ӿ�ͷ����һ���ո�ǰ��
                file_name = received_data.substr(0, space_pos);
                // ��ȡ�ļ���С���ӵ�һ���ո���ַ���ĩβ��
                string file_size_str = received_data.substr(space_pos + 1);
                // ���ļ���С���ַ���ת��Ϊ��ֵ
                file_length = stoi(file_size_str);

                // ����ļ������ļ���С
                //cout << "    �ļ�" << file_name << "��СΪ��" << file_length << " �ֽ�" << endl;


                // ���ûظ�����
                Packet head_recv;
                head_recv.set_ACK();
                head_recv.seq_num = ++in_seq;
                head_recv.ack_num = head_send.seq_num + 1;

                // ���ͻظ�����
                if (SEND(head_recv) > 0)
                {
                    //cout << "[Recv] ����ͷ��ȷ�ϱ���" << endl;
                    //head_recv.Print_Message();
                    break;
                }
            }

            // ���Ĳ���
            else
            {
                cout << "[Recv] �յ����Ϸ��ı���" << endl;
                exit(EXIT_FAILURE);
            }
        }
    }

    ofstream Recv_File(file_name, ios::binary);

    // ��ʼ�����ļ�����
    int need_packet_num = file_length / MAX_DATA_LENGTH;    // ��Ҫ���͵����ݰ�����
    int last_length = file_length % MAX_DATA_LENGTH;        // ʣ���

    recv_buffer.resize(need_packet_num + 1);  // ������СΪ need_packet_num

    int last_ack = -1;
    int begin_seq = in_seq;
    int count = 0;
 
    while (1)
    {
        Packet file_send;
        if (recvfrom(recv_Socket, (char*)&file_send, sizeof(file_send), 0, (SOCKADDR*)&send_Addr, &send_AddrLen) > 0)
        {

            if (file_send.offset < need_packet_num)
            {
                //cout << "[Recv] �յ�  [" << file_name << "]" << file_send.offset << "/" << need_packet_num << endl;
                //file_send.Print_Message();

                if (file_send.seq_num < in_seq + 2)
                {
                    continue;
                }

                // ��鱨���Ƿ���ȷ
                // �����ϣ�У���=0xffff��file_send.seq_num==in_seq + 2
                else if (file_send.check_checksum() == 0xffff && (file_send.seq_num == in_seq + 2))
                {
                    count = 0;
                    // �洢���յ�����Ϣ
                    Recv_File.write(file_send.data, MAX_DATA_LENGTH);
                    //cout << "[Recv] д��  [" << file_name << "]" << file_send.offset << "/" << need_packet_num << endl;


                    // ���ûظ�����
                    Packet file_recv;
                    file_recv.set_ACK();
                    file_recv.seq_num = ++in_seq;
                    file_recv.ack_num = file_recv.seq_num + 2;
                    file_recv.offset = file_recv.seq_num - begin_seq - 1;

                    // ���ͻظ�����
                    if (SEND(file_recv) > 0)
                    {
                        //cout << "[Recv] ����  [" << file_name << "]" << file_recv.offset << " / " << need_packet_num << "��ȷ�ϱ���" << endl;
                        //file_recv.Print_Message();
                        //cout << endl;

                        last_ack = file_recv.ack_num;
                    }
                }

                else if ((file_send.seq_num > in_seq + 2))
                {
                    count++;

                    // ���ûظ�����
                    Packet file_recv;
                    file_recv.set_ACK();
                    file_recv.seq_num = in_seq;
                    file_recv.ack_num = file_recv.seq_num + 2;
                    if ((in_seq - begin_seq - 1) < 0)
                    {
                        file_recv.offset = 0;
                    }
                    else
                        file_recv.offset = in_seq - begin_seq - 1;


                    // ���ͻظ�����
                    if (count <= 4 && SEND(file_recv) > 0)
                    {
                        
                        //cout << "[Recv] ���·���  [" << file_name << "]" << file_recv.offset << " / " << need_packet_num << "��ȷ�ϱ���" << endl;
                        //file_recv.Print_Message();
                        //cout << endl;
                        count = 0;
                    }
                }
            }


            if (file_send.offset == need_packet_num)
            {
                //cout << "[Recv] �յ�  [" << file_name << "]" << file_send.offset << "/" << need_packet_num << endl;
                //file_send.Print_Message();

                if (file_send.seq_num < in_seq + 2)
                {
                    continue;
                }

                // ��鱨���Ƿ���ȷ
                // �����ϣ�У���=0xffff��file_send.seq_num==in_seq + 2
                else if (file_send.check_checksum() == 0xffff && (file_send.seq_num == in_seq + 2))
                {
                    // �洢���յ�����Ϣ
                    Recv_File.write(file_send.data, last_length);

                    // ���ûظ�����
                    Packet file_recv;
                    file_recv.set_ACK();
                    file_recv.set_FIN();
                    file_recv.seq_num = ++in_seq;
                    file_recv.ack_num = file_send.seq_num + 1;
                    file_recv.offset = file_send.offset;

                    // ���ͻظ�����
                    if (SEND(file_recv) > 0)
                    {
                        //cout << "[Recv] ����  [" << file_name << "]" << file_send.offset << " / " << need_packet_num << "��ȷ�ϱ���" << endl;
                        //file_recv.Print_Message();
                        //cout << endl;
                        break;
                    }
                }


                else if ((file_send.seq_num > in_seq + 2))
                {
                    // ���ûظ�����
                    Packet file_recv;
                    file_recv.set_ACK();
                    file_recv.seq_num = in_seq;
                    file_recv.ack_num = last_ack;
                    file_recv.offset = in_seq - begin_seq - 1;

                    // ���ͻظ�����
                    if (SEND(file_recv) > 0)
                    {
                        count++;
                        //cout << "[Recv] ���·���  [" << file_name << "]" << file_recv.offset << " / " << need_packet_num << "��ȷ�ϱ���" << endl;
                        //file_recv.Print_Message();
                        //cout << endl;
                    }
                }

            }


        }
    }
    

    /*
    float last_time = clock();

    for (int i = 0; i <= need_packet_num; i++)
    {
        while (1)
        {
            Packet file_send;

            //if (clock() - last_time > TIMEOUT_MS)
            //{
            //    Packet re;
            //    re.ack_num = expected_seq - 1;
            //    re.set_ACK();
            //    for (int j = 0; j < 3; j++)
            //    {
            //        if (SEND(re) > 0)
            //        {
            //            cout << "!";
            //        }
            //    }

            //}

            if (recvfrom(recv_Socket, (char*)&file_send, sizeof(file_send), 0, (SOCKADDR*)&send_Addr, &send_AddrLen) > 0)
            {
                last_time = clock();
                cout << "[Recv] �յ�  [" << file_name << "]" << file_send.offset << "/" << need_packet_num << endl;
                file_send.Print_Message();

                // ������ݰ������к�С��������
                if (file_send.seq_num < expected_seq)
                {
                    /*Packet file_recv;
                    file_recv.set_ACK();
                    file_recv.seq_num = in_seq;
                    file_recv.ack_num = expected_seq;
                    file_recv.offset = in_seq - begin_seq - 1;

                    if (SEND(file_recv) > 0)
                    {
                        cout << "[Recv] �ظ��������ݰ�������ȷ�ϱ��� [" << file_name << "] "
                            << file_recv.offset << " / " << need_packet_num << endl;
                        file_recv.Print_Message();
                    }

                    // �����˰�������������һ�����ݰ�
                    continue;
                }

                // ������ݰ������кŵ������������к�
                if (file_send.check_checksum() == 0xffff && file_send.seq_num == expected_seq)
                {
                    // �����ۼ�ȷ�ϣ�ȷ�Ϻ�Ϊ��һ�����������к�
                    Packet file_recv;
                    file_recv.set_ACK();
                    file_recv.seq_num = ++in_seq;
                    file_recv.ack_num = expected_seq;
                    file_recv.offset = file_send.offset;

                    if (SEND(file_recv) > 0)
                    {
                        // ������������һ�����к�
                        expected_seq++;
                        recv_buffer[i] = file_send;

                        cout << "[Recv] ����  [" << file_name << "]" << file_recv.offset << " / " << need_packet_num << "��ȷ�ϱ���" << endl;
                        file_recv.Print_Message();
                        cout << endl;
                        break;
                    }

                }

                // ����յ������ݰ������кŴ������������кţ���ʾ�����ˣ������ϴε�ȷ��
                else if (file_send.seq_num != expected_seq)
                {
                    // ���ûظ����ģ��ۼ�ȷ��
                    Packet file_recv;
                    file_recv.set_ACK();
                    file_recv.seq_num = in_seq;
                    file_recv.ack_num = expected_seq;
                    file_recv.offset = in_seq - begin_seq - 1;

                    if (SEND(file_recv) > 0)
                    {
                        cout << "[Recv] ���·���  [" << file_name << "]" << file_recv.offset << " / " << need_packet_num << "��ȷ�ϱ���" << endl;
                        file_recv.Print_Message();
                        cout << endl;
                        count++;
                    }
                }
            }
        }




    }


    for (int i = 0; i < need_packet_num; i++)
    {
        Recv_File.write(recv_buffer[i].data, MAX_DATA_LENGTH);
    }
    if (last_length)
    {
        Recv_File.write(recv_buffer[need_packet_num].data, last_length);

    }

    */

}


void Disconnect()
{
    // 4�λ��ֵı���
    Packet hui1, hui2, hui3, hui4;

    while (1)
    {
        // ���յ��˵�һ�λ��ֵı���
        if (recvfrom(recv_Socket, (char*)&hui1, sizeof(hui1), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
        {
            // ���յ��ı�������ȷ��
            // ���յ��ı���hui1ӦΪ��FIN = 1��seq_num = in_seq+2��У���=0xffff
            if (hui1.is_FIN() && hui1.check_checksum() == 0xffff)
            {
                cout << "[Recv] �յ���һ�λ��ֵ�FIN����" << endl;
                hui1.Print_Message();

                // ��һ�����ݰ����յ�������ȷ�ģ����͵ڶ��λ��ֵ����ݰ�
                // ����hui2��ACK = 1��
                // hui2.ack_num=hui1.seq_num+1, hui2.seq_num=in_seq+1
                hui2.set_ACK();
                hui2.ack_num = hui1.seq_num + 1;
                hui2.seq_num = ++in_seq;

                // ���͵ڶ������ݰ��ɹ�
                if (SEND(hui2) > 0)
                {
                    cout << "[Recv] ���͵ڶ��λ��ֵ�ACK����" << endl;
                    hui2.Print_Message();

                    //���͵����λ��ֵ����ݰ�
                    // ����hui3��FIN = 1��
                    // hui3.seq_num=in_seq+1
                    hui3.set_FIN();
                    hui3.seq_num = ++in_seq;


                    // ���͵��������ݰ��ɹ�
                    if (SEND(hui3) > 0)
                    {
                        cout << "[Recv] ���͵����λ��ֵ�FIN����" << endl;
                        hui3.Print_Message();
                        float hui3_send_clock = clock();

                        while (1)
                        {
                            // �ɹ����յ����Ĵλ��ֵ����ݰ�
                            if (recvfrom(recv_Socket, (char*)&hui4, sizeof(hui4), 0, (SOCKADDR*)&send_Addr, &send_AddrLen) > 0)
                            {
                                cout << "[Recv] �յ����Ĵλ��ֵı���" << endl;
                                hui4.Print_Message();
                                // ���յ��ı�������ȷ��
                                // ���յ��ı���hui4ӦΪ��ACK = 1��hui4.Ack_num = hui3.seq_num+1��
                                // У���=0xffff
                                if (hui4.is_ACK() && (hui4.ack_num == (hui3.seq_num + 1))
                                    && wo3.check_checksum() == 0xffff)
                                {
                                    cout << "[Recv] �Ĵλ��ֳɹ���" << endl;

                                    closesocket(recv_Socket);
                                    WSACleanup();
                                    cout << "[Recv] �ر�Socket��" << endl;
                                    return;

                                }

                                // ���յ��ı��ķǷ�
                                else
                                {
                                    cout << "[Recv] ���Ĵλ��ִ����յ����Ϸ��ı���" << endl;
                                    break;
                                }
                            }

                            // �ȴ����յ��Ĵλ��ֵı��ĳ�ʱ�����·��͵����λ��ֵı���
                            if (clock() - hui3_send_clock > TIMEOUT_MS)
                            {
                                cout << "[Recv] ��ʱ���������·��͵����λ��ֵ�FIN����" << endl;
                                hui3_send_clock = clock();
                            }

                        }


                    }

                    // ���͵��������ݰ����ɹ�
                    else
                    {
                        cout << "[Recv] ���͵����λ��ֵ�FIN����ʧ�ܣ�" << endl;
                        break;
                    }

                }

                // ���͵ڶ������ݰ����ɹ�
                else
                {
                    cout << "[Recv] ���͵ڶ��λ��ֵ�ACK����ʧ�ܣ�" << endl;
                    break;
                }


            }

            // ��һ�λ��ֵı��ķǷ�
            else
            {
                cout << "[Recv] ��һ�λ��ִ����յ����Ϸ��ı���" << endl;
                hui1.Print_Message();
                break;
            }

        }
    }

}

int main()
{
    recv_Initial();
    cout << "-------------��ʼ����ɣ��ȴ�����������-------------" << endl;

    Connect();
    cout << "-------------�ɹ���������-------------" << endl;

    while (1)
    {
        int select;
        cout << "��ʾ�������ļ�������1���Ͽ�����������2" << endl;
        cin >> select;

        if (select == 1)
        {
            cout << "-------------�ȴ��ļ�������-------------" << endl;
            recv_file();

        }

        else if (select == 2)
        {
            cout << "-------------�����Ͽ�����-------------" << endl;
            Disconnect();
            return 0;
        }

        else
        {
            cout << "��ʾ�������ļ�������1���Ͽ�����������2" << endl;
        }
    }

    system("pause");

    return 0;
}
