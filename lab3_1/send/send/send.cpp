#include "send.h"


using namespace std;
Packet wo1, wo2, wo3;   // 3�����ֵ����ݰ�



void send_Initial()
{
    // ��ʼ��WinSock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        perror("[Send] ��ʼ��Socket DLLʧ�ܣ�\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "[Send] ��ʼ��Socket DLL�ɹ���" << endl;
    }

    // ���� UDP �׽���
    send_Socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_Socket == INVALID_SOCKET) {
        perror("[Send] ����socketʧ�ܣ�\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "[Send] ����socket�ɹ���" << endl;
    }

    // ���÷�����ģʽ
    unsigned long on = 1;
    ioctlsocket(send_Socket, FIONBIO, &on);

    // ���÷��Ͷ˵�ַ
    send_Addr.sin_family = AF_INET;
    send_Addr.sin_port = htons(send_Port);
    if (inet_pton(AF_INET, send_IP.c_str(), &send_Addr.sin_addr) <= 0) {
        cerr << "[Send] ��Ч�ķ��Ͷ�IP��ַ��" << endl;
        closesocket(send_Socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // ���׽���
    if (bind(send_Socket, (sockaddr*)&send_Addr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
        cerr << "[Send] ��socketʧ�ܣ�" << endl;
        closesocket(send_Socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // ����·������ַ
    recv_Addr.sin_family = AF_INET;
    recv_Addr.sin_port = htons(recv_Port);
   if (inet_pton(AF_INET, recv_IP.c_str(), &recv_Addr.sin_addr) <= 0) {
        cerr << "[Send] ��Ч�Ľ��ն�IP��ַ��" << endl;
        closesocket(send_Socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    cout << "[Send] ��ʼ�����Ұ�socket�ɹ���" << endl;
}

int SEND(Packet &packet)
{
    inet_pton(AF_INET, send_IP.c_str(), &packet.src_ip);
    inet_pton(AF_INET, recv_IP.c_str(), &packet.dest_ip);
    packet.src_port = send_Port;
    packet.dest_port = recv_Port;
    packet.compute_checksum();
    
    int result = sendto(send_Socket, (char*)&packet, sizeof(packet), 0, (SOCKADDR*)&recv_Addr, sizeof(recv_Addr));
    if (result == SOCKET_ERROR) {
        int error = WSAGetLastError();
        cout << "[Send] sendto failed with error: " << error << endl;
    }

    // sendto������socket���������������ݻ����������ͻ������ĳ��ȣ�
    // �Ե��õĴ���ʽ��Ŀ��socket�ĵ�ַ��Ŀ���ַ�ĳ���
    return result;
}

int Connect()
{
    // ���õ�һ�����ֵ����ݰ�����
    wo1.set_SYN();  // ����SYN=1����ʾϣ����������
    wo1.seq_num = ++in_seq; //seq��ʼ��Ϊin_seq+1

    int resend_count = 0;
    bool connected = false;

    while (resend_count < MAX_RETRIES && !connected)
    {
        if (SEND(wo1) > 0)
        {
            float wo1_send_clock = clock();
            cout << "[Send] ���͵�һ�����ֵ�SYN����" << endl;
            wo1.Print_Message();

            while (1)
            {
                // ���յ��˵ڶ������ֵı���
                if (recvfrom(send_Socket, (char*)&wo2, sizeof(wo2), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
                {
                    
                    // ���յ��ı�������ȷ��
                    // ���յ��ı���wo2ӦΪ��SYN = 1��ACK = 1��Ack_num = seq_num+1= 2��У���=0xffff
                    if (wo2.is_SYN() && wo2.is_ACK() && (wo2.ack_num == (wo1.seq_num + 1))
                        && wo2.check_checksum() == 0xffff)
                    {
                        cout << "[Send] �ڶ������ֳɹ���" << endl;
                        

                        // ���õ��������ֱ��ģ�ACK = 1�� wo3.seq_num = wo2.ack_num
                        // wo3.ack_num = wo2.seq_num + 1
                        wo3.set_ACK();
                        wo3.seq_num = ++in_seq;
                        wo3.ack_num = wo2.seq_num + 1;
                        
                        int wo3_send_count = 0;
                        int ack_send_res = -1;
                        // ���͵��������ֵı���
                        while (wo3_send_count < MAX_RETRIES && ack_send_res < 0)
                        {
                            ack_send_res = SEND(wo3);
                            
                            
                            // ������������ֵı��ķ��ͳɹ�
                            if (ack_send_res > 0)
                            {
                                cout << "[Send] ���͵��������ֵ�ACK����" << endl;
                                wo3.Print_Message();
                                connected = true;  // �������ֳɹ������ӽ���
                                cout << "[Send] �������ֽ����ɹ���" << endl;
                                return 1;
                            }
                            // ��������α��ķ���ʧ�ܣ����·����������
                            else
                            {
                                cout << "[Send] ���������ַ���ACKʧ�ܣ����Դ�����" << wo3_send_count + 1 << endl;
                                wo3_send_count++;
                                if (wo3_send_count < 3)
                                {
                                    cout << "[Send] �������·���ACK����..." << endl;
                                }
                                else
                                {
                                    cout << "[Send] ���������Σ�����������ʧ�ܣ�" << endl;
                                }
                            }
                        }
                        if (wo3_send_count == MAX_RETRIES && ack_send_res < 0)
                        {
                            cout << "[Send] �޷��ɹ����͵���������ACK���ģ�����ʧ�ܡ�" << endl;
                            exit(EXIT_FAILURE);
                        }
                        break;
                    }

                    // ���յ��ĵڶ������ֱ����Ǵ����
                    else
                    {
                        cout << "[Send] �ڶ������ִ����յ����Ϸ��ı���" << endl;
                        break;
                    }
                }

                // �����ʱ
                if (clock() - wo1_send_clock > TIMEOUT_MS)
                {
                    resend_count++;
                    cout << "[Send] ��ʱ���������·��͵�һ�����ֵ�SYN���ģ����Դ�����" << resend_count << endl;
                    break; 
                }
            }

        }

        // ��һ�����ֱ��ķ���ʧ��
        else 
        {
            cout << "[Send] ���͵�һ�����ֵ�SYN����ʧ�ܣ�" << endl; 
            break;
        }
    }

    // ���������Σ�����ʧ��
    if (!connected)
    {
        cout << "[Send] ��������ʧ�ܣ���������ʧ�ܣ�" << endl;
        exit(EXIT_FAILURE);
    }

    return 0;
}

void send_file(string& file_path)
{
    ifstream file(file_path, ios::binary);

    // ��ȡ�ļ���
    size_t pos = file_path.find_last_of("\\/");
    string file_name= file_path.substr(pos + 1);

    if (!file.is_open()) {
        cout << "    ���ļ�" << file_name << "ʧ��!" << endl;
        exit(EXIT_FAILURE);
    }

    // ��ȡ�ļ���С
    file.seekg(0, ios::end);  // �ƶ��ļ�ָ�뵽�ļ�ĩβ
    uint32_t file_length = static_cast<uint32_t>(file.tellg());  // ��ȡ�ļ���С���ֽڣ�
    file.seekg(0, ios::beg);  // �����ļ�ָ�뵽�ļ���ͷ

    cout << "    �ļ�" << file_name << "��СΪ" << file_length << "�ֽ�" << endl;

    // ����һ�����ݰ�����ʾ�ļ�ͷ
    // �����������ļ������ƣ��Լ��ļ��ĳ��ȣ�����send_head.seq_num=in_seq+1
    Packet send_head;

    //�ļ��� + �ļ���С
    string data_to_send = file_name + " " + to_string(file_length);
    strcpy_s(send_head.data, sizeof(send_head.data), data_to_send.c_str());
    send_head.data[strlen(send_head.data)] = '\0';
    // ����data_lenΪdata��ʵ�ʳ���
    send_head.data_len = static_cast<uint16_t>(data_to_send.length());
    send_head.seq_num = ++in_seq;

    cout << "[Send] ����" << file_name << "��ͷ����Ϣ" << endl;
    SEND(send_head);
    //send_head.Print_Message();

    // ��¼����ʱ��
    float send_head_time = clock();
    float start_time = clock();

    // �ȴ�����ȷ�ϱ���
    while (1)
    {
        Packet re_head;

        // ���յ���ͷ����ȷ�ϱ���
        if (recvfrom(send_Socket, (char*)&re_head, sizeof(re_head), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
        {
            // �����յ���ȷ�����ݰ��Ƿ���ȷ
            // ������Ӧ���� ACK = 1��re_head.ack_num = send_head.ack_num+1��
            // У����޴�
            if (re_head.is_ACK() && (re_head.ack_num == (send_head.seq_num + 1))
                && re_head.check_checksum() == 0xffff)
            {
                //cout << "[Send] �յ�" << file_name << "��ͷ��ȷ�ϱ��ģ�׼����������" << endl;
                //re_head.Print_Message();
                
                // ����in_seq
                //in_seq = re_head.ack_num;
                break;
            }

            // ���ݰ�����
            else
            {
                cout << "[Send] �յ����Ϸ��ı���" << endl;
                //re_head.Print_Message();
                break;
            }

        }

        // ���δ���յ�ȷ�ϱ���-��ʱ
        if (clock() - send_head_time > TIMEOUT_MS)
        {
            // ���·���
            int result = sendto(send_Socket, (char*)&send_head, sizeof(send_head), 0, (SOCKADDR*)&recv_Addr, sizeof(recv_Addr));
            
            if (result > 0)
            {
                //cout << "[Send] ����ͷ��ȷ�ϱ��ĳ�ʱ���������·���" << file_name << "��ͷ����Ϣ" << endl;
                //send_head.Print_Message();
                // ���·��ͺ��������ȷ�ϱ���
                send_head_time = clock();  // ���÷���ʱ��
                continue;  // �����ȴ�ȷ�ϱ���
            }

            else
            {
                //cout << "[Send] ����ͷ��ȷ�ϱ��ĳ�ʱ�����·���" << file_name << "��ͷ����Ϣʧ�ܣ�" << endl;
                exit(EXIT_FAILURE);
            }
        }
    }
    

    // ��ʼ�����ļ�����
    int need_packet_num = file_length / MAX_DATA_LENGTH;    // ��Ҫ���͵����ݰ�����
    int last_length = file_length % MAX_DATA_LENGTH;        // ʣ���


    for (int i = 0; i <= need_packet_num; i++)
    {
        Packet file_send;
        if (i < need_packet_num) 
        {
            // ��ȡ�������ݣ��������ݰ�
            file.read(file_send.data, MAX_DATA_LENGTH);
            file_send.data_len = MAX_DATA_LENGTH;
            file_send.seq_num = ++in_seq;
            file_send.ack_num = file_send.seq_num - 1;
            
        }

        else if (i == need_packet_num)
        {
            // ��ȡ��������
            file.read(file_send.data, last_length);
            file_send.data_len = last_length;
            file_send.seq_num = ++in_seq;
            file_send.ack_num = file_send.seq_num - 1;
        }

        // ���ݷ��ͳɹ�
        if (SEND(file_send) > 0)
        {
            // ��¼����ʱ��
            float time_send_file = clock();
            float time_use = 0;

            //cout << "[Send] ����  [" << file_name << "]" << i << "/" << need_packet_num << endl;
            //file_send.Print_Message();

            Packet file_recv;
            bool success = false;  // ���ڿ����Ƿ�ɹ����յ�ȷ�ϱ���
            while (1)
            {
                // ���յ���ȷ�ϱ���
                if (recvfrom(send_Socket, (char*)&file_recv, sizeof(file_recv), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
                {
                    // �����յ���ȷ�����ݰ��Ƿ���ȷ
                    // ������Ӧ���� ACK = 1��file_recv.ack_num = file_send.ack_num+1��
                    // У����޴�
                    if (file_recv.is_ACK() && (file_recv.ack_num == (file_send.seq_num + 1))
                        && file_recv.check_checksum() == 0xffff)
                    {
                        //cout << "[Send] �յ�  [" << file_name << "]" << i << "/" << need_packet_num << "��ȷ�ϱ���" << endl;
                        //file_recv.Print_Message();

                        // ����in_seq
                        //in_seq = file_recv.ack_num;
                        success = true;
                        break;
                    }

                    // ���ݰ�����
                    else
                    {
                        cout << "[Send] �յ����Ϸ��ı���" << endl;
                        file_recv.Print_Message();
                        break;
                    }

                }

                // ���δ���յ�ȷ�ϱ���-��ʱ
                if (clock() - time_send_file > TIMEOUT_MS)
                {
                    // ���·���
                    int result = sendto(send_Socket, (char*)&file_send, sizeof(file_send), 0, (SOCKADDR*)&recv_Addr, sizeof(recv_Addr));

                    if (result > 0)
                    {
                        //cout << "[Send] ���·���  [" << file_name << "]" << i << "/" << need_packet_num << endl;
                        //file_send.Print_Message();

                        // ���·��ͺ��������ȷ�ϱ���
                        time_send_file = clock();  // ���÷���ʱ��
                        continue;  // �����ȴ�ȷ�ϱ���
                    }

                    else
                    {
                        cout << "[Send] ����ȷ�ϱ��ĳ�ʱ�����·���" << file_name << "�Ĳ�����Ϣ" << i << "/" << need_packet_num << "ʧ�ܣ�" << endl;
                        exit(EXIT_FAILURE);
                    }
                }


            }

            // ����ɹ����յ�ȷ�ϱ��ģ������������һ�����ݰ�
            if (!success) {
                // ��������г�����û�гɹ����յ��Ϸ���ȷ�ϱ��ģ�ֹͣ����
                cout << "[Send] ����ʧ�ܣ�ֹͣ�����ļ�" << endl;
                exit(EXIT_FAILURE);
            }
        }


    }

    // ����ʱ��
    float end_time = clock();

    // ���㴫��ʱ��
    float transfer_time = (end_time - start_time) * 1000 / CLOCKS_PER_SEC;  // ת��Ϊ����
    cout << "[Send] �ļ�������ʱ��: " << transfer_time << " ����" << endl;

    // ����������
    float throughput = static_cast<float>(file_length) / transfer_time;  // ��λ���ֽ�/����
    float throughput_bps = throughput * 8;  // ��λ������/����
    cout << "[Send] �ļ�����������: " << throughput_bps << " ����/����" << endl;

    // ��������ʱ��
    cout << "[Send] ��������ʱ�ӣ�" << transfer_time / need_packet_num << " ����" << endl;
    file.close();

    file.close();
}

void Disconnect()
{
    // 4�λ��ֵı���
    Packet hui1, hui2, hui3, hui4;

    // ���õ�һ�λ��ֵı��ĸ�ʽ
    hui1.set_FIN();
    hui1.seq_num = ++in_seq;

        // ��һ�λ��ֱ��ķ��ͳɹ�
    if (SEND(hui1) > 0)
    {
        float hui1_send_clock = clock();
        cout << "[Send] ���͵�һ�λ��ֵ�FIN����" << endl;
        hui1.Print_Message();

        while (1)
        {
            // ���յ��˵ڶ��λ��ֵı���
            if (recvfrom(send_Socket, (char*)&hui2, sizeof(hui2), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
            {
                // ���յ��ı�������ȷ��
                // ���յ��ı���hui2ӦΪ��ACK = 1��Ack_num = seq_num+1��У���=0xffff
                if (hui2.is_ACK() && (hui2.ack_num == (hui1.seq_num + 1))
                    && hui2.check_checksum() == 0xffff)
                {
                    cout << "[Send] �յ��ڶ��λ��ֵ�ACK����" << endl;
                    hui2.Print_Message();

                    cout << "[Send] �ڶ��λ��ֳɹ���" << endl;

                    while (1)
                    {
                        // ���յ��˵����λ��ֵı���
                        if (recvfrom(send_Socket, (char*)&hui3, sizeof(hui3), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
                        {
                            // ���յ��ı�������ȷ��
                            // ���յ��ı���hui3ӦΪ��FIN = 1��seq_num = seq_num+1��У���=0xffff
                            if (hui3.is_FIN() && (hui3.seq_num == (hui2.seq_num + 1))
                                && hui3.check_checksum() == 0xffff)
                            {
                                cout << "[Send] �յ������λ��ֵ�FIN����" << endl;
                                hui3.Print_Message();

                                cout << "[Send] �����λ��ֳɹ���" << endl;


                                // ���õ��Ĵλ��ֱ��ģ�ACK = 1�� hui4.seq_num = ++in_seq
                                // hui4.ack_num = hui3.seq_num + 1
                                hui4.set_ACK();
                                hui4.seq_num = ++in_seq;
                                hui4.ack_num = hui3.seq_num + 1;

                                // ���͵��Ĵλ��ֵı���
                                // ���Ĵλ��ֱ��ķ��ͳɹ�
                                if (SEND(hui4) > 0)
                                {
                                    float hui4_send_clock = clock();
                                    cout << "[Send] ���͵��Ĵλ��ֵ�ACK����" << endl;
                                    hui4.Print_Message();

                                    //// �ȴ�2MSLʱ�䣬�ر�����
                                    //if (clock() - hui4_send_clock > 2 * TIMEOUT_MS)
                                    //{
                                    //    closesocket(send_Socket);
                                    //    WSACleanup();
                                    //    cout << "[Send] �ر�Socket��" << endl;
                                    //}
                                    cout << "[Send] �Ĵλ��ֳɹ�" << endl;

                                    closesocket(send_Socket);
                                    WSACleanup();
                                    cout << "[Send] �ر�Socket��" << endl;
                                    return;
                                }


                                // ���Ĵλ��ֱ��ķ���ʧ��
                                else
                                {
                                    cout << "[Send] ���͵��Ĵλ��ֵ�ACK����ʧ�ܣ�" << endl;
                                    break;
                                }

                            }

                            // ���յ��ĵ��������ֱ����Ǵ����
                            else
                            {
                                cout << "[Send] �����λ��ִ����յ����Ϸ��ı���" << endl;
                                break;
                            }


                        }

                    }

                }

                // ���յ��ĵڶ������ֱ����Ǵ����
                else
                {
                    cout << "[Send] �ڶ��λ��ִ����յ����Ϸ��ı���" << endl;
                    hui2.Print_Message();
                    break;
                }

            }

            // �ȴ����յڶ��λ��ֵı��ĳ�ʱ�����·��͵�һ�λ��ֵı���
            if (clock() - hui1_send_clock > TIMEOUT_MS)
            {
                cout << "[Send] ��ʱ���������·��͵�һ�λ��ֵ�FIN����" << endl;
                hui1_send_clock = clock();
            }

        }

    }

    // ��һ�λ��ֱ��ķ���ʧ��
    else
    {
        cout << "[Send] ���͵�һ�λ��ֵ�FIN����ʧ�ܣ�" << endl;

    }


}


int main()
{
    send_Initial();
    cout << "-------------��ʼ����ɣ����Խ���������-------------" << endl;
    
    Connect();
    cout << "-------------�ɹ���������-------------" << endl;

    // �����ļ��ĵ�ַ
    // D:\NKU\����\���������\lab3����\�����ļ�\1.jpg
    // D:\NKU\����\���������\lab3����\�����ļ�\helloworld.txt
 
    while (1)
    {
        int select;
        cout << "��ʾ�������ļ�������1���Ͽ�����������2" << endl;
        cin >> select;

        if (select == 1)
        {
            cout << "-------------��������Ҫ������ļ��ĵ�ַ-------------" << endl;
            string file_path;
            cin >> file_path;
            send_file(file_path);
            
        }

        else if (select == 2)
        {
            Disconnect();
            cout << "-------------�ɹ��Ͽ�����-------------" << endl;
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
