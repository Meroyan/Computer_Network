#include "send_3.h"

using namespace std;

// ���ڴ�С
int WINDOW_SIZE = 20;
int cwnd = 1;
int ssthresh = 32;
bool slow_start = true;
//vector<Packet> window(WINDOW_SIZE); // ��������

string file_name;
uint32_t file_length;

int need_packet_num;
int last_length;
atomic_int base(0);     // ���ڵĻ����к�
atomic_int next_seq(0); // ��һ��Ҫ���͵����ݰ����к�
int begin_seq;
atomic_int Count(0);
float time_send_file;


// ���ͻ�����-�洢ÿ��Ҫ���͵����ݰ�
//Packet* send_buffer;
std::vector<Packet> send_buffer;

mutex mtx;  // ������
condition_variable cv;  // ��������
int need_resend = false;
int finish = false;

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

int SEND(Packet& packet)
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
    Packet wo1, wo2, wo3;   // 3�����ֵ����ݰ�

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

void recv_thread()
{
    int last_ack = in_seq;
    int re_count = 0;
    cout << "last_ack = " << last_ack << endl;
    int to_count = 0;
    int yo_count = 0;

    while (1)
    {
        Packet file_recv;

        // ���յ���ȷ�ϱ���
        if (recvfrom(send_Socket, (char*)&file_recv, sizeof(file_recv), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
        {
            if (file_recv.is_ACK() && file_recv.check_checksum() == 0xffff)
            {
                lock_guard<mutex> lock(mtx);
                //cout << "[Send] �յ�  [" << file_name << "]" << file_recv.offset << "/" << need_packet_num << "��ȷ�ϱ���" << endl;
                //file_recv.Print_Message();

                // �յ��ڴ��ı���
                if (file_recv.ack_num == last_ack + 1)
                {
                    base++;
                    if (base <= need_packet_num)
                    {
                        //cout << "[Window] ���ڻ�������ǰbase = " << base << endl;
                    }

                    last_ack = file_recv.ack_num;
                    Count = 0;

                    if (file_recv.offset == need_packet_num)
                    {
                        finish = true;
                        //cout << "[Send] �ļ�" << file_name << "ȫ�����Ͳ�������ϣ�finish = " << finish << endl;
                        return;
                    }

                    if (slow_start)
                    {
                        cwnd ++;
                        if (cwnd >= ssthresh)
                        {
                            slow_start = false;
                            //cout << " [RENO] ��ǰ ssthresh = " << ssthresh << " ��cwnd = " << cwnd << " ��slow_start = " << slow_start << endl;
                            //cout << " [RENO] ����ӵ������׶Σ�" << endl;
                        }
                    }
                    else
                    {
                        yo_count++;
                        if (yo_count == cwnd)
                        {
                            cwnd += 1;
                            yo_count == 0;
                        }
                        //cout << " [RENO] ��ǰ ssthresh = " << ssthresh << " ��cwnd = " << cwnd << " ��slow_start = " << slow_start << endl;

                    }

                }


                // �յ��ظ�����
                if (file_recv.ack_num == last_ack)
                {
                    Count++;
                    //cout << " [Warning] �ظ��յ��� " << file_recv.offset << " ���ֵ�ȷ�ϱ��� " << Count << "��" << endl;
     
                    if (Count == 3)
                    {
                        Count = 0;
                        need_resend = true;
                        //cout << " [Warning] �ظ��յ��� " << file_recv.offset << " ���ֵ�ȷ�ϱ��� " << Count << "�Σ����������ش���need_resend = " << need_resend << endl;

                        ssthresh = cwnd / 2;
                        cwnd = ssthresh + 3;
                        slow_start = false;
                        //cout << " [RENO] ��ǰ ssthresh = " << ssthresh << " ��cwnd = " << cwnd << " ��slow_start = " << slow_start << endl;
                        //cout << " [RENO] ����ӵ������׶Σ�" << endl;

                    }
                    
                }


                // �ۼ�ȷ��
                if (file_recv.ack_num > last_ack + 1)
                {
                    base = file_recv.offset + 1;
                    if (base <= need_packet_num)
                    {
                        //cout << "[Window] ���ڻ�������ǰbase = " << base << endl;
                    }

                    last_ack = file_recv.ack_num;
                    Count = 0;
                }

            }
        }
    
        if (!need_resend && !finish && clock() - time_send_file > TIMEOUT_MS)
        {
            re_count++;
            lock_guard<mutex> lock(mtx);

            to_count++;

            Count = 0;
            need_resend = true;

                //cout << " [Warning] ��ʱ�����������ش���need_resend = "
                //    << need_resend << " ��finish = " << finish << endl;
                //cout << " [RENO] ��ǰ ssthresh = " << ssthresh << " ��cwnd = " << cwnd << " ��slow_start = " << slow_start << endl;
                //cout << " [RENO] �����������׶Σ�" << endl;

                //cout << endl;

                slow_start = true;
                ssthresh = cwnd / 2;
                cwnd = 1;
            

        }

    
    }
    return;
}

void send_file(string& file_path)
{
    ifstream file(file_path, ios::binary);

    // ��ȡ�ļ���
    size_t pos = file_path.find_last_of("\\/");
    file_name = file_path.substr(pos + 1);

    if (!file.is_open()) {
        cout << "    ���ļ�" << file_name << "ʧ��!" << endl;
        exit(EXIT_FAILURE);
    }

    // ��ȡ�ļ���С
    file.seekg(0, ios::end);  // �ƶ��ļ�ָ�뵽�ļ�ĩβ
    file_length = static_cast<uint32_t>(file.tellg());  // ��ȡ�ļ���С���ֽڣ�
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

    //cout << "[Send] ����" << file_name << "��ͷ����Ϣ" << endl;
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
                re_head.Print_Message();
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
                cout << "[Send] ����ͷ��ȷ�ϱ��ĳ�ʱ�����·���" << file_name << "��ͷ����Ϣʧ�ܣ�" << endl;
                exit(EXIT_FAILURE);
            }
        }
    }

    need_packet_num = file_length / MAX_DATA_LENGTH;    // ��Ҫ���͵����ݰ�����
    last_length = file_length % MAX_DATA_LENGTH;        // ʣ���

    send_buffer.resize(static_cast<std::vector<Packet, std::allocator<Packet>>::size_type>(need_packet_num) + 1);  // ������СΪ need_packet_num

    // ���������߳�
    thread recv_thread_obj(recv_thread);

    begin_seq = in_seq;
    cout << "begin_seq = " << begin_seq << endl;

    while (!finish)
    {
        // ���·���
        if (need_resend && (next_seq <= need_packet_num + 1))
        {

            // base = 179��next=181����179���ط�179��180��181
            for (int i = base; i < next_seq; i++)
            {
                lock_guard<mutex> lock(mtx);

                Packet re_send;
                re_send = send_buffer[i];

                //int data_len = strlen(send_buffer[i].data);  // ��ȡԴ���ݵ�ʵ�ʳ���
                //if (data_len > MAX_DATA_LENGTH) {
                //    cout << "data_len = " << data_len << endl;
                //    cout << "[Error] ����̫���޷����ƣ�" << endl;
                //    exit(EXIT_FAILURE);  // �������̫�󣬿��Ը���ʵ������������
                //}

                if (SEND(re_send) > 0)
                {
                    //cout << "[Send] ���·���  [" << file_name << "]" << re_send.offset << "/" << need_packet_num << endl;
                    //re_send.Print_Message();


                    float re_clock = clock();
                    while (1)
                    {
                        if (clock() - re_clock > 1)
                        {
                            break;
                        }
                    }

                    time_send_file = clock();
                }
                else
                {
                    //cout << "[Send] ���·���  [" << file_name << "]" << re_send.offset << "/" << need_packet_num << "ʧ�ܣ�" << endl;
                    //                cout << " [RENO] ��ǰ ssthresh = " << ssthresh << " ��cwnd = " << cwnd << " ��slow_start = " << slow_start << endl;                

                    exit(EXIT_FAILURE);
                }
            }

            need_resend = false;

        }

        if (next_seq <= need_packet_num && next_seq < base + min(WINDOW_SIZE, cwnd))
        {

            // ��ȡ���ݲ�������ݰ�
            Packet file_send;
            if (next_seq < need_packet_num)
            {
                lock_guard<mutex> lock(mtx);

                // ��ȡ�������ݣ��������ݰ�
                file.read(file_send.data, MAX_DATA_LENGTH);
                file_send.data_len = MAX_DATA_LENGTH;
                file_send.seq_num = ++in_seq;
                file_send.ack_num = file_send.seq_num - 1;
                file_send.offset = next_seq;

                strcpy_s(send_buffer[next_seq].data, MAX_DATA_LENGTH + 100, file_send.data);

                send_buffer[next_seq] = file_send;
            }

            else if (next_seq == need_packet_num)
            {
                lock_guard<mutex> lock(mtx);

                // ��ȡ�������ݣ��������ݰ�
                file.read(file_send.data, last_length);
                file_send.data_len = last_length;
                file_send.seq_num = ++in_seq;
                file_send.ack_num = file_send.seq_num - 1;
                file_send.offset = next_seq;

                send_buffer[need_packet_num] = file_send;
            }

            // ���ݷ��ͳɹ�
            if (SEND(file_send) > 0)
            {
                lock_guard<mutex> lock(mtx);

                // ��¼����ʱ��
                float time_send_file = clock();

                cout << "[Send] ����  [" << file_name << "]" << file_send.offset << "/" << need_packet_num << endl;
                //file_send.Print_Message();
                //cout << " [Window] ��ǰ base = " << base << " ��next_seq = " << next_seq << endl;
                //cout << " [RENO] ��ǰ ssthresh = " << ssthresh << " ��cwnd = " << cwnd << " ��slow_start = " << slow_start << endl;                

                next_seq++;
            }


        }
    }

    // �ȴ������߳̽���
    recv_thread_obj.join();

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
    //delete[] send_buffer;

    lock_guard<mutex> lock(mtx);
    next_seq = 0;
    base = 0;
    finish = false;
    need_resend = false;

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
    // D:\��ֽ\���ŷ���.jpg
    // D:\��ֽ\try.txt

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
