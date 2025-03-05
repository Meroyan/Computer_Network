#include "send_3.h"

using namespace std;

// 窗口大小
int WINDOW_SIZE = 20;
int cwnd = 1;
int ssthresh = 32;
bool slow_start = true;
//vector<Packet> window(WINDOW_SIZE); // 滑动窗口

string file_name;
uint32_t file_length;

int need_packet_num;
int last_length;
atomic_int base(0);     // 窗口的基序列号
atomic_int next_seq(0); // 下一个要发送的数据包序列号
int begin_seq;
atomic_int Count(0);
float time_send_file;


// 发送缓冲区-存储每个要发送的数据包
//Packet* send_buffer;
std::vector<Packet> send_buffer;

mutex mtx;  // 互斥锁
condition_variable cv;  // 条件变量
int need_resend = false;
int finish = false;

void send_Initial()
{
    // 初始化WinSock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        perror("[Send] 初始化Socket DLL失败！\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "[Send] 初始化Socket DLL成功！" << endl;
    }

    // 创建 UDP 套接字
    send_Socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_Socket == INVALID_SOCKET) {
        perror("[Send] 创建socket失败！\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        cout << "[Send] 创建socket成功！" << endl;
    }

    // 设置非阻塞模式
    unsigned long on = 1;
    ioctlsocket(send_Socket, FIONBIO, &on);

    // 配置发送端地址
    send_Addr.sin_family = AF_INET;
    send_Addr.sin_port = htons(send_Port);
    if (inet_pton(AF_INET, send_IP.c_str(), &send_Addr.sin_addr) <= 0) {
        cerr << "[Send] 无效的发送端IP地址！" << endl;
        closesocket(send_Socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // 绑定套接字
    if (bind(send_Socket, (sockaddr*)&send_Addr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
        cerr << "[Send] 绑定socket失败！" << endl;
        closesocket(send_Socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // 配置路由器地址
    recv_Addr.sin_family = AF_INET;
    recv_Addr.sin_port = htons(recv_Port);
    if (inet_pton(AF_INET, recv_IP.c_str(), &recv_Addr.sin_addr) <= 0) {
        cerr << "[Send] 无效的接收端IP地址！" << endl;
        closesocket(send_Socket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    cout << "[Send] 初始化并且绑定socket成功！" << endl;
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

    // sendto参数：socket描述符，发送数据缓存区，发送缓冲区的长度，
    // 对调用的处理方式，目标socket的地址，目标地址的长度
    return result;
}

int Connect()
{
    Packet wo1, wo2, wo3;   // 3次握手的数据包

    // 设置第一次握手的数据包参数
    wo1.set_SYN();  // 设置SYN=1，表示希望建立连接
    wo1.seq_num = ++in_seq; //seq初始化为in_seq+1

    int resend_count = 0;
    bool connected = false;

    while (resend_count < MAX_RETRIES && !connected)
    {
        if (SEND(wo1) > 0)
        {
            float wo1_send_clock = clock();
            cout << "[Send] 发送第一次握手的SYN报文" << endl;
            wo1.Print_Message();

            while (1)
            {
                // 接收到了第二次握手的报文
                if (recvfrom(send_Socket, (char*)&wo2, sizeof(wo2), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
                {

                    // 接收到的报文是正确的
                    // 接收到的报文wo2应为：SYN = 1，ACK = 1，Ack_num = seq_num+1= 2，校验和=0xffff
                    if (wo2.is_SYN() && wo2.is_ACK() && (wo2.ack_num == (wo1.seq_num + 1))
                        && wo2.check_checksum() == 0xffff)
                    {
                        cout << "[Send] 第二次握手成功！" << endl;


                        // 设置第三次握手报文，ACK = 1， wo3.seq_num = wo2.ack_num
                        // wo3.ack_num = wo2.seq_num + 1
                        wo3.set_ACK();
                        wo3.seq_num = ++in_seq;
                        wo3.ack_num = wo2.seq_num + 1;

                        int wo3_send_count = 0;
                        int ack_send_res = -1;
                        // 发送第三次握手的报文
                        while (wo3_send_count < MAX_RETRIES && ack_send_res < 0)
                        {
                            ack_send_res = SEND(wo3);


                            // 如果第三次握手的报文发送成功
                            if (ack_send_res > 0)
                            {
                                cout << "[Send] 发送第三次握手的ACK报文" << endl;
                                wo3.Print_Message();
                                connected = true;  // 三次握手成功，连接建立
                                cout << "[Send] 三次握手建立成功！" << endl;
                                return 1;
                            }
                            // 如果第三次报文发送失败，重新发，最多三次
                            else
                            {
                                cout << "[Send] 第三次握手发送ACK失败，重试次数：" << wo3_send_count + 1 << endl;
                                wo3_send_count++;
                                if (wo3_send_count < 3)
                                {
                                    cout << "[Send] 正在重新发送ACK报文..." << endl;
                                }
                                else
                                {
                                    cout << "[Send] 已重试三次，第三次握手失败！" << endl;
                                }
                            }
                        }
                        if (wo3_send_count == MAX_RETRIES && ack_send_res < 0)
                        {
                            cout << "[Send] 无法成功发送第三次握手ACK报文，连接失败。" << endl;
                            exit(EXIT_FAILURE);
                        }
                        break;
                    }

                    // 接收到的第二次握手报文是错误的
                    else
                    {
                        cout << "[Send] 第二次握手错误！收到不合法的报文" << endl;
                        break;
                    }
                }

                // 如果超时
                if (clock() - wo1_send_clock > TIMEOUT_MS)
                {
                    resend_count++;
                    cout << "[Send] 超时，正在重新发送第一次握手的SYN报文，重试次数：" << resend_count << endl;
                    break;
                }
            }

        }

        // 第一次握手报文发送失败
        else
        {
            cout << "[Send] 发送第一次握手的SYN报文失败！" << endl;
            break;
        }
    }

    // 重试了三次，连接失败
    if (!connected)
    {
        cout << "[Send] 三次握手失败，建立连接失败！" << endl;
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

        // 接收到了确认报文
        if (recvfrom(send_Socket, (char*)&file_recv, sizeof(file_recv), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
        {
            if (file_recv.is_ACK() && file_recv.check_checksum() == 0xffff)
            {
                lock_guard<mutex> lock(mtx);
                //cout << "[Send] 收到  [" << file_name << "]" << file_recv.offset << "/" << need_packet_num << "的确认报文" << endl;
                //file_recv.Print_Message();

                // 收到期待的报文
                if (file_recv.ack_num == last_ack + 1)
                {
                    base++;
                    if (base <= need_packet_num)
                    {
                        //cout << "[Window] 窗口滑动，当前base = " << base << endl;
                    }

                    last_ack = file_recv.ack_num;
                    Count = 0;

                    if (file_recv.offset == need_packet_num)
                    {
                        finish = true;
                        //cout << "[Send] 文件" << file_name << "全部发送并接收完毕！finish = " << finish << endl;
                        return;
                    }

                    if (slow_start)
                    {
                        cwnd ++;
                        if (cwnd >= ssthresh)
                        {
                            slow_start = false;
                            //cout << " [RENO] 当前 ssthresh = " << ssthresh << " ，cwnd = " << cwnd << " ，slow_start = " << slow_start << endl;
                            //cout << " [RENO] 进入拥塞避免阶段！" << endl;
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
                        //cout << " [RENO] 当前 ssthresh = " << ssthresh << " ，cwnd = " << cwnd << " ，slow_start = " << slow_start << endl;

                    }

                }


                // 收到重复报文
                if (file_recv.ack_num == last_ack)
                {
                    Count++;
                    //cout << " [Warning] 重复收到第 " << file_recv.offset << " 部分的确认报文 " << Count << "次" << endl;
     
                    if (Count == 3)
                    {
                        Count = 0;
                        need_resend = true;
                        //cout << " [Warning] 重复收到第 " << file_recv.offset << " 部分的确认报文 " << Count << "次，启动快速重传！need_resend = " << need_resend << endl;

                        ssthresh = cwnd / 2;
                        cwnd = ssthresh + 3;
                        slow_start = false;
                        //cout << " [RENO] 当前 ssthresh = " << ssthresh << " ，cwnd = " << cwnd << " ，slow_start = " << slow_start << endl;
                        //cout << " [RENO] 进入拥塞避免阶段！" << endl;

                    }
                    
                }


                // 累计确认
                if (file_recv.ack_num > last_ack + 1)
                {
                    base = file_recv.offset + 1;
                    if (base <= need_packet_num)
                    {
                        //cout << "[Window] 窗口滑动，当前base = " << base << endl;
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

                //cout << " [Warning] 超时！启动快速重传！need_resend = "
                //    << need_resend << " ，finish = " << finish << endl;
                //cout << " [RENO] 当前 ssthresh = " << ssthresh << " ，cwnd = " << cwnd << " ，slow_start = " << slow_start << endl;
                //cout << " [RENO] 进入慢启动阶段！" << endl;

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

    // 获取文件名
    size_t pos = file_path.find_last_of("\\/");
    file_name = file_path.substr(pos + 1);

    if (!file.is_open()) {
        cout << "    打开文件" << file_name << "失败!" << endl;
        exit(EXIT_FAILURE);
    }

    // 获取文件大小
    file.seekg(0, ios::end);  // 移动文件指针到文件末尾
    file_length = static_cast<uint32_t>(file.tellg());  // 获取文件大小（字节）
    file.seekg(0, ios::beg);  // 重置文件指针到文件开头

    cout << "    文件" << file_name << "大小为" << file_length << "字节" << endl;

    // 发送一个数据包，表示文件头
    // 数据内容是文件的名称，以及文件的长度，设置send_head.seq_num=in_seq+1
    Packet send_head;

    //文件名 + 文件大小
    string data_to_send = file_name + " " + to_string(file_length);
    strcpy_s(send_head.data, sizeof(send_head.data), data_to_send.c_str());
    send_head.data[strlen(send_head.data)] = '\0';
    // 设置data_len为data的实际长度
    send_head.data_len = static_cast<uint16_t>(data_to_send.length());
    send_head.seq_num = ++in_seq;

    //cout << "[Send] 发送" << file_name << "的头部信息" << endl;
    SEND(send_head);
    //send_head.Print_Message();

    // 记录发送时间
    float send_head_time = clock();
    float start_time = clock();

    // 等待返回确认报文
    while (1)
    {
        Packet re_head;

        // 接收到了头部的确认报文
        if (recvfrom(send_Socket, (char*)&re_head, sizeof(re_head), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
        {
            // 检查接收到的确认数据包是否正确
            // 理论上应该是 ACK = 1，re_head.ack_num = send_head.ack_num+1，
            // 校验和无错
            if (re_head.is_ACK() && (re_head.ack_num == (send_head.seq_num + 1))
                && re_head.check_checksum() == 0xffff)
            {
                //cout << "[Send] 收到" << file_name << "的头部确认报文，准备发送数据" << endl;
                //re_head.Print_Message();

                // 更新in_seq
                //in_seq = re_head.ack_num;
                break;
            }

            // 数据包不对
            else
            {
                cout << "[Send] 收到不合法的报文" << endl;
                re_head.Print_Message();
                break;
            }

        }

        // 如果未接收到确认报文-超时
        if (clock() - send_head_time > TIMEOUT_MS)
        {
            // 重新发送
            int result = sendto(send_Socket, (char*)&send_head, sizeof(send_head), 0, (SOCKADDR*)&recv_Addr, sizeof(recv_Addr));

            if (result > 0)
            {
                //cout << "[Send] 接收头部确认报文超时，正在重新发送" << file_name << "的头部信息" << endl;
                //send_head.Print_Message();
                // 重新发送后继续接收确认报文
                send_head_time = clock();  // 重置发送时间
                continue;  // 继续等待确认报文
            }

            else
            {
                cout << "[Send] 接收头部确认报文超时，重新发送" << file_name << "的头部信息失败！" << endl;
                exit(EXIT_FAILURE);
            }
        }
    }

    need_packet_num = file_length / MAX_DATA_LENGTH;    // 需要发送的数据包个数
    last_length = file_length % MAX_DATA_LENGTH;        // 剩余的

    send_buffer.resize(static_cast<std::vector<Packet, std::allocator<Packet>>::size_type>(need_packet_num) + 1);  // 调整大小为 need_packet_num

    // 启动接收线程
    thread recv_thread_obj(recv_thread);

    begin_seq = in_seq;
    cout << "begin_seq = " << begin_seq << endl;

    while (!finish)
    {
        // 重新发送
        if (need_resend && (next_seq <= need_packet_num + 1))
        {

            // base = 179，next=181，丢179，重发179，180，181
            for (int i = base; i < next_seq; i++)
            {
                lock_guard<mutex> lock(mtx);

                Packet re_send;
                re_send = send_buffer[i];

                //int data_len = strlen(send_buffer[i].data);  // 获取源数据的实际长度
                //if (data_len > MAX_DATA_LENGTH) {
                //    cout << "data_len = " << data_len << endl;
                //    cout << "[Error] 数据太大，无法复制！" << endl;
                //    exit(EXIT_FAILURE);  // 如果数据太大，可以根据实际情况处理错误
                //}

                if (SEND(re_send) > 0)
                {
                    //cout << "[Send] 重新发送  [" << file_name << "]" << re_send.offset << "/" << need_packet_num << endl;
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
                    //cout << "[Send] 重新发送  [" << file_name << "]" << re_send.offset << "/" << need_packet_num << "失败！" << endl;
                    //                cout << " [RENO] 当前 ssthresh = " << ssthresh << " ，cwnd = " << cwnd << " ，slow_start = " << slow_start << endl;                

                    exit(EXIT_FAILURE);
                }
            }

            need_resend = false;

        }

        if (next_seq <= need_packet_num && next_seq < base + min(WINDOW_SIZE, cwnd))
        {

            // 读取数据并填充数据包
            Packet file_send;
            if (next_seq < need_packet_num)
            {
                lock_guard<mutex> lock(mtx);

                // 读取数据内容，设置数据包
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

                // 读取数据内容，设置数据包
                file.read(file_send.data, last_length);
                file_send.data_len = last_length;
                file_send.seq_num = ++in_seq;
                file_send.ack_num = file_send.seq_num - 1;
                file_send.offset = next_seq;

                send_buffer[need_packet_num] = file_send;
            }

            // 数据发送成功
            if (SEND(file_send) > 0)
            {
                lock_guard<mutex> lock(mtx);

                // 记录发送时间
                float time_send_file = clock();

                cout << "[Send] 发送  [" << file_name << "]" << file_send.offset << "/" << need_packet_num << endl;
                //file_send.Print_Message();
                //cout << " [Window] 当前 base = " << base << " ，next_seq = " << next_seq << endl;
                //cout << " [RENO] 当前 ssthresh = " << ssthresh << " ，cwnd = " << cwnd << " ，slow_start = " << slow_start << endl;                

                next_seq++;
            }


        }
    }

    // 等待接收线程结束
    recv_thread_obj.join();

    // 结束时间
    float end_time = clock();

    // 计算传输时间
    float transfer_time = (end_time - start_time) * 1000 / CLOCKS_PER_SEC;  // 转换为毫秒
    cout << "[Send] 文件传输总时间: " << transfer_time << " 毫秒" << endl;

    // 计算吞吐率
    float throughput = static_cast<float>(file_length) / transfer_time;  // 单位：字节/毫秒
    float throughput_bps = throughput * 8;  // 单位：比特/毫秒
    cout << "[Send] 文件传输吞吐率: " << throughput_bps << " 比特/毫秒" << endl;
    // 计算往返时延
    cout << "[Send] 传输往返时延：" << transfer_time / need_packet_num << " 毫秒" << endl;

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
    // 4次挥手的报文
    Packet hui1, hui2, hui3, hui4;

    // 设置第一次挥手的报文格式
    hui1.set_FIN();
    hui1.seq_num = ++in_seq;

    // 第一次挥手报文发送成功
    if (SEND(hui1) > 0)
    {
        float hui1_send_clock = clock();
        cout << "[Send] 发送第一次挥手的FIN报文" << endl;
        hui1.Print_Message();

        while (1)
        {
            // 接收到了第二次挥手的报文
            if (recvfrom(send_Socket, (char*)&hui2, sizeof(hui2), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
            {
                // 接收到的报文是正确的
                // 接收到的报文hui2应为：ACK = 1，Ack_num = seq_num+1，校验和=0xffff
                if (hui2.is_ACK() && (hui2.ack_num == (hui1.seq_num + 1))
                    && hui2.check_checksum() == 0xffff)
                {
                    cout << "[Send] 收到第二次挥手的ACK报文" << endl;
                    hui2.Print_Message();

                    cout << "[Send] 第二次挥手成功！" << endl;

                    while (1)
                    {
                        // 接收到了第三次挥手的报文
                        if (recvfrom(send_Socket, (char*)&hui3, sizeof(hui3), 0, (SOCKADDR*)&recv_Addr, &recv_AddrLen) > 0)
                        {
                            // 接收到的报文是正确的
                            // 接收到的报文hui3应为：FIN = 1，seq_num = seq_num+1，校验和=0xffff
                            if (hui3.is_FIN() && (hui3.seq_num == (hui2.seq_num + 1))
                                && hui3.check_checksum() == 0xffff)
                            {
                                cout << "[Send] 收到第三次挥手的FIN报文" << endl;
                                hui3.Print_Message();

                                cout << "[Send] 第三次挥手成功！" << endl;


                                // 设置第四次挥手报文，ACK = 1， hui4.seq_num = ++in_seq
                                // hui4.ack_num = hui3.seq_num + 1
                                hui4.set_ACK();
                                hui4.seq_num = ++in_seq;
                                hui4.ack_num = hui3.seq_num + 1;

                                // 发送第四次挥手的报文
                                // 第四次挥手报文发送成功
                                if (SEND(hui4) > 0)
                                {
                                    float hui4_send_clock = clock();
                                    cout << "[Send] 发送第四次挥手的ACK报文" << endl;
                                    hui4.Print_Message();

                                    //// 等待2MSL时间，关闭连接
                                    //if (clock() - hui4_send_clock > 2 * TIMEOUT_MS)
                                    //{
                                    //    closesocket(send_Socket);
                                    //    WSACleanup();
                                    //    cout << "[Send] 关闭Socket！" << endl;
                                    //}
                                    cout << "[Send] 四次挥手成功" << endl;

                                    closesocket(send_Socket);
                                    WSACleanup();
                                    cout << "[Send] 关闭Socket！" << endl;
                                    return;
                                }


                                // 第四次挥手报文发送失败
                                else
                                {
                                    cout << "[Send] 发送第四次挥手的ACK报文失败！" << endl;
                                    break;
                                }

                            }

                            // 接收到的第三次握手报文是错误的
                            else
                            {
                                cout << "[Send] 第三次挥手错误！收到不合法的报文" << endl;
                                break;
                            }


                        }

                    }

                }

                // 接收到的第二次握手报文是错误的
                else
                {
                    cout << "[Send] 第二次挥手错误！收到不合法的报文" << endl;
                    hui2.Print_Message();
                    break;
                }

            }

            // 等待接收第二次挥手的报文超时，重新发送第一次挥手的报文
            if (clock() - hui1_send_clock > TIMEOUT_MS)
            {
                cout << "[Send] 超时，正在重新发送第一次挥手的FIN报文" << endl;
                hui1_send_clock = clock();
            }

        }

    }

    // 第一次挥手报文发送失败
    else
    {
        cout << "[Send] 发送第一次挥手的FIN报文失败！" << endl;

    }


}


int main()
{
    send_Initial();
    cout << "-------------初始化完成，尝试建立连接中-------------" << endl;

    Connect();
    cout << "-------------成功建立连接-------------" << endl;

    // 测试文件的地址
    // D:\NKU\大三\计算机网络\lab3测试\测试文件\1.jpg
    // D:\NKU\大三\计算机网络\lab3测试\测试文件\helloworld.txt
    // D:\壁纸\老张分区.jpg
    // D:\壁纸\try.txt

    while (1)
    {
        int select;
        cout << "提示：传输文件请输入1，断开连接请输入2" << endl;
        cin >> select;

        if (select == 1)
        {
            cout << "-------------请输入想要传输的文件的地址-------------" << endl;
            string file_path;
            cin >> file_path;
            send_file(file_path);

        }

        else if (select == 2)
        {
            Disconnect();
            cout << "-------------成功断开连接-------------" << endl;
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
