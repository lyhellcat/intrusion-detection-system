# **基于PCAP的网络入侵检测系统**

## 项目背景

本项目将实现一个基本的网络入侵检测系统, 涉及到对TCP/IP网络协议和线程的知识理解. 项目将使用`libpcap`库在特定的接口拦截 (嗅探) 数据包, 之后分析数据包. 项目的目标是检测高吞吐量网络中潜在的恶意流量. 

## 项目结构

```bash
src
├── Makefile    # 构建../build/idsniff
├── analysis.c  # 分析和识别恶意数据包
├── analysis.h
├── dispatch.c  # 将analyse()任务分发给多个线程
├── dispatch.h
├── main.c     # 包含解析命令行参数的代码段, 同时调用sniff()在指定的端口上启动抓包
├── perf.data  # 使用perf工具检测性能得到的报告
├── sniff.c   # 使用pcap_loop()持续捕获数据包
└── sniff.h
```

## 功能实现

### SYN Flooding Attack

当一个在TCP套接字上监听的服务器收到海量TCP SYN数据包时, 即受到SYN泛洪攻击. 对于每个收到的SYN包, 服务器将打开一个TCP连接, 分配一些资源, 用一个SYN-ACK包进行回复, 然后等待发件人的ACK. 然而, 恶意的发件人并没有发送ACK. 服务器在等待ACK数据包的过程中, 攻击者发送更多的SYN数据包, 每当有新的SYN数据包到达, 服务器都会临时打开新的端口并在一段时间内保持连接, 用遍所有端口后, 服务器将无法运行. 

由于攻击者发送了许多这样的SYN数据包, 服务器的资源被耗尽, 导致合法的连接请求被放弃. 这是一种拒绝服务攻击(Denial-of-service, DoS)的形式. 在大多数情况下, 攻击者从伪造的IP地址生成SYN数据包. 伪造的IP地址是随机产生的, 与攻击者的真实IP地址不一致, 以隐藏攻击者真是身份. 

![SYN Flood DDoS 攻击动画](https://www.cloudflare.com/img/learning/ddos/syn-flood-ddos-attack/syn-flood-attack-ddos-attack-diagram-2.png)

本项目将统计如下信息: 

1. 嗅探到的 SYN 数据包总数

2. IP源地址的数量

对于IP地址, 可以采用链表的方式存储, 但由于需要判断IP地址是否唯一, 故需遍历整个链表, 时间复杂度为`O(n)`, 同时我们只需要知道IP地址是否已经存在, 并不需要记录完整的IP地址, 因此内存上的开销也不占据优势. 因此, 考虑使用**Bitmap**的方式记录某个IP地址是否出现, 降低时间和内存开销. 

对于IPv4地址, 较优的方案是创建一个大小为$\frac{2^{32}}{2^{5}} = 2^{27}$的`uint32_t`数组, 记录IP地址是否出现. 

```C
typedef uint32_t word_t;
word_t words[1ll << 27];  // Up to 2^32 IP addresses

#define WORD_OFFSET(b) ((b) / 32)
#define BIT_OFFSET(b) ((b) % 32)
void set_bit(uint32_t ip_addr) {
    words[WORD_OFFSET(ip_addr)] |= (1 << BIT_OFFSET(ip_addr));
}
```

使用`hping3`工具可测试对SYN包的检测. 

![image-20220114141659456](https://raw.githubusercontent.com/lyhellcat/Pic/master/img/image-20220114141659456.png)

`-c`指定了发送数据包的数目, `-d`为数据包大小, `-S`设定`SYN`标志位为1

`-w`为滑动窗口大小, 默认为64. `-p`为目的端口, 指定为80.

`-i`指定发送数据包间隔, `u100`为100微秒. ` --rand-source`为随机地址源模式

测试结果如下: 

![image-20220114141625299](https://raw.githubusercontent.com/lyhellcat/Pic/master/img/image-20220114141625299.png)

### ARP Cache Poisoning

`ARP`可将IP地址转换为Mac地址. 主机维护一个ARP缓存, 即IP地址和MAC地址之间的映射表, 并使用它连接到网络上的目的地. 若主机不知道某个 IP 地址的 MAC 地址, 则会发出一个 ARP 请求包, 向网络上的其他机器询问匹配的 MAC 地址. ARP协议不是为安全设计的, 不会验证ARP请求的响应是否来自真正的授权方. 即使主机从未发出过ARP请求, 也可以接收ARP响应, 这是ARP协议中一个容被用于攻击的弱点. 

ARP欺骗 (ARP中毒), 是一种中间人攻击的形式, 拦截网络设备之间的通信, 然后伪造ARP响应. 

可以使用如下方式发送伪造的ARP数据包. 

```python
operation = 2        # 2 specifies ARP Reply
victim = '127.0.0.1' # We're poisoning our own cache for this demonstration
spoof = '192.168.222.222' # We are trying to poison the entry for this IP
mac = 'de:ad:be:cf:ca:fe' # Silly mac address


arp=ARP(op=operation, psrc=spoof, pdst=victim, hwdst=mac)
send(arp)
```



![image-20220114154432124](https://raw.githubusercontent.com/lyhellcat/Pic/master/img/image-20220114154432124.png)

### 黑名单URL

除了来自外部的攻击外, 入侵检测系统通常还会监视源自内部网络的流量. 这将会检测到与可疑服务器的连接, 防止内网信息外泄或遭受病毒攻击. 系统中将`www. google.co.uk `与`www.bbc.com`假定为可疑域, 当有HTTP流量被发送到这些网络时, 我们希望得到提示. 

HTTP请求的`header`段为: 

```http
GET / HTTP/1.1\r\n
User=Agent: Wget/1.20.3 (linux-gnu)\r\n
Accept: */*\r\n
Host: www.bbc.com
Connection: Keep-Alive\r\n
```

![image-20220114155134757](https://raw.githubusercontent.com/lyhellcat/Pic/master/img/image-20220114155134757.png)

由此,  我们对所有访问80端口的TCP数据包的payload部分进行检查, 使用`strstr(payload, "Host: www.google.co.uk")`来确定是否访问了不可信的域.

![image-20220114155631937](https://raw.githubusercontent.com/lyhellcat/Pic/master/img/image-20220114155631937.png)

## Threadpool Model

### 为什么选择线程池? 

线程池是基于池化思想的线程管理工具, 维护多个线程, 等待线程池管理者分配课并发执行的任务. 使用线程池一方面可避免处理任务时创建销毁线程的开销, 另一方面避免了线程数量膨胀导致的过分调度问题, 可保证对内核的充分利用. 

使用线程池可以: 

- **降低资源消耗**, 通过池化技术重复利用已创建的线程, 降低线程创建和销毁造成的损耗. 
- **提高响应速度**, 任务到达时, 无需等待线程创建即可立即执行
- **提高线程的可管理性**, 线程是稀缺资源, 如果无限制创建, 不仅会消耗系统资源, 而且会导致资源调度失衡, 系统出现颠簸, 降低系统的稳定性. 

线程池主要应用了池化思想. 在计算机中, 池化思想表现为: 同一管理计算机资源, 包括服务器, 存储, 网络资源等. 其他典型的策略包括: 

1. **内存池 Memory pooling**, 预先申请内存, 提高内存处理速度, 减少内存碎片
2. **连接池 Connection pooling**, 预先申请数据库连接, 提升申请连接的速度, 降低系统开销
3. **实例池 Object pooling**, 循环使用对象, 减少资源初始化和释放时的开销. 

[工业界应用的线程池](https://tech.meituan.com/2020/04/02/java-pooling-pratice-in-meituan.html)可以支持动态化设定参数, 这里为了实现简单, 选择将线程池大小设置为`核心数+1, `, 即`get_nprocs() + 1`. 

线程池中有2个重要的函数, `tpool_add_work`将工作添加到工作队列中进行处理, `tpool_wait`将阻塞当前进程直至所有工作完成. 

工作队列可设计为一个存储有需要调用的函数以及函数参数的简单链队列. 

```C
typedef struct tpool_work {
    thread_func_t func;
    void *arg;
    struct tpool_work *next;
} tpool_work_t;
```

由于工作队列使用了链队列实现, 因此线程池需要维护工作队列的队头以及队尾, 以高效的完成对链队列的`push() pop()`操作. 线程池还需要2个条件变量, `work_cond`表示当前有工作需要处理, `working_cond`在当前没有线程处于工作状态时发出信号, `working_cnt`表示多少线程正在处理工作,  `thread_cnt`表示有多少线程处于`alive`状态. 

```c
typedef struct tpool {
    tpool_work_t *work_head;
    tpool_work_t *work_tail;
    pthread_mutex_t work_mutex;
    pthread_cond_t work_cond;     // There is work to be processed
    pthread_cond_t working_cond;  // No threads processing
    size_t working_cnt;           // How many threads are actively processing work
    size_t thread_cnt;            // How many threads are alive
    bool stop;
} tpool_t;
```

线程池的具体实现详见代码. 

## 测试

测试部分, 我们选择`hping3`工具作为负载, 尝试更改`-c`参数指定的数据包数量以及`-d`参数指定的数据包大小, 得到性能记录. 

测试机配置: Intel(R) Xeon(R) Silver 4210R CPU @ 2.40GHz * 40

(1) 启动5个设定参数为`-c 600000 -d 30000`的`hping3`进程, 此时内网带宽为7.54Gbips, 进程`idsniff`的负载为802%, 可见确实有多个线程在工作, 能够处理较大的流量负载

![image-20220114143426009](https://raw.githubusercontent.com/lyhellcat/Pic/master/img/image-20220114143426009.png)

(2) 考虑发送数量多但单个数据包大小较小的情况, 设定`-c 600000 -d 120`, 启动5个`hping3`进程. 此时`hping3`的CPU占用率较低(30%)而`idsniff`占用率为`1282%`. 由此可见多个较小的数据包给`idsniff`带来的检测压力更大. 

![image-20220114143844613](https://raw.githubusercontent.com/lyhellcat/Pic/master/img/image-20220114143844613.png)

测试结果初步表明了多线程`idsniff`可有效应对高流量的网络. 

## Usage

使用`-h`选项可提示相关帮助信息

```bash
$ ../build/idsniff -h
A Packet Sniffer/Intrusion Detection System
Usage: ../build/idsniff [OPTIONS]...

        -i [interface]  Specify network interface to sniff
        -v              Enable verbose mode. Useful for Debugging
        -h              Display this help information
```

## References

[1] PCAP教程 https://www.tcpdump.org/pcap.html

[2] pcap_loop() https://www.devdungeon.com/content/using-libpcap-c\#pcap-loop
https://nachtimwald.com/2019/04/12/thread-pool-in-c/
https://www.jianshu.com/p/87fc3f068554

[3] SYN洪水攻击 https://www.cloudflare.com/zh-cn/learning/ddos/syn-flood-ddos-attack/

[4] ARP中毒 https://www.imperva.com/learn/application-security/arp-spoofing/



