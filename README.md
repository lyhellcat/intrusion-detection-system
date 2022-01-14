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
├── perf.data
├── perf.data.old
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



## 测试

![image-20220114143426009](https://raw.githubusercontent.com/lyhellcat/Pic/master/img/image-20220114143426009.png)

发送数量多但单个数据包大小较小(`datasize`为120)的情况

![image-20220114143844613](https://raw.githubusercontent.com/lyhellcat/Pic/master/img/image-20220114143844613.png)



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

