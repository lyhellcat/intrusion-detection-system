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

