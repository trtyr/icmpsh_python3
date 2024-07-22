原来的icmpsh下的icmpsh_m.py是Python2版本的，简单修改成Python3文件，同时该文件会自动运行`sysctl -w net.ipv4.icmp_echo_ignore_all=1`命令，关闭本机的icmp应答，防止搭建隧道时，内核对自己的ping包响应。
