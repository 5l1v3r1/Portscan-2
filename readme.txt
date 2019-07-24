1.python简易端口扫描器，扫描TCP与UDP

2.根据网路状态在portscan.py中配置
	
	TCP_TIMEOUT与TCP_THREAD_DELAY参数

	eg:
	扫描内网:
	TCP_TIMEOUT = 0.5
	TCP_THREAD_DELAY = 0

	扫描外网:
	TCP_TIMEOUT = 6
	TCP_THREAD_DELAY = 3