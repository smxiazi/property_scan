# 资产测绘

```
用于日常工作中的很繁琐的资产测绘任务，被逼疯了，只能自己折腾一个了
```

### 0x01 使用环境
* python3.7+
* 安装好 nmap
* 按照好 masscan

#### 0x02 使用方法
* 运行 main.py 打开对应的8000端口,默认账号密码admin:admin123登录
  
<img width="863" alt="image" src="https://github.com/user-attachments/assets/7e5f28b6-26ee-4306-87bf-da134e61c676">

<img width="1441" alt="image" src="https://github.com/user-attachments/assets/21ab41f4-d284-4d68-9291-535b3572f41c">

* 添加本次要收集的根域名，如：baidu.com 

<img width="621" alt="image" src="https://github.com/user-attachments/assets/a29e7273-7e0e-47c6-b7e3-c7ecd7052d28">

* 然后自己去hunter、fofa上，下载该域名的 子域名 和 ip，填写上去，同时会获取域名解析A记录的ip，进行ip资产扫描全端口

<img width="1454" alt="image" src="https://github.com/user-attachments/assets/7869f26e-6036-4749-b770-95b5e146c8f5">

* 可以点击 查看运行任务 查看当前任务进度

<img width="779" alt="image" src="https://github.com/user-attachments/assets/78eba0eb-5ffc-4be7-b1dc-07748ee7ad9d">





