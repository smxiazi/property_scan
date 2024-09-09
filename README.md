# 资产测绘

```
用于日常工作中的很繁琐的资产测绘任务，被逼疯了，只能自己折腾一个了
```

### 0x00 使用环境
* python3.7+
* 安装好 nmap
* 按照好 masscan
* 最好在服务器上跑，家庭网络出口不稳定，容易丢包

### 0x01 程序逻辑

* 所有资产均需要自己输入，本程序只是补充完善字段，如协议、中间件、标题、响应吗等……
  
* 输入url地址会自动提取子域名或ip地址，如果是子域名则会解析dns记录，如果是A记录则会提取出ip，然会对ip进行全端口扫描
  
* 子域名不对进行端口扫描，只会根据用户输入的url进行完善字段
  
* ip会进行全端口扫描
  
* 用户可随意输入各种格式的资产 如：http://abc.baidu.com:8088 或者 abc.baidu.com 或者 http://114.114.114.114 或者 114.114.114.114 本程序会自动处理
  
* 程序会自动处理用户输入的资产信息，进行分类、去重等操作，所以不用担心资产会重复，不小心多次点击了提交相同资产也无所谓。

### 0x02 使用方法
* 运行 main.py 打开对应的8000端口,默认账号密码admin:admin123登录
  
<img width="863" alt="image" src="https://github.com/user-attachments/assets/7e5f28b6-26ee-4306-87bf-da134e61c676">

<img width="1441" alt="image" src="https://github.com/user-attachments/assets/21ab41f4-d284-4d68-9291-535b3572f41c">

* 添加本次要收集的根域名，如：baidu.com （可填写多个根域名）

<img width="621" alt="image" src="https://github.com/user-attachments/assets/a29e7273-7e0e-47c6-b7e3-c7ecd7052d28">

* 然后自己去hunter、fofa上，下载该域名的 子域名 和 ip，填写上去，同时会获取域名解析A记录的ip，进行ip资产扫描全端口

<img width="1454" alt="image" src="https://github.com/user-attachments/assets/7869f26e-6036-4749-b770-95b5e146c8f5">

* 可以点击 查看运行任务 查看当前任务进度

<img width="847" alt="image" src="https://github.com/user-attachments/assets/1d009d23-8d4c-46cc-a3c9-92d9a1ebd213">


* 也可以随时下载xlsx文档,里面将会显示当前任务最新完成情况

<img width="1618" alt="image" src="https://github.com/user-attachments/assets/0e6e1676-e1e6-4502-906f-ab31b2b43d33">


<img width="1358" alt="image" src="https://github.com/user-attachments/assets/c5d1c2fd-50d0-414b-bc83-5b9868639568">

<img width="722" alt="image" src="https://github.com/user-attachments/assets/18087413-d955-49cd-b6b4-18ea183713b3">

* 当运行日志里面显示 任务全部完成 即可去下载 xlsx文档，获取跑完任务的完整版

<img width="613" alt="image" src="https://github.com/user-attachments/assets/783339f1-d0bc-49d4-8e20-015e66ff2f17">






