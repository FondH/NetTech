# 实验文档

##### 实验准备：

Cisco Packet Tracer 软件

## 1. 仿真环境下的共享式以太网组网

1. 连接多个接线器

   ![image-20231014185424563](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20231014185424563.png)

2. 手动分配静态ip、子网掩码        ![image-20231014190721212](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20231014190721212.png)

3. ping 测试

   ![image-20231014190852761](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20231014190852761.png)

4. Simulation模式下，观察ICMP包的传递；

   可以看出，当PC6向PC5使用ping指令时，发送三个包，每个包传递一旦经过某个接线器，将会给接线器其余设备发送，机器判断是否是自己应该接受的包，若是则向PC6返回相应包。

   ![image-20231014191430942](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20231014191430942.png)



## 2. 仿真环境下的交换式以太网组网和VLAN配置

1. 组网、配置ip

   ![image-20231014200009047](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20231014200009047.png)

2. 终端配置交换机，设置vlan网段，设置接口的VLAN,后续配置直接使用可视化界面

   ~~~bash
   Switch#configure t
   Enter configuration commands, one per line.  End with CNTL/Z.
   Switch(config)#vlan 10
   Switch(config)#vlan name VLAN0
   Switch(config-vlan)#exit
   Switch(config)#vlan 20
   Switch(config)#vlan name VLAN1
   Switch(config-vlan)#exit
   Switch(config)#vlan 2
   Switch(config)#vlan name VLAN2
   Switch(config-vlan)#exit
   Switch(config)#interface fa0/1
   Switch(config-if)#switchport mode access
   Switch(config-if)#switchport access vlan 10
   Switch(config-if)#exit
   Switch(config)#interface fa0/2
   Switch(config-if)#switchport mode access
   Switch(config-if)#switchport access vlan 10
   Switch(config-if)#exit
   Switch(config)#interface fa0/3
   Switch(config-if)#switchport mode access
   Switch(config-if)#switchport access vlan 20
   Switch(config-if)#exit
   Switch(config)#exit
   ~~~

   ![image-20231014192212208](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20231014192212208.png)

3. 测试验证，同一VLAN之间可以ping通，但是不同VLAN不可以；这里一开始我以为任何交换机内的设备都可以ping通，但是实际上，只可以通过集线器连接到交换机对应接口的VLAN，例如下面，左下的交换机的PC-0处于VLAN10，PC-7处于VLAN20，集线器相连接处于VLAN10，因此0可以ping通集线器内的6，但是7不可以。

   ![image-20231014195444550](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20231014195444550.png)

   ![image-20231014195455831](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20231014195455831.png)

## 实验问题与解决
### 交换器的端口选择问题
在实验的初步阶段，我错误地选择了交换器的trunc端口和普通端口，这导致了整个网络不通。经过深入的探究，我了解到trunc端口是用来连接两个交换机并传输多个VLAN的信息，而普通端口则主要用于连接终端设备或单一VLAN的通信。在我错误地设置后，数据包不能正确地在VLAN之间传递，从而导致网络的中断。

解决方法：我重新审查了网络的设计，并正确设置了trunc和普通端口，之后网络恢复了通信。

## 实验中的协议探究
### ICMP协议的观察
通过Cisco的动画模型，我观察到当一个设备试图与另一个设备通信时，它首先发送ICMP的Echo Request，目标设备在接收到请求后回复Echo Reply。这就是常见的ping命令背后的原理，用于测试网络连通性。

### DNS协议的观察
同样，在Cisco的动画模型中，当一个设备需要解析域名时，它会发送一个DNS查询请求到已知的DNS服务器。该服务器回复一个DNS响应，其中包含域名对应的IP地址。这一过程确保了设备能够通过域名找到并连接到正确的服务器或资源。

## 思考与感悟
- 通过这次实验，我更加明白了网络配置中的细微之处和每一个选择的重要性。一个简单的端口设置错误就可能导致整个网络的故障。
- 观察ICMP和DNS协议的交互过程加深了我对这两种基本网络协议的理解，这在日常的网络故障排除中是非常有用的。
- Cisco的模拟工具不仅提供了一个进行实验的平台，还允许我通过动画模型深入观察协议的工作原理，这对于理解和掌握复杂的网络知识非常有帮助。

