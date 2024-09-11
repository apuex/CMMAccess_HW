V1.0.0.20240612
1.增加webserver接口
2.增加get set接口处理设备列表数据 格式为json  设备数据保存到/appdata/config下

20240618
1.更改TDeviceInfo结构体参数 新增父设备ID 子设备ID 别名
2.设置别名由前端发送set 不用扩展模块设置

20240701
1.增加UDP服务 由宏定义ACCESSCONTROL区分UDP和 HTTP
2.支持特殊机型的透传接口

20240710
1.优化UDP数据包格式 用udp传输串口数据包
2.新增UDP FSU心跳

20240712
1.UDP逻辑修改  FSU只关心SC送来的数据写入串口 和读到的串口数据发到SC 其他不管
2.新增串口读写逻辑

20240713
1.优化UDP交互逻辑 优化UDP客户端性能