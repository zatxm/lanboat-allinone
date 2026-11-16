# 本机生成的uQUIC回归报文

这五份1250字节Initial报文由`tests/quic-client-reference`固定的uQUIC版本在回环接口生成，测试主机名为`reference.quic.test`，只含公开握手字段，不含业务数据或凭据。

前一版本在500次Chrome115配置采集中出现5次测试失败：三个样本为前后均有PADDING的单CRYPTO布局，应识别为`quic-go`，修改前错误返回unknown；两个样本的随机版本值碰巧符合Chromium的保留版本模式，按报文特征应保持`chromium`。这两个类别均为栈家族提示，不是浏览器或进程身份认证。
