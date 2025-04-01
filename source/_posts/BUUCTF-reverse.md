---
title: BUUCTF reverse
date: 2025-03-30 19:54:37
tags: CTF
excerpt: rererererererererererererererererererere...
mathjax: true
---

不知道怎么搞得,下午写的wp被"rm -rf"了🤣🤣🤣

做re给我re成 Re: 从零开始的异世界生活 ...

我现在情绪非常淡定,淡淡的死感罢了。

# 新年快乐

## 题目

详见 [BUUUCTF 的这道题](https://buuoj.cn/challenges#%E6%96%B0%E5%B9%B4%E5%BF%AB%E4%B9%90)

## wp

先放进IDA反编译，F5一下
![alt text](check.png)
发现函数很少，怀疑是加壳了。

### 查壳
![alt text](check.png)
发现加了UPX壳，并且文件是32位的。

### 脱壳

#### 手动脱壳
找到入口断点。
![alt text](unpack1.png)

然后设置这个地址为新的执行点。
![alt text](unpack2.png)

注意此时寄存器ESP地址
![alt text](unpack3.png)

F8执行异步后，ESP地址变化。
![alt text](unpack4.png)

在内存窗口打开变化后的地址，设置为新的硬件断点，并执行
![alt text](unpack5.png)

发现断点。找到popad，其后的第一个jump即为OEP。

![alt text](unpack6.png)

用插件dump掉壳，然后autoresearch IAT，并导入IAT，fix之前掉壳的文件。

最后拖进IDA，就可以看到脱壳后的程序反编译的结果了。结合题目提示，字符串即flag。
![alt text](ida2.png)

#### 工具脱壳

用upx的工具进行脱壳，脱壳后的文件拖进IDA结果一致。
![alt text](unpackbytool.png)

## 笔记

{% notel red 壳 %}
[脱壳——UPX脱壳原理](https://www.cnblogs.com/Sna1lGo/p/14727846.html)
[加壳与脱壳理论详解](https://www.cnblogs.com/cainiao-chuanqi/p/14763537.html)
{% endnotel %}

# XOR

拖进IDA，F5一下
![alt text](xor1.png)

反编译结果大概是说，输入的flag字符串v5，从v5[1]开始和前一个字符做异或得到global。

找到global
![alt text](9e648f5389fd8773bc25dc43ff5c516.png)

提取字符串并转换成ascll码

```
data=[
	0x66, 0x0A, 0x6B, 0x0C, 0x77, 0x26, 0x4F, 0x2E, 0x40, 0x11,
    0x78, 0x0D, 0x5A, 0x3B, 0x55, 0x11, 0x70, 0x19, 0x46, 0x1F,
    0x76, 0x22, 0x4D, 0x23, 0x44, 0x0E, 0x67, 0x06, 0x68, 0x0F,
    0x47, 0x32, 0x4F
]
```

由

$$
\begin{aligned}
s[i]' &= s[i] \oplus s[i-1] \\
s[i] &= s[i]' \oplus s[i-1]
\end{aligned}
$$
脚本：

```python
data = [
    0x66, 0x0A, 0x6B, 0x0C, 0x77, 0x26, 0x4F, 0x2E, 0x40, 0x11,
    0x78, 0x0D, 0x5A, 0x3B, 0x55, 0x11, 0x70, 0x19, 0x46, 0x1F,
    0x76, 0x22, 0x4D, 0x23, 0x44, 0x0E, 0x67, 0x06, 0x68, 0x0F,
    0x47, 0x32, 0x4F
]

decrypted = encrypted_data.copy()
for i in range(len(decrypted)-1, 0, -1):
    decrypted[i] ^= decrypted[i-1]

flag = bytes(decrypted).decode('utf-8')
print("Decrypted Flag:", flag)
```

拿到flag

![alt text](8e4bbdacde59d80c8db2706f79dca28.png)
