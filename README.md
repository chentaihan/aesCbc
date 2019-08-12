## aesCbc

### aesCbc加密解密

#### 为什么要实现？
go本身不支持256位aes加密，而我又需要这个功能

#### 实现原理
aes-cbc-128：使用的是golang自带的功能

aes-cbc-256：把libmcrypt这个库的c语言实现，用go重新实现了一下

实现原理：将c语言翻译成go语言