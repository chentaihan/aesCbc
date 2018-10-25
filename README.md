## aesCbc

### aes-cbc-256加密解密

#### 为什么要实现？
go本身不支持256位aes加密，而我又需要这个功能

#### 实现原理
和php自带的mcrypt的aes-cbc-256功能完全一样，就是把libmcrypt这个库的c语言实现，用golang重新实现了一下