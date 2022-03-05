#ifndef __SERVER_CONFIG_H
#define __SERVER_CONFIG_H

#define DB_PATH "./SQLite.db"
// 串行模式
// #define SQLITE_MOD SQLITE_CONFIG_SERIALIZED
// 多线程模式
#define SQLITE_MOD SQLITE_CONFIG_MULTITHREAD
// 上文定义了一些基本的工作单位了

// 完整的公钥长度才是750左右，完全够用，包括了很长的line存在于此啦
#define SQL_MAX_LINE 1024

// 这句魔数是为了区别某个m_vector是否为无效
// 这句话就是典型写照，有一定概率产生冲突？方案上是不可行的。
#define HIDDEN_INFO_CHARS "not useful"
#endif