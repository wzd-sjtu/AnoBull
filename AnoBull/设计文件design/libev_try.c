
// 这里是对libve库的简单化实现
// 主要是针对服务器端的写法

fd_single = socket();
bind();

// 初始化ev_loop*指针变量，0暂时不知道是什么意思
ev_loop* loop = ev_default_loop(0)

// 初始化ev_io，表示的事件是IO事件
// 函数原型  
// void ev_io_init(ev_io *io, callback, int fd, int events) 
// 对事件类型可以做自己的区分
ev_io* accept_event = NULL;
ev_io* listen_event = NULL;
ev_io* read_event = NULL;
ev_io* write_event = NULL;

ev_io_init(accept_event, accept_callback, fd_single, EV_READ)
ev_io_init(listen_event, listen_callback, fd_single, EV_READ)

// 将io event加入到事件列表之中
ev_io_start(loop, listen_event)

// 正式开启对应的的循环，是对的了
ev_loop(loop, 0)

// 对于不同的event，可以进行对应的不同的处理。


// 1.accept_event 对应的accept_callback
{
    FILE* fd = accept();

    ev_io_init(read_event, read_callback, fd, EV_READ);
    ev_io_start(loop, read_event);
}

// 2.read_event 对应的read_callback
{
    // 从套接字中获取buffer内容
    // fd在此处是唯一确定的
    read(fd);

    // 这里的w是什么东西呢？具体需要查阅相关文档
    ev_io_stop(EV_A_ w);

    // 事件驱动的一问一答类型的服务器，如何将它们和服务器分离开来？
    // 这需要首先设计好协议，再完成相应的代码

    ev_io_init(write_event, write_callback, fd, EV_WRITE);

    ev_io_start(loop, write_event);
}

// 3.write_event 对应的write_callback
{   
    // 为什么要write fd呢？这是为什么呢？不明白
    // 这个是向缓冲区写入有关内容用的，emm
    write(fd);

    // 将上一次的事件stop掉，从而加速
    ev_io_stop(EV_A_ w);

    ev_io_init(read_event, read_callback, fd, EV_READ);

    // 再次返回对应的event里面去了
    ev_io_start(loop, read_event);
}