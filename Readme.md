#一个IDA插件

借用IDA 的PDB 解析（实际上用微软github那个PDB解析例子解析不到，我也懒得研究了），获得所有的导出/未导出函数偏移和全局变量偏移，方便驱动的编写。

因为所有变量写在头文件，所以可能会重定义，如果编译器支持inline，在每个变量前加inline或const，或者写在cpp内写，别的文件extern

![Image Text](https://github.com/helloobaby/pdbtoheader/blob/master/1.png)
