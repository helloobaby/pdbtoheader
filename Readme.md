## A IDA plugin

基于IDA,将所有符号转成偏移存储在头文件里(通俗点说就是硬编码(hard signature))

适合写点poc的项目。

编译:
mkdir build 
cd build
cmake -DIDA_INSTALL_DIR="E:\IDA Pro 7.6" ..    
上面提供自己的ida路径,作用就是将dll编译到插件目录的


用法:  


![Image Text](https://github.com/helloobaby/pdbtoheader/blob/master/123.png)

![Image Text](https://github.com/helloobaby/pdbtoheader/blob/master/QQ截图20220419213541.png)


