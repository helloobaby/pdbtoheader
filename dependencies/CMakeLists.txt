include(FetchContent)  ##加了这个才能使用FetchContent_Declare

message("clone idasdk ....")
FetchContent_Declare(
       idasdk76
       GIT_REPOSITORY https://github.com/helloobaby/idasdk76.git
       GIT_TAG bd07eb74db4dbf30466c30f6e264fdb9c00eda10)
FetchContent_MakeAvailable(idasdk76) #如果长时间卡住的话，可以自己手动执行git clone
message("clone done...")
