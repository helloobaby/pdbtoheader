#define _SILENCE_ALL_CXX20_DEPRECATION_WARNINGS

//https://hex-rays.com/products/ida/support/sdkdoc/fpro_8h.html
#define USE_STANDARD_FILE_FUNCTIONS


//这个涉及到地址长度的问题，用ida64.exe就得加这个宏，ida32.exe不用
#define __EA64__
//
// ida7.5及以上的插件一定要定义这个宏
// 为了保证老代码能够编译，IDA还是会支持一些老结构体，但是在新IDA上全都不能用，会导致未定义问题
// 这个宏确保你没有使用sdk中废弃的代码
//
#define NO_OBSOLETE_FUNCS
#include "./hexrays_sdk/include/hexrays.hpp"
#include<fstream>

//IDA内部用的名字，识别每个UI部件的,前面加作用域是IDA的推荐做法
#define action_internal_name_1 "example::name"

//这个是右键显示给用户的名字
#define action_show_name_1 "example"

using namespace std;
std::ofstream write_file;

ssize_t idaapi ui_hook(void* user_data, int notification_code, va_list va)
{
    if (notification_code == ui_populating_widget_popup)
    {
        TWidget* view = va_arg(va, TWidget*);
        if (get_widget_type(view) == BWN_DISASM) {
            TPopupMenu* p = va_arg(va, TPopupMenu*);
            attach_action_to_popup(view, p, action_internal_name_1, nullptr, SETMENU_FIRST);
        }
    }

    return false;
}

struct example_action : public action_handler_t
{
    //action被触发的主逻辑
    virtual int idaapi activate(action_activation_ctx_t* ctx) override
    {
        static char buffer[128]{};
        qstring funcName;
        write_file.open(".\\PDBSDK.h",ios_base::trunc | ios_base::out);
        if (!write_file.is_open())
        {
            msg("create/open file failed!\n");
        }
        write_file << "//Generate by https://github.com/helloobaby/pdbtoheader.git \n\n\n";
        write_file << "#pragma once \n";
        write_file << "#include <ntdef.h> \n\n\n";
//        for (int f = 0; f < get_func_qty(); f++)   //get_func_qty() 获取有符号函数数量
//        {
//            func_t* curfunc = getn_func(f);     //获取函数信息
//            get_func_name(&funcName, curfunc->start_ea); //获取函数名
//            //把没符号的sub_xx排除了，然后写入文件
//            if (funcName.find(("sub_")) != qstring::npos)
//                continue;
//            if (funcName.find(("@")) != qstring::npos)
//                continue;
//            if (funcName.find(("::")) != qstring::npos)
//                continue;
//
//#if 0
//            msg("%s:\t %llx\n",funcName.c_str(), curfunc->start_ea);    //打印函数名和函数起始地址.
//#endif       
//            //不要用c/c++提供的标准sprintf，会导致IDA无法正常关闭！
//            qsnprintf(buffer,sizeof(buffer),
//                "ULONG Offset%s = 0x%x;\n", funcName.c_str(),
//                curfunc->start_ea - get_imagebase());
//            write_file << buffer;
//            write_file.flush();
//            memset(buffer, 0, sizeof(buffer));
//        }

        int seg_count = get_segm_qty();
        for (int s = 0; s < seg_count; s++) {

            qstring seg_name;
            qstring ea_name;
            if (segment_t* seg = getnseg(s))
            {
                
                get_segm_name(&seg_name, seg);
#if 0
                msg("%s\n", seg_name.c_str());
#endif
                //忽略下面的节，根据内核文件的不同要添加或减少，这里是win10 1809的例子
                if (!stricmp(seg_name.c_str(), "kvascode")||
                    !stricmp(seg_name.c_str(), "retpol")|| !stricmp(seg_name.c_str(), "INITKDBG")||
                    !stricmp(seg_name.c_str(), "POOLCODE")|| !stricmp(seg_name.c_str(), ".idata")||
                    !stricmp(seg_name.c_str(), ".pdata")|| !stricmp(seg_name.c_str(), "INIT")||
                    !stricmp(seg_name.c_str(), "INITDATA")|| !stricmp(seg_name.c_str(), "PAGEVRFY"))
                    continue;

                auto seg_start = seg->start_ea;
                auto seg_end = seg->end_ea;
                for (ea_t i = seg_start; i < seg_end; i++)
                {
                    ea_name = get_name(i);
                    if (ea_name.size()) {//过滤一下没有符号的
                        if (ea_name.find("unk") != qstring::npos)
                            continue;
                        if (ea_name.find("loc") != qstring::npos)
                            continue;
                        if (ea_name.find("algn") != qstring::npos)
                            continue;
                        if (ea_name.find("word_") != qstring::npos)
                            continue;
                        if (ea_name.find("off") != qstring::npos)
                            continue;
                        if (ea_name[0] == 'a'))//ida 会把ascal字符串命名为a开头
                            continue;
                        if (ea_name.find("stru") != qstring::npos)
                            continue;
                        if (ea_name.find("byte_") != qstring::npos)
                            continue;
                        if (ea_name.find("sub_") != qstring::npos)
                            continue;
                        if (ea_name.find("@") != qstring::npos)
                            continue;
                        if (ea_name.find("::") != qstring::npos)
                            continue;
#if 0
                        msg("%s\n", ea_name.c_str());
#endif
                        qsnprintf(buffer, sizeof(buffer),
                            "const ULONG Offset%s = 0x%x;\n", ea_name.c_str(),
                            i - get_imagebase());
                        write_file << buffer;
                        write_file.flush();
                        memset(buffer, 0, sizeof(buffer));
                    }
                }
            }

        }
        write_file.flush();
        write_file.close();
        return true;
    }

    virtual action_state_t idaapi update(action_update_ctx_t* ctx) override
    {
        //AST_DISABLE选项的话action就是灰色，无法点
        return AST_ENABLE_ALWAYS;
    }
};

example_action action1;
struct plugin_ctx_t : public plugmod_t
{
    plugin_ctx_t()
    {
        register_action(ACTION_DESC_LITERAL_PLUGMOD(
            action_internal_name_1,// action name
            action_show_name_1, // show name
            &action1,
            this,
            nullptr,
            nullptr,
            -1));

        hook_to_notification_point(HT_UI, ui_hook);
    }
    ~plugin_ctx_t()
    {
        unregister_action(action_internal_name_1);
        unhook_from_notification_point(HT_UI, ui_hook);
        term_hexrays_plugin();
    }
    virtual bool idaapi run(size_t) override;
};



//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
    msg("hello world");
    
    return true;
}

//--------------------------------------------------------------------------
// Initialize the plugin.
static plugmod_t* idaapi init()
{
    if (!init_hexrays_plugin())
        return nullptr; // no decompiler
    const char* hxver = get_hexrays_version();
    msg("Hex-rays version %s has been detected, %s ready to use\n",
        hxver, PLUGIN.wanted_name);
    return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
static const char comment[] = "whatever you want";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI|PLUGIN_UNL|PLUGIN_HIDE,//PLUGIN_UNL用来调试，run一次就自动卸载的功能
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "whatever you want", // 在Edit->Plugins中显示的名字
  nullptr,              // 热键
};
