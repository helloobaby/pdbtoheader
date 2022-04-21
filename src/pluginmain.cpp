#define _SILENCE_ALL_CXX20_DEPRECATION_WARNINGS

//https://hex-rays.com/products/ida/support/sdkdoc/fpro_8h.html
#define USE_STANDARD_FILE_FUNCTIONS

#define __EA64__

#define NO_OBSOLETE_FUNCS
#include "./hexrays_sdk/include/hexrays.hpp"
#include<fstream>
#include<format>

#define action_internal_name_1 "pdbheader::pdbheader"

#define action_show_name_1 "pdbtoheader"

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
        
        write_file.open(".\\sdk.h",ios_base::trunc | ios_base::out);
        if (!write_file.is_open())
        {
            msg("create/open file failed!\n");
        }
        write_file << "//Generate by https://github.com/helloobaby/pdbtoheader.git \n\n\n";
        write_file << "#pragma once \n";
        write_file << "#include <ntdef.h> \n\n\n";

        int seg_count = get_segm_qty();
        for (int s = 0; s < seg_count; s++) {

            qstring seg_name;
            qstring ea_name;
            if (segment_t* seg = getnseg(s))
            {
                
                get_segm_name(&seg_name, seg);

                msg("find the section:\n");
                msg("%s\n", seg_name.c_str());

                //忽略指定节
                if (!stricmp(seg_name.c_str(), ".pdata") ||
                    !stricmp(seg_name.c_str(), "RETPOL") ||
                    !stricmp(seg_name.c_str(), "INITKDBG") ||
                    !stricmp(seg_name.c_str(), "INIT") ||
                    !stricmp(seg_name.c_str(), "INITDATA"))
                  continue;

                auto seg_start = seg->start_ea;
                auto seg_end = seg->end_ea;
                for (ea_t i = seg_start; i < seg_end; i++)
                {
                    ea_name = get_name(i);
                    if (ea_name.size()) {
                      if (ea_name.find("unk_") != qstring::npos)
                        continue;
                        if (ea_name.find("loc_") != qstring::npos)
                          continue;
                        if (ea_name.find("algn_") != qstring::npos)
                          continue;
                        if (ea_name.find("word_") != qstring::npos)
                          continue;
                        if (ea_name[0] ==
                            'a') // windows内核驱动的函数命名都是pascal约定,所以这样判断没事
                          continue;
                        if (ea_name.find("stru_") != qstring::npos) //结构体
                          continue;
                        if (ea_name.find("byte_") !=
                            qstring::npos) //奇怪的全局变量
                          continue;
                        if (ea_name.find("sub_") !=
                            qstring::npos) //没有符号的函数
                          continue;
                        if (ea_name.find("@") !=
                            qstring::npos) // c++的一些很长的符号名称
                          continue;
                        if (ea_name.find("::") !=
                            qstring::npos) // c++的函数带作用域的函数名称,太长
                          continue;
                        if (ea_name.find("_imp_") != qstring::npos) //导入表
                          continue;

                        std::string t = std::format("const ULONG Offset_{} = {:#x};\n",
                            ea_name.c_str(), i - get_imagebase());
                        write_file << t;
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
    return true;
}

//--------------------------------------------------------------------------
// Initialize the plugin.
static plugmod_t* idaapi init()
{
  if (!init_hexrays_plugin()) {
    msg("pdbtoheader cant  init\n");
    return nullptr;
  }
    const char* hxver = get_hexrays_version();
    return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI|PLUGIN_UNL|PLUGIN_HIDE,
  init,                 
  nullptr,
  nullptr,
  nullptr,
  nullptr,             
  "pdbtoheader",
  nullptr,              
};
