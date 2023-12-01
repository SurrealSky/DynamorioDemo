//#define WINODWS
//#define X86_32
#include<stdio.h>
#include<inttypes.h>
#include<string>
#include "dr_api.h"
#include "drmgr.h"
#include"drwrap.h"


#ifdef X86_32
	#ifdef _DEBUG
		#pragma comment(lib,"ext\\lib32\\debug\\drwrap.lib")
		#pragma comment(lib,"ext\\lib32\\debug\\drmgr.lib")
		#pragma comment(lib,"lib32\\debug\\dynamorio.lib")
	#else
		#pragma comment(lib,"ext\\lib32\\release\\drwrap.lib")
		#pragma comment(lib,"ext\\lib32\\release\\drmgr.lib")
		#pragma comment(lib,"lib32\\release\\dynamorio.lib")
	#endif
#elif X86_64
	#ifdef _DEBUG
		#pragma comment(lib,"ext\\lib64\\debug\\drwrap.lib")
		#pragma comment(lib,"ext\\lib64\\debug\\drmgr.lib")
		#pragma comment(lib,"lib64\\debug\\dynamorio.lib")
	#else
		#pragma comment(lib,"ext\\lib64\\release\\drwrap.lib")
		#pragma comment(lib,"ext\\lib64\\release\\drmgr.lib")
		#pragma comment(lib,"lib64\\release\\dynamorio.lib")
	#endif
#endif

typedef struct bb_counts {
	uint64 blocks;
	uint64 total_size;
} bb_counts;

static bb_counts counts_as_built;
void* as_built_lock;

static bb_counts counts_dynamic;

typedef struct _module_array_t {
	app_pc base;
	app_pc end;
	std::string module_name;
} module_array_t;
#define MAX_MOD_NUM	0x30
static module_array_t mod_array[MAX_MOD_NUM];
static int num_mods;
void* mod_lock;

static void event_exit(void);
static void pre_fuzz_handler(void* wrapcxt, void** user_data);
static dr_emit_flags_t event_app2app_callback(void* drcontext, void* tag, instrlist_t* bb, bool for_trace, bool translating);
static dr_emit_flags_t event_analysis_callback(void* drcontext, void* tag,instrlist_t* bb, bool for_trace,bool translating, OUT void** user_data);
static dr_emit_flags_t instrument_insert_callback(void* drcontext, void* tag, instrlist_t* bb, instr_t* inst, bool for_trace, bool translating, void* user_data);
static dr_emit_flags_t instru2instru_callback(void* drcontext, void* tag, instrlist_t* bb, bool for_trace, bool translating);
static dr_emit_flags_t meta_instru_callback(void* drcontext, void* tag, instrlist_t* bb, bool for_trace, bool translating);
static dr_emit_flags_t trace_callback(void* drcontext, void* tag, instrlist_t* bb, bool translating);
static void event_module_load(void* drcontext, const module_data_t* info, bool loaded);


DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[])
{
	drmgr_init();
	drwrap_init();

	/* initialize lock */
	as_built_lock = dr_mutex_create();
	mod_lock = dr_mutex_create();
	num_mods = 0;
	
	//设置第1阶段回调
	drmgr_register_bb_app2app_event(event_app2app_callback, NULL);
	//设置2,3阶段回调
	drmgr_register_bb_instrumentation_event(event_analysis_callback, instrument_insert_callback,NULL);
	//设置4阶段回调
	drmgr_register_bb_instru2instru_event(instru2instru_callback, NULL);
	//设置5阶段回调
	drmgr_register_bb_meta_instru_event(meta_instru_callback, NULL);
	
	//设置跟踪回调
	dr_register_trace_event(trace_callback);
	//设置模块加载回调
	drmgr_register_module_load_event(event_module_load);
	//设置程序退出事件
	dr_register_exit_event(event_exit);


}

static void event_exit(void)
{
	dr_mutex_lock(as_built_lock);
	char msg[512];
	int len;
	len = snprintf(msg, sizeof(msg) / sizeof(msg[0]),
		"Number of basic blocks built: %" UINT64_FORMAT_CODE "\n Average size : % 5.2lf instructions\n"
		"Number of blocks executed  : %" UINT64_FORMAT_CODE "\n Average weighted size : %5.2lf instructions\n",
		counts_as_built.blocks,
		counts_as_built.total_size / (double)counts_as_built.blocks,
		counts_dynamic.blocks,
		counts_dynamic.total_size / (double)counts_dynamic.blocks);
	DR_ASSERT(len > 0);
	msg[sizeof(msg) / sizeof(msg[0]) - 1] = '\0'; /* NUll terminate */
	dr_printf("%s",msg);
	dr_mutex_unlock(as_built_lock);

	dr_mutex_destroy(as_built_lock);
	dr_mutex_destroy(mod_lock);
	drmgr_exit();
	drwrap_exit();
}

static void pre_fuzz_handler(void* wrapcxt, void** user_data)
{
	app_pc target_to_fuzz = drwrap_get_func(wrapcxt);
	dr_mcontext_t* mc = drwrap_get_mcontext_ex(wrapcxt, DR_MC_ALL);
	void *drcontext = drwrap_get_drcontext(wrapcxt);
}

static void event_module_load(void* drcontext, const module_data_t* info, bool loaded)
{
	dr_mutex_lock(mod_lock);
	//store module info
	const char* module_name = info->names.exe_name;
	if (module_name == NULL) 
	{ 
		module_name = dr_module_preferred_name(info); 
	}
	mod_array[num_mods].base = info->start;
	mod_array[num_mods].end = info->end;
	mod_array[num_mods].module_name = module_name;
	dr_printf("Module loaded: %s ,start: %p ,end: %p \n", mod_array[num_mods].module_name.c_str(), mod_array[num_mods].base, mod_array[num_mods].end);
	num_mods++;
	/*
	long fuzz_offset = 0x0;
	if (_stricmp(module_name, "Demo.exe") == 0) {
		to_wrap = info->start + fuzz_offset;
		drwrap_wrap_ex(to_wrap, pre_fuzz_handler, NULL, NULL, DRWRAP_CALLCONV_DEFAULT);
	}
	*/

	/*
	app_pc to_wrap = 0;
	if (_stricmp(module_name, "KERNEL32.dll") == 0) {
		to_wrap = (app_pc)dr_get_proc_address(info->handle, "CreateFileW");
		drwrap_wrap(to_wrap, createfilew_interceptor, NULL);
		to_wrap = (app_pc)dr_get_proc_address(info->handle, "CreateFileA");
		drwrap_wrap(to_wrap, createfilea_interceptor, NULL);
	}*/
	dr_mutex_unlock(mod_lock);
}

static dr_emit_flags_t event_app2app_callback(void* drcontext, void* tag, instrlist_t* bb, bool for_trace,bool translating)
{
	dr_printf("app2app callback\n");
	instr_t* instr = NULL;
	for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr))
	{
		app_pc address = instr_get_app_pc(instr);
		char buffer[0x20] = { 0 };
		disassemble_set_syntax(DR_DISASM_INTEL);
		instr_disassemble_to_buffer(drcontext, instr, buffer, 0x20);
		char addr[0x40] = { 0 };
		sprintf_s(addr, "%p %s\n", address,buffer);
		dr_printf("%s", addr);	
	}
	return DR_EMIT_DEFAULT;

	////修改指令
	//dr_mutex_lock(mod_lock);
	////获取目标模块地址
	//app_pc bb_addr = dr_fragment_app_pc(tag);
	//bool isFind = false;
	//int i = 0;
	//for (; i < num_mods; i++) 
	//{
	//	if (mod_array[i].base <= bb_addr && mod_array[i].end > bb_addr)
	//	{
	//		isFind = true;
	//		break;
	//	}
	//}
	//if (!isFind) return DR_EMIT_DEFAULT;
	//const char* dst_module = "Demo.exe";
	//app_pc dst_offset = mod_array[i].base+0x123d4;
	//if (strcmp(mod_array[i].module_name.c_str(), dst_module) == 0)
	//{
	//	//指令落在目标模块
	//	instr_t* instr;
	//	for (instr = instrlist_first_app(bb); instr != NULL; instr = instr_get_next_app(instr)) {
	//		
	//		app_pc address = instr_get_app_pc(instr);
	//		if (address == dst_offset)
	//		{
	//			//找到目标地址
	//			char buffer[0x30] = { 0 };
	//			disassemble_set_syntax(DR_DISASM_INTEL);
	//			instr_disassemble_to_buffer(drcontext, instr, buffer, sizeof(buffer));
	//			dr_printf("origin IL : %p %s\n",address, buffer);
	//			
	//			instr_t* new_instr = INSTR_CREATE_add(drcontext, instr_get_dst(instr, 0), instr_get_src(instr,0));
	//			memset(buffer, 0, sizeof(buffer));
	//			instr_disassemble_to_buffer(drcontext, new_instr, buffer, 0x30);
	//			dr_printf("changed IL : %s\n", buffer);
	//			if (instr_get_prefix_flag(instr, PREFIX_LOCK))
	//				instr_set_prefix_flag(new_instr, PREFIX_LOCK);
	//			instr_set_translation(new_instr, instr_get_app_pc(instr));
	//			
	//			instrlist_replace(bb, instr, new_instr);
	//			
	//			instr_destroy(drcontext, instr);
	//		}

	//	}
	//}
	//dr_mutex_unlock(mod_lock);
	//return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t event_analysis_callback(void* drcontext, void* tag, instrlist_t* bb, bool for_trace, bool translating, OUT void** user_data)
{
	dr_printf("analysis callback\n");
	instr_t* instr = NULL;
	for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr))
	{
		app_pc address = instr_get_app_pc(instr);
		char buffer[0x20] = { 0 };
		disassemble_set_syntax(DR_DISASM_INTEL);
		instr_disassemble_to_buffer(drcontext, instr, buffer, 0x20);
		char addr[0x40] = { 0 };
		sprintf_s(addr, "%p %s\n", address, buffer);
		dr_printf("%s", addr);
	}
	return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t instrument_insert_callback(void* drcontext, void* tag, instrlist_t* bb, instr_t* inst, bool for_trace, bool translating, void* user_data)
{
	dr_printf("insert callback\n");
	disassemble_set_syntax(DR_DISASM_INTEL);
	app_pc address = instr_get_app_pc(inst);
	char buffer[0x20] = { 0 };
	instr_disassemble_to_buffer(drcontext, inst, buffer, 0x20);
	dr_printf("%p %s\n", address, buffer);

	//统计功能
	uint num_instructions = 0;
	instr_t * instr,*where=NULL;

	for(instr = instrlist_first_app(bb); instr != NULL; instr = instr_get_next_app(instr))
	{
		/*
		app_pc address = instr_get_app_pc(instr);
		char buffer[0x20] = { 0 };
		disassemble_set_syntax(DR_DISASM_INTEL);
		instr_disassemble_to_buffer(drcontext, instr, buffer, 0x20);
		char addr[0x40] = { 0 };
		sprintf_s(addr, "%p %s", address,buffer);
		dr_printf("%s", addr);
		*/
		num_instructions++;
	}
	dr_mutex_lock(as_built_lock);
	counts_as_built.blocks++;
	counts_as_built.total_size += num_instructions;
	dr_mutex_unlock(as_built_lock);

	where = instrlist_first(bb);
	dr_save_arith_flags(drcontext, bb, where, SPILL_SLOT_1);
#ifdef X86_32
	instrlist_meta_preinsert(bb, where,LOCK(INSTR_CREATE_add(drcontext,OPND_CREATE_ABSMEM((byte*)&counts_dynamic.blocks, OPSZ_4),OPND_CREATE_INT8(1))));
	instrlist_meta_preinsert(bb, where,LOCK(INSTR_CREATE_adc(drcontext,OPND_CREATE_ABSMEM((byte*)&counts_dynamic.blocks + 4, OPSZ_4),OPND_CREATE_INT8(0))));
	instrlist_meta_preinsert(bb, where,LOCK(INSTR_CREATE_add(drcontext,OPND_CREATE_ABSMEM((byte*)&counts_dynamic.total_size, OPSZ_4),OPND_CREATE_INT_32OR8(num_instructions))));
	instrlist_meta_preinsert(bb, where,LOCK(INSTR_CREATE_adc(drcontext,OPND_CREATE_ABSMEM((byte*)&counts_dynamic.total_size + 4, OPSZ_4),OPND_CREATE_INT8(0))));
#else /* X86_64 */
	instrlist_meta_preinsert(bb, where,LOCK(INSTR_CREATE_inc(drcontext,OPND_CREATE_ABSMEM((byte*)&counts_dynamic.blocks, OPSZ_8))));
	instrlist_meta_preinsert(bb, where,LOCK(INSTR_CREATE_add(drcontext,OPND_CREATE_ABSMEM((byte*)&counts_dynamic.total_size, OPSZ_8),OPND_CREATE_INT_32OR8(num_instructions))));
#endif
	dr_restore_arith_flags(drcontext, bb, where, SPILL_SLOT_1);

	return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t instru2instru_callback(void* drcontext, void* tag, instrlist_t* bb, bool for_trace, bool translating)
{
	dr_printf("instru2instru callback\n");
	instr_t* instr = NULL;
	for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr))
	{
		app_pc address = instr_get_app_pc(instr);
		char buffer[0x20] = { 0 };
		disassemble_set_syntax(DR_DISASM_INTEL);
		instr_disassemble_to_buffer(drcontext, instr, buffer, 0x20);
		char addr[0x40] = { 0 };
		sprintf_s(addr, "%p %s\n", address, buffer);
		dr_printf("%s", addr);
	}
	return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t meta_instru_callback(void* drcontext, void* tag, instrlist_t* bb, bool for_trace, bool translating)
{
	dr_printf("meta_instru callback\n");
	instr_t* instr = NULL;
	for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr))
	{
		app_pc address = instr_get_app_pc(instr);
		char buffer[0x20] = { 0 };
		disassemble_set_syntax(DR_DISASM_INTEL);
		instr_disassemble_to_buffer(drcontext, instr, buffer, 0x20);
		char addr[0x40] = { 0 };
		sprintf_s(addr, "%p %s\n", address, buffer);
		dr_printf("%s", addr);
	}
	return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t trace_callback(void* drcontext, void* tag, instrlist_t* bb, bool translating)
{
	dr_printf("trace callback\n");
	instr_t* instr = NULL;
	for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr))
	{
		app_pc address = instr_get_app_pc(instr);
		char buffer[0x20] = { 0 };
		disassemble_set_syntax(DR_DISASM_INTEL);
		instr_disassemble_to_buffer(drcontext, instr, buffer, 0x20);
		char addr[0x40] = { 0 };
		sprintf_s(addr, "%p %s\n", address, buffer);
		dr_printf("%s", addr);
	}
	return DR_EMIT_DEFAULT;
}