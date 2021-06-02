import idaapi
import ida_hexrays
import ida_typeinf
import ida_kernwin

API_TYPE_ACTION_NAME = "setAPIType"
API_TYPE_ACTION_DESC = "Re-type as API * ..."
API_TYPE_ACTION_SHORTCUT = "CTRL-SHIFT-A"

# Look up the type signature for an API name. 
def GetTypeSignature(apiName):
	
	# Look up the prototype by name from the main TIL
	o = ida_typeinf.get_named_type(None, apiName, ida_typeinf.NTF_SYMU)
	
	# Found?
	if o is not None:
		code, type_str, fields_str, cmt, field_cmts, sclass, value = o
		
		# Create a tinfo_t by deserializing the data returned above
		t = ida_typeinf.tinfo_t()
		if t.deserialize(None, type_str, fields_str, field_cmts):
			
			# And change the prototype into a function pointer
			ptrType = ida_typeinf.tinfo_t()
			ptrType.create_ptr(t)
			return ptrType
	
	# On any failure, return None
	return None

# Convenience function to set 
def ChangeVariableType(func_ea, lvar, tif):
	lsi = ida_hexrays.lvar_saved_info_t()
	lsi.ll = lvar
	lsi.type = ida_typeinf.tinfo_t(tif)
	if not ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_TYPE, lsi):
		print("[E] Could not modify lvar type for %s" % lvar.name)
		return False
	return True

def is_32bit():
	return not ida_ida.inf_is_64bit()

PTR_SIZE = 4 if is_32bit() else 8

def IsPtrSizedLvar(vu):
	lvar = vu.item.get_lvar()
	if lvar is None:
		return False
	return lvar.width == PTR_SIZE

# The popup menu item handler
class api_ptr_type_setter(ida_kernwin.action_handler_t):
	def __init__(self):
		ida_kernwin.action_handler_t.__init__(self)

	def activate(self, ctx):
		vu = ida_hexrays.get_widget_vdui(ctx.widget)
		if not IsPtrSizedLvar(vu):
			return 1
		
		lvar = vu.item.get_lvar()
		name = ida_kernwin.ask_str("", ida_kernwin.HIST_IDENT, "Please enter the API name for which to set the type")
		if name is None:
			return 1
		
		ptrTif = GetTypeSignature(name)
		if ptrTif is None:
			ida_kernwin.warning("Could not get type for \"%s\"" % name)
			return 1
		
		ChangeVariableType(vu.cfunc.entry_ea, lvar, ptrTif)
		vu.cfunc.refresh_func_ctext()
		
		return 1

	def update(self, ctx):
		vu = ida_hexrays.get_widget_vdui(ctx.widget)
		if vu is None:
			return ida_kernwin.AST_DISABLE_FOR_WIDGET
		if IsPtrSizedLvar(vu):
			return ida_kernwin.AST_ENABLE
		return ida_kernwin.AST_DISABLE

def ApiPtrTypeSetInstall():
	if ida_hexrays.init_hexrays_plugin():
		ra = ida_kernwin.register_action(
			ida_kernwin.action_desc_t(
				API_TYPE_ACTION_NAME,
				API_TYPE_ACTION_DESC,
				api_ptr_type_setter(),
				API_TYPE_ACTION_SHORTCUT))

	else:
		print("API * type setter: hexrays is not available.")

def ApiPtrTypeSetUninstall():
	idaapi.unregister_action(API_TYPE_ACTION_NAME)

ApiPtrTypeSetUninstall()
ApiPtrTypeSetInstall()

# This class lets us only show the menu item when the cursor is currently over
# a pointer-sized local variables
class ApiPtrHooks(ida_hexrays.Hexrays_Hooks):
	def populating_popup(self, widget, popup_handle, vu):
		if IsPtrSizedLvar(vu):
			ida_kernwin.attach_action_to_popup(widget,popup_handle,API_TYPE_ACTION_NAME)
		return 0

# Convenience for development
try:
	apiptrhooks.unhook()
	del apiptrhooks
except NameError as e:
	pass
finally:
	apiptrhooks = ApiPtrHooks()
	apiptrhooks.hook()
