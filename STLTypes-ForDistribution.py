# (C) Rolf Rolles, Mobius Strip Reverse Engineering, 9/21/2021.

import idaapi
from functools import reduce

stl_map_keyvalue_fmt = ("struct {2}_{3}_keyvalue_t"
"{{"
"{0} key;"
"{1} value;"
"}};")

stl_map_node_fmt = ("struct _Tree_node_{2}_{3};" # FORWARD DECLARATION
"struct _Tree_node_{2}_{3}"
"{{ "
"  _Tree_node_{2}_{3} *_Left;"
"  _Tree_node_{2}_{3} *_Parent;"
"  _Tree_node_{2}_{3} *_Right;"
"  bool _Color;"
"  bool _IsNil;"
"  {2}_{3}_keyvalue_t KeyValue;"
"}};")

stl_map_fmt = ("struct __cppobj map_{2}_{3}"
"{{ "
"  _Tree_node_{2}_{3} *_Myhead;"
"  unsigned __int64 _Mysize;"
"}};")

stl_map_pairib = ("struct __cppobj map_{2}_{3}_iterator_pairib"
"{{ "
"  _Tree_node_{2}_{3} *_Myhead;"
"  bool _Second;"
"}};")
 

stl_map_templates = [stl_map_keyvalue_fmt, stl_map_node_fmt, stl_map_fmt, stl_map_pairib]

stl_map_func_insert_at = "_Tree_node_{2}_{3} **__fastcall map_{2}_{3}_insert_at(map_{2}_{3} *map, _Tree_node_{2}_{3} **it_out, bool IsLeft, _Tree_node_{2}_{3} *it1_in, {2}_{3}_keyvalue_t *keyValue, _Tree_node_{2}_{3} *it2_in);"
stl_map_func_insert_nohint = "map_{2}_{3}_iterator_pairib *__fastcall map_{2}_{3}_insert_nohint(map_{2}_{3} *map, map_{2}_{3}_iterator_pairib *itp_out, bool IsLeft, {2}_{3}_keyvalue_t *keyValue, _Tree_node_{2}_{3} *it2_in);"
stl_map_func_insert_hint = "_Tree_node_{2}_{3} **__fastcall map_{2}_{3}_insert_hint(map_{2}_{3} *map, _Tree_node_{2}_{3} **it_out, _Tree_node_{2}_{3} *it1_in, {2}_{3}_keyvalue_t *keyValue, _Tree_node_{2}_{3} *it2_in);"

stl_map_funcsigs = [stl_map_func_insert_at, stl_map_func_insert_nohint, stl_map_func_insert_hint]

def ParseOneDecl(declWithSemi):
	retVal = idaapi.parse_decls(None, declWithSemi, None, idaapi.convert_pt_flags_to_hti(idaapi.PT_TYP))
	return retVal is not None

def MakeMapTypes(sKeyType, sValType, sKeyName=None, sValName=None):
	if sKeyName is None:
		sKeyName = sKeyType
	if sValName is None:
		sValName = sValType
	stl_types_reified = map(lambda s:s.format(sKeyType,sValType,sKeyName,sValName),stl_map_templates)
	stl_types_reduced = reduce(lambda x,y: x+y, stl_types_reified)
	if not ParseOneDecl(stl_types_reduced):
		print("Could not parse declaration: %s" % stl_types_reduced)
		return False
	stl_funcs_reified = map(lambda s:s.format(sKeyType,sValType,sKeyName,sValName),stl_map_funcsigs)
	stl_funcs_reduced = reduce(lambda x,y: x+"\n"+y, stl_funcs_reified)
	return True
	
stl_set_node_fmt = ("struct _Tree_node_{1};" # FORWARD DECLARATION
"struct _Tree_node_{1}"
"{{ "
"  _Tree_node_{1} *_Left;"
"  _Tree_node_{1} *_Parent;"
"  _Tree_node_{1} *_Right;"
"  bool _Color;"
"  bool _IsNil;"
"  {0} _Key;"
"}};")

stl_set_fmt = ("struct __cppobj set_{1}"
"{{ "
"  _Tree_node_{1} *_Myhead;"
"  unsigned __int64 _Mysize;"
"}};")

stl_set_pairib = ("struct __cppobj set_{1}_iterator_pairib"
"{{ "
"  _Tree_node_{1} *_Myhead;"
"  bool _Second;"
"}};")
 

stl_set_templates = [stl_set_node_fmt, stl_set_fmt, stl_set_pairib]

def MakeSetTypes(sKeyType, sKeyName=None):
	if sKeyName is None:
		sKeyName = sKeyType
	stl_types_reified = map(lambda s:s.format(sKeyType,sKeyName),stl_set_templates)
	stl_types_reduced = reduce(lambda x,y: x+y, stl_types_reified)
	if not ParseOneDecl(stl_types_reduced):
		print("Could not parse declaration: %s" % stl_types_reduced)
		return False
	return True
	
stl_deque_cont = ("struct deque_{1} {{"
"  void *_Myproxy;"
"  {0} **_Map;"
"  size_t _Mapsize;"
" _QWORD _Myoff;"
" _QWORD _Mysize;"
"}};")

def MakeDequeType(sEltType, sEltName=None):
	if sEltName is None:
		sEltName = sEltType
	deque_type_reified = stl_deque_cont.format(sEltType, sEltName)
	if not ParseOneDecl(deque_type_reified):
		print("Could not parse declaration: %s" % deque_type_reified)
		return False
	return True

stl_vector_cont = ("struct vector_{1} {{"
"  {0} *_Myfirst;"
"	 {0} *_Mylast;"
"	 {0} *_Myend;"
"}};")
	
def MakeVectorType(sEltType, sEltName=None):
	if sEltName is None:
		sEltName = sEltType
	vector_type_reified = stl_vector_cont.format(sEltType, sEltName)
	if not ParseOneDecl(vector_type_reified):
		print("Could not parse declaration: %s" % vector_type_reified)
		return False
	return True

stl_list_node = ("struct _List_node_{1};" # FORWARD DECLARATION
"struct _List_node_{1}"
"{{ "
"	 _List_node_{1} *_Next;"
"	 _List_node_{1} *_Prev;"
"	 {0} _Myval;"
"}};")

stl_list_cont = ("struct list_{1}"
"{{ "
"	 _List_node_{1} *_Myhead;"
"	 size_t _Mysize;"
"}};")
	
stl_list_templates = [stl_list_node, stl_list_cont]

def MakeListTypes(sEltType, sEltName=None):
	if sEltName is None:
		sEltName = sEltType
	stl_types_reified = map(lambda s:s.format(sEltType,sEltName),stl_list_templates)
	stl_types_reduced = reduce(lambda x,y: x+y, stl_types_reified)
	if not ParseOneDecl(stl_types_reduced):
		print("Could not parse declaration: %s" % stl_types_reduced)
		return False
	return True

stl_ref_count_base_vtbl_fmt = ("struct _Ref_count_base_{1};"
"struct _Ref_count_base_{1}_vtbl {{"
"	void  (__fastcall *_Destroy)(_Ref_count_base_{1} *this);"
"	void  (__fastcall *_Delete_this)(_Ref_count_base_{1} *this);"
"	void  (__fastcall *Destructor)(_Ref_count_base_{1} *this);"
"	void *(__fastcall *_Get_deleter)(_Ref_count_base_{1} *this);"
"}};")

stl_ref_count_base_fmt = ("struct _Ref_count_base_{1}_vtbl;"
"struct _Ref_count_base_{1} {{"
"  _Ref_count_base_{1}_vtbl *__vftable;"
"  volatile int _Uses;"
"  volatile int _Weaks;"
"}};")

stl_ref_count_fmt = ("struct _Ref_count_base_{1};"
"struct _Ref_count_{1} : _Ref_count_base_{1} {{"
"  {0} *_Ptr;"
"}};")

stl_ref_count_obj_fmt = ("struct _Ref_count_base_{1};"
"struct _Ref_count_obj_{1} : _Ref_count_base_{1} {{"
"  {0} _Storage;"
"}};")

# Changed _Ref_count to _Ref_count_base
stl_shared_ptr_fmt = ("struct _Ref_count_base_{1};"
"struct shared_ptr_{1} {{"
"  {0} *_Ptr;"
"  _Ref_count_base_{1} *_Rep;"
"}};")

# FOR 64-BIT TYPES BECAUSE OF __shifted(X,16)
# OTHERWISE WOULD BE __shifted(X,12)
stl_shared_ptr_obj_fmt = ("struct _Ref_count_obj_{1};"
"struct shared_ptr_obj_{1} {{"
"  {0} *__shifted(_Ref_count_obj_{1},16) _Ptr;"
"  _Ref_count_obj_{1} *_Rep;"
"}};")

stl_shared_ptr_templates = [stl_ref_count_base_vtbl_fmt, stl_ref_count_base_fmt, stl_ref_count_fmt, stl_ref_count_obj_fmt, stl_shared_ptr_fmt, stl_shared_ptr_obj_fmt]

def MakeSharedPtrTypes(sEltType, sEltName=None):
	if sEltName is None:
		sEltName = sEltType
	stl_types_reified = map(lambda s:s.format(sEltType,sEltName),stl_shared_ptr_templates)
	stl_types_reduced = reduce(lambda x,y: x+y, stl_types_reified)
	if not ParseOneDecl(stl_types_reduced):
		print("Could not parse declaration:")
		return False
	return True
