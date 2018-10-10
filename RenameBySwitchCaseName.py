from collections import defaultdict

class CallExtractor(idaapi.ctree_visitor_t):
	def __init__(self):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
		self.calls = []
	
	# Hex-Rays will call this function for every expression within the first
	# line of code extracted from the case statement bodies.
	def visit_expr(self,i):

		# Look for call expressions...
		if i.op == idaapi.cot_call:

			# ... where the target is a known location in the database.
			if i.x.op == idaapi.cot_obj:
				self.calls.append(i.x.obj_ea)

		return 0
	
class SwitchExaminer(idaapi.ctree_visitor_t):
	def __init__(self):
		idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST | idaapi.CV_INSNS)
		self.mapping = defaultdict(list)
	
	# This function extracts the addresses of all functions called from the
	# first line of a case statement.
	def ExtractCalls(self,cinsn,label):
		
		# Switch cases usually have cblock_t bodies.
		if cinsn.op == idaapi.cit_block:
			# Copy the first instruction out of the cblock_t.
			cinsn = cinsn.cblock.front()

		# Extract the calls from the first line
		ce = CallExtractor()
		ce.apply_to(cinsn, None)

		# If there was only one call, record it and the switch case number 
		# (which is one of the hexcall_t enumerated elements).
		if len(ce.calls) == 1:
			self.mapping[ce.calls[0]].append(label)
	
	# Hex-Rays will call this function for every instruction in the 
	# decompilation listing.
	def visit_insn(self,i):
		
		# Look for switch statements.
		if i.op == idaapi.cit_switch:
			
			# Iterate over all switch cases.
			for c in i.cswitch.cases:

				# Extract the numeric values associated with this switch case.
				# This line requires IDA 7.2; the value vector in ccase_t is
				# not accessible in IDA 7.1 or below.
				labels = [ l for l in c.values ]

				# If there was only one case label, extract called functions
				# from the first line of the case statement.
				if len(labels) == 1:
					self.ExtractCalls(c.cinsn, labels[0])
		return 0

# Get the func_t for hexdsp. (Address is from my copy of hexrays.dll.)
f = idaapi.get_func(0x0000000017033B6C)

if f is None:
	print "Couldn't get func_t for hexdsp?"

else:
	# Decompile the function.
	cfunc = idaapi.decompile(f)
	if cfunc is None:
		print "Failed to decompile!"

	else:	
		# Apply the visitors above to the decompilation listing.
		se = SwitchExaminer()
		se.apply_to(cfunc.body, None)

		# Get the IDA enumeration number for hexcall_t (must be loaded in the
		# database as an enumeration); see the corresponding blog entry.
		enumT = idaapi.get_enum("hexcall_t")
		namesApplied = 0

		# Iterate through the information collected by the visitor.
		for (k,v) in se.mapping.items():

			# For each function that was only called once on the first line of
			# a case statement body...
			if len(v) == 1:

				# Get the IDA enumeration element number for the numeric value
				# of the case label.
				enumM = idaapi.get_enum_member(enumT, v[0], -1, idaapi.DEFMASK)
				
				# Get the name of the enumeration element as a string.
				retVal = idaapi.get_enum_member_name(enumM)

				# The hexcall_t elements all begin with "hx_"; strip that off.
				if retVal and retVal[0:3] == "hx_":
					
					# Rename the function after the enumeration element.
					idaapi.set_name(k,retVal[3:])
					namesApplied += 1

		print namesApplied, "names created"
				