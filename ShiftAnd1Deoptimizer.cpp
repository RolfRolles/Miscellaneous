// ShiftAnd1Deoptimizer.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <hexrays.hpp>

// Hex-Rays API pointer
hexdsp_t *hexdsp = NULL;


struct ShiftAnd1Deoptimizer : public minsn_visitor_t
{
	// Replaces:
	// *  (x >> n) & 1 => (x & (1<<n)) != 0
	// * ~(x >> n) & 1 => (x & (1<<n)) == 0
	int visit_minsn()
	{
		minsn_t *ins = this->curins;
		bool bHadNot = false;

		// Instruction must be AND(x,y,z)
		if (ins->opcode != m_and)
			return 0;

		// Either x or y must be numeric
		mop_t *nonNumOp = NULL;
		mop_t *numOp = ins->find_num_op(&nonNumOp);
		if (numOp == NULL)
			return 0;

		// The numeric operand must have the value 1
		if (numOp->nnn->value != 1ULL)
			return 0;

		// The other operand must be compound
		if (nonNumOp->t != mop_d)
			return 0;

		int size = nonNumOp->size;
		
		minsn_t *topLevelNonNum = nonNumOp->d;
		// We have two patterns. One has a bnot underneath the top-level m_and, the 
		// other doesn't.
		if (topLevelNonNum->opcode == m_bnot)
		{
			bHadNot = true;
			// The left-hand operand must be a compound instruction.
			if (topLevelNonNum->l.t != mop_d)
				return 0;
			topLevelNonNum = topLevelNonNum->l.d;
		}

		// There must be an m_low instruction beneath the m_and or m_bnot.
		if (topLevelNonNum->opcode != m_low)
			return 0;

		// Its left-hand side must be a compound instruction.
		if (topLevelNonNum->l.t != mop_d)
			return 0;

		minsn_t *lowSubexpression = topLevelNonNum->l.d;

		// The subinstruction must be an m_shr.
		if (lowSubexpression->opcode != m_shr)
			return 0;

		// The right-hand side of the shift must be numeric.
		if (lowSubexpression->r.t != mop_n)
			return 0;

		// If we get here, then the pattern matched. Now we need to convert the
		// microinstructions into a test. This is a little involved
		// because we need to make sure that the result of the test is the same
		// size as the result of the AND operation, so we might have to extend,
		// truncate, or keep the size the same as it was. Hence this compound
		// ternary expression in the line below.
		// 
		// There's another piece of subtlety in the line below. If the m_and
		// instruction was at the top level, then it will have a "destination"
		// operand. If it doesn't, it won't. Do we need to treat those two
		// cases differently? After all, if it doesn't have a destination 
		// operand, then it doesn't make any sense to "move" the result into
		// a non-existent destination. It turns out that the code below handles
		// both cases, because the first thing that minsn_t::optimize_subtree 
		// does is to call a function that specifically looks for patterns of 
		// instructions like this and fixes them up.
		ins->opcode = ins->d.size == size ? m_mov :
			ins->d.size > size ? m_xdu : m_low;
		
		// Those three instruction varieties don't have right-hand ("r") 
		// operands, so erase the existing one.
		ins->r.erase();
		
		// We insert a "== 0" or "!= 0" depending on whether there was an 
		// m_bnot in the pattern.
		topLevelNonNum->opcode = bHadNot ? m_setz : m_setnz;
		
		// Here's where we create the AND by the constant.
		lowSubexpression->opcode = m_and;
		
		// By copying the original address/operand number from the shift constant,
		// we get the ability to change the constant into an enumeration element in
		// the disassembly. Evidently, in order to convert numbers into enumeration
		// elements, Hex-Rays requires that the number have a corresponding location
		// of a numeric operand in the disassembly, even if the number in the 
		// disassembly is not the same as what's in the decompilation. My original
		// solution did not set an address/operand number, and so it was not 
		// possible to change the number into an enumeration element.
		uint64 newValue = 1ULL << lowSubexpression->r.nnn->value;
		int newSize = lowSubexpression->l.size;
		ea_t origEa = lowSubexpression->r.nnn->ea;
		int origOp = lowSubexpression->r.nnn->opnum;
		lowSubexpression->r.make_number(newValue, newSize, origEa, origOp);
		
		// Insert the AND instruction as the child of the m_setz/m_setnz.
		topLevelNonNum->l.d->swap(*lowSubexpression);
		
		// This is the "0" part of the "!= 0" or "== 0".
		topLevelNonNum->r.make_number(0ULL, lowSubexpression->l.size);
		ins->l.d->swap(*topLevelNonNum);

		// Now tell Hex-Rays to propagate these changes into the parent 
		// instruction.
#if IDA_SDK_VERSION == 710
		ins->optimize_flat();
#elif IDA_SDK_VERSION >= 720
		ins->optimize_solo();
#endif	
		
		// Return 1 to indicate that we changed the microcode.
		return 1;
	}
};

// I had tried to install the function above as an "instruction optimizer", but
// I found that I did not get callbacks consistently. Sometimes my plugin would
// get called and could modify the microcode, and other times it wouldn't. So, 
// I created this block optimizer instead, which simply calls the code above
// for all microcode instructions in a block.
struct ShiftAnd1BlockDeoptimizer : optblock_t
{
	int func(mblock_t *blk)
	{
		ShiftAnd1Deoptimizer insDeopt;
		return blk->for_all_insns(insDeopt);
	}
};

ShiftAnd1BlockDeoptimizer blk_deopt;
//--------------------------------------------------------------------------
int idaapi init(void)
{
	if (!init_hexrays_plugin())
		return PLUGIN_SKIP; // no decompiler
	const char *hxver = get_hexrays_version();
	msg("Hex-rays version %s has been detected, %s ready to use\n", hxver, PLUGIN.wanted_name);
	install_optblock_handler(&blk_deopt);
	return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
	if (hexdsp != NULL)
	{
		remove_optblock_handler(&blk_deopt);
		term_hexrays_plugin();
	}
}

//--------------------------------------------------------------------------
bool idaapi run(size_t arg)
{
	if (arg == 0xbeef)
	{
		PLUGIN.flags |= PLUGIN_UNL;
		return true;
	}
	return true;
}

//--------------------------------------------------------------------------
static char comment[] = "Rewrite (x>>n)&1";
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,                    // plugin flags
	init,                 // initialize
	term,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	comment,              // long comment about the plugin
						  // it could appear in the status line
						  // or as a hint
						  "",                   // multiline help about the plugin
						  "DeoptimizeShiftAnd",  // the preferred short name of the plugin
						  ""                    // the preferred hotkey to run the plugin
};
