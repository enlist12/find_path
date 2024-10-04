import idautils
import idaapi
import angr
import idangr
import angrdbg
import idc
import os
import claripy
from archinfo import Endness

'''
create solution file
'''

cur=idc.get_input_file_path()

dir = os.path.dirname(cur)

file_name = os.path.splitext(os.path.basename(cur))[0]

new_path = os.path.join(dir, file_name + ".sol")



def check(addr:int,block:idaapi.BasicBlock)->bool:
    if addr>=block.start_ea and addr<block.end_ea:
        return True
    return False

'''
automatically get i1 address and i2 address
'''

start:int=idc.get_reg_value('rip')

n=idc.get_bpt_qty()

for i in range(n):
    if idc.get_bpt_ea(i)!=start:
        end:int=idc.get_bpt_ea(i)
        break


paths=[]

func=0

start_bk=0

def dfs(block:idaapi.BasicBlock,cur:list[int]):
    new_path = cur + [block.start_ea]
    if check(end,block):
        global paths
        paths.append(new_path)
        return
    next=list(block.succs())
    if not next:
        return
    for bk in next:
        dfs(bk,new_path)
    return

def comp(type:str,pos,vector,state:angr.SimState)->bool:
    cur=0
    if type=='reg':
        cur=idc.get_reg_value(pos)
        state.solver.add(vector==cur)
        if state.satisfiable():
            return True
    if type=='mem':
        size=vector.size()
        length=int(size/8)
        if length==1:
            cur=idc.get_wide_byte(pos)
        elif length==2 :
            cur=idc.get_wide_word(pos)
        elif length==4 :
            cur=idc.get_wide_dword(pos)
        elif length==8 :
            cur=idc.get_wide_qword(pos)
        state.solver.add(vector==cur)
        if state.satisfiable():
            return True
    return False


'''
    find the function that includes the path
'''
for ea in idautils.Functions():
    func=idaapi.get_func(ea)
    if start>=func.start_ea and start<func.end_ea:
        break

chart=idaapi.FlowChart(func)

'''
    find the block that contains the start
'''

for block in chart:
    if check(start,block):
        start_bk=block
        break

'''
    harness the dfs to collect paths from start_point to end_point
'''

dfs(start_bk,[])

#print('paths:',paths) #used for figure out paths
"""
    get current state
"""


if not idangr.is_initialized():
    idangr.init()

proj=angrdbg.reload_project()

regs=proj.arch.register_names

state=angrdbg.StateShot()
'''
irsb = proj.factory.block(state.addr).vex

print(irsb.pp())
'''

"""
{16: 'rax', 24: 'rcx', 32: 'rdx', 40: 'rbx',, 64: 'rsi',
 72: 'rdi', 80: 'r8', 88: 'r9', 96: 'r10', 104: 'r11', 112: 'r12', 120: 'r13', 128: 'r14', 136: 'r15'}
    this registers maybe used to decide branch
"""

target=[16,24,32,40,64,72,80,88,96,104,112,120,128,136]

vectors=[]

over_addrs=[]

over_regs=[]

def sym_mem(state:angr.SimState):
    global over_addrs
    addr = state.solver.eval(state.inspect.mem_read_address)
    length = state.solver.eval(state.inspect.mem_read_length)
    if addr in over_addrs:
        return
    bvv=state.memory.load(addr,length,endness=Endness.LE,disable_actions=True,inspect=False)
    if not bvv.symbolic:
        bvs=claripy.BVS('bvs',8*length)
        vectors.append((('mem',addr),bvs))
        state.memory.store(addr,bvs,endness=Endness.LE,disable_actions=True,inspect=False)
    else:
        pass
    return

def sym_reg(state:angr.SimState):
    global over_regs
    global target
    code = state.solver.eval(state.inspect.reg_read_offset)
    if code in over_regs or code not in target:
        return
    #print(type(state.inspect.reg_read_offset)) #test for its type BV type
    reg_value = state.registers.load(code, 8, endness=Endness.LE, disable_actions=True, inspect=False)
    if not reg_value.symbolic:
        bvs = claripy.BVS('bvs', 64)
        vectors.append((('reg',code),bvs))
        state.registers.store(code, bvs, endness=Endness.LE, disable_actions=True, inspect=False)
    else:
        pass
    return

def sol_mem(state:angr.SimState):
    global over_addrs
    addr = state.solver.eval(state.inspect.mem_write_address)
    if addr in over_addrs:
        pass
    else:
        over_addrs.append(addr)
    return

def sol_reg(state:angr.SimState):
    global over_regs
    code = state.solver.eval(state.inspect.reg_write_offset)
    if code in over_regs or code not in target:
        pass
    else:
        over_regs.append(code)
    return

mem_read_bp=state.inspect.b("mem_read",when=angr.BP_BEFORE,action=sym_mem)

reg_read_bp=state.inspect.b("reg_read",when=angr.BP_BEFORE,action=sym_reg)

mem_write_bp=state.inspect.b("mem_write",when=angr.BP_BEFORE,action=sol_mem)

reg_write_bp=state.inspect.b("reg_write",when=angr.BP_BEFORE,action=sol_reg)

solutions=[]

f=open(new_path,'w')

rank:int=0

is_modify=1

output=''

for path in paths:
    over_addrs.clear()
    over_regs.clear()
    vectors.clear()
    solution=[]
    simgr=proj.factory.simgr(state.copy())
    for addr in path[1:]:
        if not simgr.active:
            break
        cur_st=simgr.active[0]
        bk=proj.factory.block(addr=cur_st.addr)
        steps=len(bk.instruction_addrs)
        for _ in range(steps):
            simgr.step(num_inst=1)
        simgr.move('active','deadended',lambda s:s.addr!=addr)
    if simgr.active:
        is_modify=0
        rank+=1
        output+=f'Solution{rank}#\n'
        final=simgr.active[0]
        '''
        analyze constraints,get all symbolic variables
        '''
        for ele in vectors:
            if ele[0][0]=='reg':
                code:int=ele[0][1]
                reg=regs[code]
                vector=ele[1]
                if not comp('reg',reg,vector,final.copy()):
                    ans = final.solver.eval(vector)
                    output+=f'{reg}: {hex(ans)} \n'
                    solution.append((reg,hex(ans)))
                    is_modify=1
            if ele[0][0]=='mem':
                addr=ele[0][1]
                vector=ele[1]
                size=vector.size()
                if not comp('mem',addr, vector, final.copy()):
                    length=int(size/8)
                    ans=final.solver.eval(vector)
                    output+=f'{hex(addr)} ({length}) :{hex(ans)}\n'
                    solution.append((hex(addr),length,ans))
                    is_modify=1
        solutions.append(solution)
    if not is_modify:
        output='No modifications required'
        break
if not output:
    output='No satisfiable modification have been found'
f.write(output)
f.close()
'''
print('solutions:',solutions)
'''



