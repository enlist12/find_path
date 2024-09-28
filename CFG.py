import idautils
import idaapi
import angr
import idangr
import angrdbg
import idc
import os
import claripy
import archinfo

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
automatically get start address and end address
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
    if type=='reg':
        cur=idc.get_reg_value(pos)
        state.solver.add(vector==cur)
        if state.satisfiable():
            return True
    if type=='mem':
        size=vector.size()
        length=int(size/8)
        for j in range(length):
            num=idc.get_wide_byte(pos+j)
            vec=state.memory.load(pos+j,1)
            state.solver.add(vec==num)
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

print('paths:',paths)

if not idangr.is_initialized():
    idangr.init()

proj=angrdbg.reload_project()

state=proj.factory.blank_state(addr=start)
#state=angrdbg.StateShot()
'''
    specify the rsp and rbp
'''
rbp=idc.get_reg_value('rbp')
rsp=idc.get_reg_value('rsp')
state.regs.rsp=rsp
state.regs.rbp=rbp

'''
    used for debug
'''
solutions=[]

f=open(new_path,'a')

rank:int=1

for path in paths:
    solution=[]
    simgr=proj.factory.simgr(state)
    for addr in path[1:]:
        if not simgr.active:
            break
        simgr.step()
        simgr.move('active','deadended',lambda s:s.addr!=addr)
    if simgr.active:
        f.write(f'Solution{rank}#\n')
        final=simgr.active[0]
        '''
        analyze constraints,get all symbolic variables
        '''
        symbolic=list(final.solver.get_variables())
        print(symbolic)
        regs=proj.arch.register_names
        for ele in symbolic:
            if ele[0][0]=='reg':
                code:int=ele[0][1]
                reg=regs[code]
                vector=ele[1]
                if not comp('reg',reg,vector,final.copy()):
                    ans = final.solver.eval(vector)
                    f.write(f'{reg}: {hex(ans)} \n')
                    solution.append((reg,hex(ans)))
            if ele[0][0]=='mem':
                addr=ele[0][1]
                vector=ele[1]
                size=vector.size()
                if not comp('mem',addr, vector, final.copy()):
                    length=int(size/8)
                    ans=[]
                    str='{'
                    for j in range(length):
                        vec=final.memory.load(addr+j,1)
                        byte=final.solver.eval(vec)
                        str+=f' {hex(byte)},'
                        ans.append(byte)
                    str = str[:-1]
                    str+=' }'
                    f.write(f'{hex(addr)} ({length}) :{str}\n')
                    solution.append((hex(addr),length,ans))
        solutions.append(solution)
f.close()
print(solutions)




