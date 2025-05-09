import angr
import claripy
import logging
from angr.project import Project
from angr.sim_state import SimState

l = logging.getLogger(__name__)

def allocate_memory(procedure: str, state: SimState, sim_size: claripy.ast.bv.BV) -> claripy.ast.bv.BV:
    """
    Allocate memory and save the returned pointer and allocated memory size.
    """
    call_site_addr = state.callstack.call_site_addr
    ptr = state.solver.BVV(state.heap._malloc(sim_size), state.project.arch.bits)
    state.locals.memory_info[ptr] = {'size': sim_size, 'malloc_site': call_site_addr, 'free_site': None}
    l.info(f'{state}: Called {procedure} @ {hex(call_site_addr)} with size: {sim_size}. Returns pointer: {ptr}')
    return ptr 

def release_memory(procedure: str, state: SimState, ptr: claripy.ast.bv.BV) -> None:
    """
    Save the call site address for the freed pointer.
    """
    call_site_addr = state.callstack.call_site_addr
    if call_site_addr == 0:
        return
    if ptr in state.locals.memory_info.keys():
        state.locals.memory_info[ptr]['free_site'] = call_site_addr
    else:
        bits = state.project.arch.bits
        state.locals.memory_info[ptr] = {'size': state.solver.BVS('size', bits), 'malloc_site': state.solver.BVS('malloc_site', bits), 'free_site': call_site_addr}
    l.info(f'{state}: Called {procedure} @ {hex(call_site_addr)} with ptr: {ptr}')

class MallocHook(angr.SimProcedure):
    """
    An angr SimProcedure to hook malloc calls.
    """
    def run(self, sim_size: claripy.ast.bv.BV) -> claripy.ast.bv.BV:
        return allocate_memory('malloc', self.state, sim_size)

class FreeHook(angr.SimProcedure):
    """
    An angr SimProcedure to hook free calls.
    """
    def run(self, ptr: claripy.ast.bv.BV) -> None:
        release_memory('free', self.state, ptr)

class NewHook(angr.SimProcedure):
    """
    An angr SimProcedure to hook operator.new calls.
    """
    def run(self, sim_size: claripy.ast.bv.BV) -> claripy.ast.bv.BV:
        return allocate_memory('operator.new', self.state, sim_size)

class DeleteHook(angr.SimProcedure):
    """
    An angr SimProcedure to hook operator.delete calls.
    """
    def run(self, ptr: claripy.ast.bv.BV) -> None:
        release_memory('operator.delete', self.state, ptr)

class NewArrayHook(angr.SimProcedure):
    """
    An angr SimProcedure to hook operator.new[] calls.
    """
    def run(self, sim_size: claripy.ast.bv.BV) -> claripy.ast.bv.BV:
        return allocate_memory('operator.new[]', self.state, sim_size)

class DeleteArrayHook(angr.SimProcedure):
    """
    An angr SimProcedure to hook operator.delete[] calls.
    """
    def run(self, ptr: claripy.ast.bv.BV) -> None:
        release_memory('operator.delete[]', self.state, ptr)

class ReallocHook(angr.SimProcedure):
    """
    An angr SimProcedure to hook realloc calls.
    """
    def run(self, ptr: claripy.ast.bv.BV, size: claripy.ast.bv.BV) -> claripy.ast.bv.BV:
        call_site_addr = self.state.callstack.call_site_addr
        new_ptr = self.state.solver.BVV(self.state.heap._realloc(ptr, size), self.project.arch.bits)
        self.state.locals.memory_info[new_ptr] = {'size': size, 'malloc_site': call_site_addr, 'free_site': None}
        l.info(f'Called realloc @ {hex(call_site_addr)} with size: {size}. Returns pointer: {new_ptr}')
        release_memory('free', self.state, ptr)
        return new_ptr 

class CallocHook(angr.SimProcedure):
    """
    An angr SimProcedure to hook calloc calls.
    """
    def run(self, sim_nmemb: claripy.ast.bv.BV, sim_size: claripy.ast.bv.BV) -> claripy.ast.bv.BV:
        call_site_addr = self.state.callstack.call_site_addr
        ptr = self.state.solver.BVV(self.state.heap._calloc(sim_nmemb, sim_size), self.project.arch.bits)
        self.state.locals.memory_info[ptr] = {'size': sim_size, 'malloc_site': call_site_addr, 'free_site': None}
        l.info(f'Called calloc @ {hex(call_site_addr)} with nmemb: {sim_nmemb} & size: {sim_size}. Returns pointer: {ptr}')
        return ptr 

class ReallocarrayHook(angr.SimProcedure):
    """
    An angr SimProcedure to hook reallocarray calls.
    """
    def run(self, ptr: claripy.ast.bv.BV, sim_nmemb: claripy.ast.bv.BV, size: claripy.ast.bv.BV) ->  claripy.ast.bv.BV:
        call_site_addr = self.state.callstack.call_site_addr
        if size.symbolic:
            try:
                size_int = self.state.solver.max(size, extra_constraints=(size < self.state.libc.max_variable_size,))
            except SimSolverError:
                size_int = self.state.solver.min(size)
            self.state.add_constraints(size_int == size)
        else:
            size_int = self.state.solver.eval(size)

        new_ptr = self.state.solver.BVV(self.state.heap._calloc(sim_nmemb, size_int), self.project.arch.bits)

        if self.state.solver.eval(ptr) != 0:
            v = self.state.memory.load(ptr, size_int)
            self.state.memory.store(new_ptr, v)
        self.state.locals.memory_info[new_ptr] = {'size': size_int, 'malloc_site': call_site_addr, 'free_site': None}
        l.info(f'Called reallocarray @ {hex(call_site_addr)} with nmemb: {sim_nmemb} & size: {size_int}. Returns pointer: {new_ptr}')
        release_memory('free', self.state, ptr)
        return new_ptr 
