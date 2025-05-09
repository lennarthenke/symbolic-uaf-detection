import angr
import claripy
import logging
from angr.sim_state import SimState
from angr.sim_manager import SimulationManager
from procedures.dynamic_memory import MallocHook, FreeHook, NewHook, DeleteHook, NewArrayHook, DeleteArrayHook, ReallocHook, CallocHook, ReallocarrayHook

l = logging.getLogger(__name__)

class UseAfterFreeCheck(angr.Analysis):
    """
    An angr analysis class that performs Use-After-Free detection in a binary.

    This class hooks dynamic memory functions, sets breakpoints at memory read/write
    operations, and runs the simulation manager to identify possible Use-After-Free
    states.
    """
    def __init__(self, start_state: SimState, simulation_manager: SimulationManager) -> None:
        self.start_state = start_state
        self.simulation_manager = simulation_manager
        # Define the custom initial heap size (1 MB)
        initial_heap_size = 1 * 1024 * 1024
        self.start_state.heap.heap_size = initial_heap_size
        self.uaf_states = self.uaf_analysis()

    def hook_dynamic_memory_functions(self) -> None:
        """
        Hook the dynamic memory functions in the binary with their respective custom hooks.
        """
        hooks = {
            'malloc': MallocHook(),
            'free': FreeHook(),
            '_Znwm': NewHook(),
            '_ZdlPvm': DeleteHook(),
            '_Znam': NewArrayHook(),
            '_ZdaPv': DeleteArrayHook(),
            'realloc': ReallocHook(),
            'calloc': CallocHook(),
            'reallocarray': ReallocarrayHook(),
        }

        for func_name, hook in hooks.items():
            self.project.hook_symbol(func_name, hook, replace=True)

    def use_after_free_check(self, state: SimState, use_addr: claripy.ast.bv.BV) -> None:
        """
        Check if the used address is an Use After Free and if so save a copy of the state.
        """
        # Iterate over memory_info items
        for free_addr, mem_info in state.locals.memory_info.items():
            if mem_info['free_site'] is not None:
                # Create constraint based on the address range
                in_range = (
                    claripy.And(
                        free_addr <= use_addr,
                        use_addr < free_addr + mem_info['size']
                    )
                )

                # Constrain allocation size if symbolic
                if state.solver.symbolic(mem_info['size']):
                    state.solver.add(mem_info['size'] >= 1)
                    state.solver.add(mem_info['size'] <= state.libc.max_variable_size)

                # Constrain use_addr if symbolic and not uninitialized
                if state.solver.symbolic(use_addr) and not use_addr.uninitialized:
                    heap_base = state.heap.heap_base
                    heap_end = heap_base + state.heap.heap_size
                    state.solver.add(use_addr >= heap_base)
                    state.solver.add(use_addr <= heap_end)

                # Check for Use-After-Free condition
                if state.solver.symbolic(use_addr) and use_addr.uninitialized or state.solver.symbolic(free_addr) and free_addr.uninitialized:
                    use_after_free = state.solver.is_true(use_addr == free_addr)
                else:
                    use_after_free = state.solver.satisfiable(extra_constraints=[in_range])

                # Log and save the state if Use-After-Free is detected
                if use_after_free is True:
                    l.info(f'Possible Use-After-Free detected @ {use_addr} in {state}')
                    l.info(f'allocation site: {mem_info["malloc_site"]} free site: {mem_info["free_site"]}')
                    state.globals['free_ptr'] = free_addr
                    mem_info['uaf_ptr'] = use_addr
                    self.simulation_manager.stashes['uaf_states'].append(state.copy())

    def read_freed_addr_check(self, state: SimState) -> None:
        """
        Check the address at which memory is being read for an Use After Free.
        """
        read_addr = state.inspect.mem_read_address
        self.use_after_free_check(state, read_addr)
  
    def write_freed_addr_check(self, state: SimState) -> None:
        """
        Check the address at which memory is being written for an Use After Free.
        """
        write_addr = state.inspect.mem_write_address
        self.use_after_free_check(state, write_addr)

    def set_breakpoints(self) -> None:
        """
        Set breakpoints at every memory read/write and check for an Use-After-Free.
        """
        self.start_state.inspect.b('mem_read', action=self.read_freed_addr_check)
        self.start_state.inspect.b('mem_write', action=self.write_freed_addr_check)

    def custom_callless(self, state: SimState) -> None:
        """
        Bypasses function calls for non dynamic-memory functions by directly setting the return address and updating the stack pointer.
        """
        func = state.project.kb.functions.get_by_addr(state.addr)
        if func.name not in ['malloc', 'free', '_Znwm', '_ZdlPvm', '_Znam', '_ZdaPv', 'realloc', 'calloc', 'reallocarray']:
            state.registers.store(state.arch.ret_offset, state.solver.Unconstrained('fake_ret_value', state.arch.bits))
            state.history.jumpkind = 'Ijk_Ret'
            state.regs.ip = state.solver.BVV(state.callstack.ret_addr, state.project.arch.bits)
            if state.arch.call_pushes_ret:
                state.regs.sp = state.regs.sp + state.arch.bytes

    def uaf_analysis(self) -> list[SimState]:
        """
        Perform use-after-free (UAF) analysis on the project by hooking dynamic memory functions,
        setting breakpoints at memory read/write operations, and running the simulation manager.
        """
        self.hook_dynamic_memory_functions()
        self.set_breakpoints()
        if 'CUSTOM_CALLLESS' in self.start_state.globals:
            self.start_state.inspect.b('call', when=angr.BP_AFTER, action=self.custom_callless)
        try:
            # step until everything terminates
            self.simulation_manager.run()
        except Exception as e:
            l.error(f'Error during UAF analysis: {e}')
        if len(self.simulation_manager.errored) > 0:
            l.debug(f'Errored states: {self.simulation_manager.errored}')
        return self.simulation_manager.stashes['uaf_states']
