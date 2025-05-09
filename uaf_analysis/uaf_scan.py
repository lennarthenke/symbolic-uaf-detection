#!/usr/bin/env python3

import sys
import json
import angr
import claripy
import logging
import argparse
import tracemalloc
from pathlib import Path
from angr.project import Project
from angr.sim_state import SimState
from procedures.fgets import FgetsHook 
from procedures.getenv import GetenvHook
from typing import Set, Optional, Union
from analyses.pre_director import PreDirector
from angr.sim_manager import SimulationManager
from angr.analyses.cfg.cfg_fast import CFGFast
from state_plugins.locals import SimStateLocals
from exploration_techniques.auto_drop import AutoDrop
from exploration_techniques.new_director import NewDirector
from analyses.use_after_free_check import UseAfterFreeCheck
from exploration_techniques.memory_watcher import MemoryWatcher
from exploration_techniques.length_limiter import LengthLimiter 
from angr.exploration_techniques import DFS, LoopSeer, Veritesting, Timeout

# Max memory usage in GB
MAX_MEMORY_USAGE = 12
# Timeout in seconds
TIMEOUT = 10800 
MAX_PATH_LENGTH = 3000
GHIDRA_TO_ANGR_OFFSET = 0x300000
FREE_FUNCTIONS = ['free', 'realloc', 'reallocarray', '_ZdlPvm', '_ZdaPv']

def get_args() -> argparse.Namespace:
    """
    Set up argument parser and add arguments
    """
    parser = argparse.ArgumentParser(
        prog = 'uaf_scan',
        description = 'Script for finding Use-After-Free vulnerabilities using Symbolic Execution with angr.'
    )
    parser.add_argument('binary', metavar='binary_path', type=str, help='path to the binary executable')
    parser.add_argument('-v', '--verbose', help='increase verbosity', action='count', default=0)
    parser.add_argument('-d', '--dfs', help='use depth first search (DFS) instead of breadth first search (BFS)', action='store_true')
    parser.add_argument('-l', '--loopSeer', help='bound symbolic loops', action='store_true')
    parser.add_argument('-t', '--veritesting', help='use veritesting', action='store_true')
    parser.add_argument('-u', '--ucse', metavar='func_addrs', type=str,  nargs='*', help='use under-constrained symbolic execution (UCSE). Optionally define function addresses to run (Default run all functions)')
    parser.add_argument('-g', '--goals', metavar='goal_addrs', type=str, nargs='+', help='specify UAF goal addresses to use directed symbolic execution')
    parser.add_argument('-e', '--export', help='export all vulnerability paths as a json file', action='store_true')
    return parser.parse_args()

def _set_detailed_logging(loggers: list[str]) -> None:
    """
    Set detailed logging for the specified loggers.
    """
    for logger in loggers:
        logging.getLogger(logger).setLevel(logging.DEBUG)

def set_verbosity(verbosity: int) -> None:
    """
    Set the verbosity level for logging.

    If verbosity is 0, disable all logging. If verbosity is 1 or greater,
    enable detailed logging for specific loggers. If verbosity is greater
    than 1, enable detailed logging for all 'angr' loggers.
    """
    log_config = {
        0: lambda: logging.disable(logging.CRITICAL),
        1: lambda: _set_detailed_logging(['angr.sim_manager', 'angr.analyses.cfg', 'angr.exploration_techniques.timeout','analyses', 'procedures', 'exploration_techniques']),
        2: lambda: _set_detailed_logging(['angr', 'analyses', 'procedures', 'exploration_techniques']),
    }
    log_action = log_config.get(verbosity, log_config[2])
    log_action()

def register_defaults() -> None:
    """
    Register the UAF analysis with angr's global analysis list
    and the state plugin as a default.
    """
    angr.AnalysesHub.register_default('UseAfterFreeCheck', UseAfterFreeCheck)
    angr.AnalysesHub.register_default('PreDirector', PreDirector)
    SimStateLocals.register_default('locals')

def convert_addr(addr: str, base: int) -> int:
    """
    Convert a string hex address into an int address.

    This function takes into account differences between Ghidra and angr addresses for 
    position-independent executables (PIEs). Ghidra uses 0x100000 as the base address, 
    while angr uses 0x400000.
    """
    addr = int(addr, 16)
    if base == 0x400000 and addr < 0x400000:
        addr += GHIDRA_TO_ANGR_OFFSET
    return addr

def get_func_name(cfg: CFGFast, addr: int) -> Optional[str]:
    """
    Get the name of the function at the given address.
    """
    func = cfg.kb.functions.get(addr)
    return func.name if func is not None else None

def get_state_options() -> Set[str]:
    """
    Returns a set of angr state options.
    """
    base_options = {
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        angr.options.TRACK_MEMORY_ACTIONS,
    }

    all_options = base_options.union(angr.options.resilience)
    return all_options

def get_reaching_nodes(start_state: SimState, cfg: CFGFast, goal_addrs: list[int]) -> list[tuple[int, int]]:
    """
    Get reaching nodes for a given start state and control flow graph.
    """
    print(f'[+] Running PreDirector analysis...')
    pre_director = start_state.project.analyses.PreDirector(start_state, cfg, MAX_PATH_LENGTH, goal_addrs)
    reaching_nodes = pre_director.get_free_cwe_nodes()
    print(f'[+] PreDirector analysis ended. Found {len(reaching_nodes)} reaching nodes.')
    return reaching_nodes

def set_exploration_techniques(simulation_manager: SimulationManager, cfg: CFGFast, args: argparse.Namespace()) -> None:
    """
    Set the exploration techniques for the SimulationManager.
    """
    simulation_manager.use_technique(Timeout(TIMEOUT))
    simulation_manager.use_technique(LengthLimiter(MAX_PATH_LENGTH))
    simulation_manager.use_technique(MemoryWatcher(max_mem=MAX_MEMORY_USAGE))
    simulation_manager.use_technique(AutoDrop(['deadended', 'unconstrained', 'spinning', 'deprioritized', 'out_of_memory']))
    if args.dfs is True:
        simulation_manager.use_technique(DFS())
    if args.loopSeer is True:
        simulation_manager.use_technique(LoopSeer(cfg=cfg, bound=1, limit_concrete_loops=False))
    if args.veritesting is True:
        simulation_manager.use_technique(Veritesting())

def get_simulation_manager(start_state: SimState, cfg: CFGFast, args: argparse.Namespace, goal_addrs: list[int]) -> SimulationManager:
    """
    Initialize a SimulationManager with the given start state, control flow graph, arguments, and goal addresses.
    """
    simulation_manager = start_state.project.factory.simulation_manager(start_state)
    if len(goal_addrs) > 0:
        reaching_nodes = get_reaching_nodes(start_state, cfg, goal_addrs)
        simulation_manager.use_technique(NewDirector(reaching_nodes))
    set_exploration_techniques(simulation_manager, cfg, args)
    return simulation_manager

def print_simulation_results(simulation_manager: SimulationManager, description: str) -> None:
    """
    Print the results of a simulation with a given description.
    
    This function extracts the dropped paths and maximum number of paths from the
    simulation manager, and prints them along with the provided description.
    """
    dropped = {key: val for key, val in simulation_manager.dropped.items() if val > 0}
    print(f'[+] {description} ended. Paths dropped: {dropped}')
    print(f'[+] Max number of paths: {simulation_manager.stashes["max_number_paths"][0]}')

def run_ucse_on_address(project: Project, cfg: CFGFast, args: argparse.Namespace, addr: int, goal_addrs: list[int], callless: bool) -> list[SimState]:
    """
    Run Under-Constrained Symbolic Execution (UCSE) on a single address and return the UAF states.
    """
    func_name = get_func_name(cfg, addr)
    options = get_state_options()
    options.add(angr.options.UNDER_CONSTRAINED_SYMEXEC)
    start_state = project.factory.call_state(addr, add_options=options)
    if callless is True:
        start_state.globals['CUSTOM_CALLLESS'] = True
    simulation_manager = get_simulation_manager(start_state, cfg, args, goal_addrs)
    print(f'[+] Running UCSE on {func_name}')
    uaf_states = project.analyses.UseAfterFreeCheck(start_state, simulation_manager).uaf_states
    print_simulation_results(simulation_manager, f'UCSE on {func_name}')
    return uaf_states 

def run_ucse(project: Project, cfg: CFGFast, args: argparse.Namespace, ucse_addrs: list[int], goal_addrs: list[int]) -> list[SimState]:
    """
    Run Under-Constrained Symbolic Execution (UCSE) on the given addresses and return the UAF states.
    If no addresses are provided, run UCSE on all non-simprocedure, non-plt, and non-syscall functions.
    """
    uaf_states = []
    if len(ucse_addrs) == 0:
        for addr, func in cfg.kb.functions.items():
            if not func.is_simprocedure and not func.is_plt and not func.is_syscall:
                uaf_states.extend(run_ucse_on_address(project, cfg, args, addr, goal_addrs, callless=True))
    else:
        for addr in ucse_addrs:
            uaf_states.extend(run_ucse_on_address(project, cfg, args, addr, goal_addrs, callless=False))

    return uaf_states

def select_unique_address_states(states: list[SimState]) -> list[SimState]:
    """
    Select unique address states with the lowest depth from a list of SimState objects.
    """
    unique_address_states = {}
    for state in states:
        # Extract the address and depth of the current state
        address = state.addr
        depth = state.history.depth

        # Check if the address is in the dictionary
        if address not in unique_address_states:
            unique_address_states[address] = state
        else:
            # Compare the depth of the current state with the stored state
            stored_state = unique_address_states[address]
            if depth < stored_state.history.depth:
                unique_address_states[address] = state
    return list(unique_address_states.values())

def print_address(label: str, address: Union[int, claripy.ast.bv.BV]) -> None:
    """
    Prints the given label and address in the desired format.
    """
    if isinstance(address, int):
        print(f'{label:20} @ {hex(address)}')
    else:
        print(f'{label:20} @ {address}')

def get_path_of_state(cfg: CFGFast, state: SimState) -> list[int]:
    """
    Get the path of a given stat
    """
    lineage = state.history.lineage
    addrs = [parent.addr for parent in lineage if parent.addr is not None]
    addrs.append(state.addr)
    return addrs

def print_path_of_state(cfg: CFGFast, state: SimState) -> None:
    """
    Print the path of a given state.
    """
    addrs = get_path_of_state(cfg, state)

    for idx, addr in enumerate(addrs, start=1):
        func_addr = cfg.get_any_node(addr, anyaddr=True).function_address
        func_name = get_func_name(cfg, func_addr)

        if func_name is not None:
            print(f'\t{idx:3}: {hex(addr):8} - {func_name}')
        else:
            print(f'\t{idx:3}: {hex(addr):8}')

def output_state(cfg: CFGFast, state: SimState, args: argparse.Namespace):
    """
    Output a possible Use-After-Free state.
    """
    func_addr = cfg.get_any_node(state.addr, anyaddr=True).function_address
    func_name = get_func_name(cfg, func_addr)
    callstack_names = [get_func_name(cfg, call.func_addr) for call in state.callstack if call.func_addr > 0][::-1]
    print(f'[+] Use-After-Free: {state} in {func_name} may access a dangling pointer')
    if args.ucse is None:
        print('    Call stack: ', end='')
        print(*callstack_names, sep=' -> ')
    if args.verbose >= 1:
        free_ptr = state.globals['free_ptr']
        mem_info = state.locals.memory_info[free_ptr]
        uaf_ptr = mem_info['uaf_ptr']
        print_address('    Allocation-site:', mem_info['malloc_site'])
        print_address('    Free-site:', mem_info['free_site'])
        print_address('    Use-site:', state.addr)
        print_address('    Free-ptr:', free_ptr)
        print_address('    Use-ptr:', uaf_ptr)
        print(f'    {"Size:":18} {mem_info["size"]}')
        stdin = state.posix.dumps(0).decode('utf-8', 'backslashreplace')
        if stdin != '':
            print(f'    Stdin: {stdin}')
        if not args.veritesting:
            print(f'    Registers:')
            state.solver.timeout = 1
            for reg in state.arch.register_list:
                if reg.general_purpose is True:
                    register_number, size = state.arch.registers[reg.name]
                    register_value = str(state.registers.load(
                        register_number, inspect=False, disable_actions=True, size=size
                    ))
                    if len(register_value) > 50:
                        register_value = register_value[:50] + '...'
                    print(f'\t{reg.name:3}: {register_value}')
        print(f'    Path:')
        print_path_of_state(cfg, state)

def export_paths(cfg: CFGFast, states: list[SimState]) -> dict[int, int]:
    """
    Export the paths of the given states.
    """
    paths = {}
    for idx, state in enumerate(states, start=1):
        get_path_of_state(cfg, state)
        base = state.project.loader.main_object.min_addr
        addrs = [addr - GHIDRA_TO_ANGR_OFFSET  if base == 0x400000  else addr for addr in get_path_of_state(cfg, state)]
        paths[idx] = addrs
    return paths

def main() -> int:
    """
    Analyze a binary file for use-after-free vulnerabilities.
    
    This function performs the following steps:
    1. Get command-line arguments and set verbosity.
    2. Register default angr settings.
    3. Load the binary using angr and create a project.
    4. Check if the binary contains any specified free functions.
    5. Run CFGFast analysis on the binary.
    6. Run Use-After-Free analysis.
    7. Output the results of the analysis.
    """
    args = get_args()
    set_verbosity(args.verbose)
    register_defaults()
    binary = Path(args.binary)

    if not binary.exists():
        sys.stderr.write(f'Error: {binary} does not exist\n')
        sys.exit(-1)

    project = angr.Project(binary, auto_load_libs=False)
    project.analyses.CompleteCallingConventions(recover_variables=True, force=True, analyze_callsites=True)

    # Hooking modified SimProcedures.
    project.hook_symbol('fgets', FgetsHook(), replace=True)
    project.hook_symbol('getenv', GetenvHook(), replace=True)

    goal_addrs = [convert_addr(addr, project.loader.main_object.min_addr) for addr in args.goals] if args.goals is not None else []
    symbols = [symbol.name for symbol in project.loader.symbols]

    # Check if the binary contains any of the specified free functions
    if not any(func in symbols for func in FREE_FUNCTIONS):
        print(f'[+] {binary.name} does not contain any free functions.')
        return 0

    print(f'[+] Running CFGFast analysis...')
    cfg = project.analyses.CFGFast(indirect_calls_always_return=False, jumptable_resolver_resolves_calls=True, show_progressbar=True)
    print(f'[+] CFGFast analysis ended. Created a {cfg.graph}')

    if args.ucse is not None:
        if args.veritesting is True:
            sys.stderr.write('Error: Under-Constrained Symbolic Execution and Veritesting cannot be used at the same time.\n')
            sys.exit(-1)
        ucse_addrs = [convert_addr(addr, project.loader.main_object.min_addr) for addr in args.ucse]
        uaf_states = run_ucse(project, cfg, args, ucse_addrs, goal_addrs)
    else:
        start_state = project.factory.blank_state(addr=project.entry, add_options=get_state_options())
        simulation_manager = get_simulation_manager(start_state, cfg, args, goal_addrs)
        print(f'[+] Running Use-After-Free analysis...')
        uaf_states = project.analyses.UseAfterFreeCheck(start_state, simulation_manager).uaf_states
        print_simulation_results(simulation_manager, 'Use-After-Free analysis')

    unique_address_states = select_unique_address_states(uaf_states) 
    for state in unique_address_states:
        output_state(cfg, state, args)

    if args.export and len(unique_address_states) > 0:
        print(f'[+] Exporting UAF paths of {binary.name}...')
        with open(f'{binary.name}.json', 'w') as fp:
            json.dump(export_paths(cfg, unique_address_states), fp)

    if len(uaf_states) == 0:
        print('[+] Found no Use-After-Free')

    return 0

if __name__ == '__main__':
    sys.exit(main())
