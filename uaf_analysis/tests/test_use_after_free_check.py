import angr
from pathlib import Path
from analyses.pre_director import PreDirector
from state_plugins.locals import SimStateLocals
from analyses.use_after_free_check import UseAfterFreeCheck
from exploration_techniques.new_director import NewDirector

TEST_DIR = Path(__file__).parent / 'data'

class BinaryForTesting:
    def __init__(self, path: Path, uaf_addrs: list[int]) -> None:
        self.path = path
        self.uaf_addrs = uaf_addrs

class TestUseAfterFreeCheck:
    angr.AnalysesHub.register_default('UseAfterFreeCheck', UseAfterFreeCheck)
    angr.AnalysesHub.register_default('PreDirector', PreDirector)
    SimStateLocals.register_default('locals')
    options = {
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    }
    options = options.union(angr.options.resilience)
    no_uaf_binary = BinaryForTesting(TEST_DIR / 'no_uaf', [])
    simple_malloc_uaf_binary = BinaryForTesting(TEST_DIR / 'simple_malloc_uaf', [0x401189])
    simple_new_uaf_binary = BinaryForTesting(TEST_DIR / 'simple_new_uaf', [0x4011ef])
    simple_new_array_uaf_binary = BinaryForTesting(TEST_DIR / 'simple_new_array_uaf', [0x401311])
    simple_realloc_uaf_binary = BinaryForTesting(TEST_DIR / 'simple_realloc_uaf', [0x401192])
    simple_calloc_uaf_binary = BinaryForTesting(TEST_DIR / 'simple_calloc_uaf', [0x401184, 0x40118e])
    simple_reallocarray_uaf_binary = BinaryForTesting(TEST_DIR / 'simple_reallocarray_uaf', [0x401189, 0x401193])
    loop_uaf_binary = BinaryForTesting(TEST_DIR / 'loop_uaf', [0x40119b])
    func_uaf_binary = BinaryForTesting(TEST_DIR / 'func_uaf', [0x4011c7])
    scanf_uaf_binary = BinaryForTesting(TEST_DIR / 'scanf_uaf', [0x500028])
    strlen_uaf_binary = BinaryForTesting(TEST_DIR / 'strlen_uaf', [0x4012a5])
    fgets_uaf_binary = BinaryForTesting(TEST_DIR / 'fgets_uaf', [0x401238])
    getenv_uaf_binary = BinaryForTesting(TEST_DIR / 'getenv_uaf', [0x500020])
    vulnerable_path_binary = BinaryForTesting(TEST_DIR / 'vulnerable_path', [0x401201])

    def run_uaf_check(self, binary: Path, goal_addrs: list[int]) -> list[int]:
        project = angr.Project(binary, auto_load_libs=False)
        cfg = project.analyses.CFGFast(force_smart_scan=False, force_complete_scan=True)
        max_path_length = 3000
        start_state = project.factory.blank_state(addr=project.entry, add_options=self.options)
        simulation_manager = project.factory.simulation_manager(start_state)
        if len(goal_addrs) > 0:
            pre_director = start_state.project.analyses.PreDirector(start_state, cfg, max_path_length, goal_addrs)
            reaching_nodes = pre_director.get_free_cwe_nodes()
            simulation_manager.use_technique(NewDirector(reaching_nodes))
        uaf_states = project.analyses.UseAfterFreeCheck(start_state, simulation_manager).uaf_states
        uaf_state_addrs = []
        for state in uaf_states:
            if state.addr not in uaf_state_addrs:
                uaf_state_addrs.append(state.addr)
        return uaf_state_addrs

    def test_uaf_check(self) -> None:
        uaf_state_addrs = self.run_uaf_check(self.no_uaf_binary.path, [])
        assert uaf_state_addrs == self.no_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.simple_malloc_uaf_binary.path, [])
        assert uaf_state_addrs == self.simple_malloc_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.simple_new_uaf_binary.path, [])
        assert uaf_state_addrs == self.simple_new_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.simple_new_array_uaf_binary.path, [])
        assert uaf_state_addrs == self.simple_new_array_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.simple_realloc_uaf_binary.path, [])
        assert uaf_state_addrs == self.simple_realloc_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.simple_calloc_uaf_binary.path, [])
        assert uaf_state_addrs == self.simple_calloc_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.simple_reallocarray_uaf_binary.path, [])
        assert uaf_state_addrs == self.simple_reallocarray_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.loop_uaf_binary.path, [])
        assert uaf_state_addrs == self.loop_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.func_uaf_binary.path, [])
        assert uaf_state_addrs == self.func_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.scanf_uaf_binary.path, [])
        assert uaf_state_addrs == self.scanf_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.strlen_uaf_binary.path, [])
        assert uaf_state_addrs == self.strlen_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.fgets_uaf_binary.path, [])
        assert uaf_state_addrs == self.fgets_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.getenv_uaf_binary.path, [])
        assert uaf_state_addrs == self.getenv_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.vulnerable_path_binary.path, [])
        assert uaf_state_addrs == self.vulnerable_path_binary.uaf_addrs

    def test_uaf_check_with_director(self) -> None:
        uaf_state_addrs = self.run_uaf_check(self.no_uaf_binary.path, self.no_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.no_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.simple_malloc_uaf_binary.path, self.simple_malloc_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.simple_malloc_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.simple_new_uaf_binary.path, self.simple_new_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.simple_new_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.simple_new_array_uaf_binary.path, self.simple_new_array_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.simple_new_array_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.simple_realloc_uaf_binary.path, self.simple_realloc_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.simple_realloc_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.simple_calloc_uaf_binary.path, self.simple_calloc_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.simple_calloc_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.simple_reallocarray_uaf_binary.path, self.simple_reallocarray_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.simple_reallocarray_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.loop_uaf_binary.path, self.loop_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.loop_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.func_uaf_binary.path, self.func_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.func_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.scanf_uaf_binary.path, self.scanf_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.scanf_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.strlen_uaf_binary.path, self.strlen_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.strlen_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.fgets_uaf_binary.path, self.fgets_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.fgets_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.getenv_uaf_binary.path, self.getenv_uaf_binary.uaf_addrs)
        assert uaf_state_addrs == self.getenv_uaf_binary.uaf_addrs
        uaf_state_addrs = self.run_uaf_check(self.vulnerable_path_binary.path, self.vulnerable_path_binary.uaf_addrs)
        assert uaf_state_addrs == self.vulnerable_path_binary.uaf_addrs
