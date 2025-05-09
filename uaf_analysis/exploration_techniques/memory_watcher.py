import os
import psutil
import logging
from angr.sim_manager import SimulationManager
from angr.exploration_techniques import ExplorationTechnique

l = logging.getLogger(name=__name__)

class MemoryWatcher(ExplorationTechnique):
    """
    MemoryWatcher is an angr ExplorationTechnique that monitors the memory usage of the process.
    It moves the states to the 'out_of_memory' stash if the memory usage exceeds the specified limit.
    """
    def __init__(self, max_mem: float) -> None:
        super(MemoryWatcher, self).__init__()
        self.max_mem = max_mem
        self.process = psutil.Process(os.getpid())

    @property
    def memory_usage_psutil(self) -> float:
        """
        Returns the memory usage in GB.
        """
        mem = self.process.memory_info().vms / float(2 ** 30)
        l.info(f'Current memory usage: {round(mem, 2)} GB')
        return mem

    def step(self, simulation_manager: SimulationManager, stash: str = 'active', **kwargs) -> SimulationManager:
        """
        Steps the simulation manager and moves states to the 'out_of_memory' stash if memory usage exceeds the limit.
        """
        if psutil.virtual_memory().percent > 90 or self.max_mem < self.memory_usage_psutil:
            l.info('Memory usage exceeded! Stopping execution')
            simulation_manager.move(from_stash='active', to_stash='out_of_memory')
            simulation_manager.move(from_stash='deferred', to_stash='out_of_memory')
        simulation_manager = simulation_manager.step()
        return simulation_manager
