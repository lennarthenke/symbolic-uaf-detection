import angr
import logging
from angr.sim_manager import SimulationManager
from angr.exploration_techniques import ExplorationTechnique

l = logging.getLogger(name=__name__)

class AutoDrop(ExplorationTechnique):
    """
    AutoDrop is an exploration technique that keeps track of automatically
    dropped stashes during simulation.
    """
    def __init__(self, drop_stashes: list[str]) -> None:
        super(AutoDrop, self).__init__()
        self.dropped = {stash: 0 for stash in drop_stashes}
        self.max_number_paths = 0

    def update_max_number_paths(self, simulation_manager: SimulationManager, stash: str) -> None:
        """
        Update the maximum number of paths seen during simulation.
        """
        current_number_paths = len(simulation_manager.stashes[stash]) + len(simulation_manager.stashes['deferred'])
        self.max_number_paths = max(self.max_number_paths, current_number_paths)

    def drop_states(self, simulation_manager: SimulationManager) -> None:
        """
        Drop the specified stashes from the simulation manager and keep track of the number of dropped states.
        """
        for stash in self.dropped.keys():
            self.dropped[stash] += len(simulation_manager.stashes[stash])
            simulation_manager.drop(stash=stash)

    def step(self, simulation_manager: SimulationManager, stash: str = 'active', **kwargs) -> SimulationManager:
        """
        Perform a step in the simulation, dropping specified stashes and keeping
        track of the number of dropped states.
        """
        self.update_max_number_paths(simulation_manager, stash)
        self.drop_states(simulation_manager)
        l.info(f'States dropped: {self.dropped}')
        simulation_manager = simulation_manager.step()
        simulation_manager.stashes['dropped'] = self.dropped
        simulation_manager.stashes['max_number_paths'] = [self.max_number_paths]
        return simulation_manager
