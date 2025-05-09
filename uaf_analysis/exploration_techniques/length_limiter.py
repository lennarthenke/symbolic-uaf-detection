import logging
from angr.sim_state import SimState
from angr.sim_manager import SimulationManager
from angr.exploration_techniques import ExplorationTechnique

l = logging.getLogger(name=__name__)

class LengthLimiter(ExplorationTechnique):
    """
    Length limiter on paths.
    """
    def __init__(self, max_length: int) -> None:
        super(LengthLimiter, self).__init__()
        self._max_length = max_length

    def _filter(self, state: SimState) -> bool:
        return state.history.block_count > self._max_length

    def step(self, simulation_manager: SimulationManager, stash: str = 'active', **kwargs) -> SimulationManager:
        simulation_manager = simulation_manager.step(stash=stash, **kwargs)
        before = len(simulation_manager.stashes[stash])
        simulation_manager.move(stash, '_DROP', self._filter)
        after = len(simulation_manager.stashes[stash])
        dropped = before - after
        if dropped > 0:
            l.info(f'{dropped} state(s) exceeded the length limit of {self._max_length} and were dropped.')
        return simulation_manager
