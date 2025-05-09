import angr
import logging
from angr.sim_state import SimState
from angr.sim_manager import SimulationManager
from angr.knowledge_plugins.cfg.cfg_node import CFGNode
from angr.exploration_techniques import ExplorationTechnique

l = logging.getLogger(name=__name__)

class NewDirector(ExplorationTechnique):
    """
    An exploration technique for directed symbolic execution.

    Given a list with relevant nodes (tuple of start and end address) from the PreDirector analysis,
    all states are categorized into two different categories:
    - States that reach the destination, which are prioritized.
    - States that don't reach the destination, which are de-prioritized and dropped.
    """
    def __init__(self, reaching_nodes: list[tuple[int, int]]) -> None:
        super(NewDirector, self).__init__()
        self.reaching_nodes = reaching_nodes

    def _find_address_in_nodes(self, state: SimState) -> int:
        """
        Find the index of an address using binary search in a sorted list of nodes
        where a node is a tuple of a start and an end address.
        """
        low = 0
        high = len(self.reaching_nodes) - 1
        addr = state.addr
        # binary search to find the index of an address in a list of address ranges
        while (low <= high):
            # find the mid element
            mid = (low + high) >> 1
            mid_node = self.reaching_nodes[mid]
            # if the address is found
            if (mid_node[0] <= addr and addr <= mid_node[1]):
                l.info(f'Found {state} in reaching nodes')
                return mid
            # check in first half
            elif (addr < mid_node[0]):
                high = mid - 1
            # check in second half
            else:
                low = mid + 1
        # not found
        l.info(f'Did not find {state} in reaching nodes')
        return -1

    def _filter(self, state: SimState) -> bool:
        """
        Filter for states that do NOT reach the goal(s).
        """
        return self._find_address_in_nodes(state) == -1

    def _categorize_states(self, simulation_manager: SimulationManager, stash: str = 'active') -> SimulationManager:
        """
        Categorizes all states into two different groups: reaching the destination,
        and not reaching the destination within the max steps.
        """
        simulation_manager.move(
            from_stash=stash,
            to_stash='deprioritized',
            filter_func=self._filter
        )
        return simulation_manager

    def step(self, simulation_manager: SimulationManager, stash: str ='active', **kwargs) -> SimulationManager:
        """
        Categorizes all active states in the simulation manager.
        """
        if len(simulation_manager.stashes[stash]) >= 1:
            self._categorize_states(simulation_manager, stash)
        # step all active states forward. This is executed in parallel for all exploration techniques
        simulation_manager = simulation_manager.step(stash=stash, **kwargs)
        return simulation_manager
