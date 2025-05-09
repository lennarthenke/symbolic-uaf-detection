import angr
import logging
import networkx
from collections import defaultdict
from angr.sim_state import SimState
from bisect import insort, bisect_left
from typing import Callable, Generator, Iterable
from networkx.classes.digraph import DiGraph
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.knowledge_plugins.cfg.cfg_node import CFGNode

l = logging.getLogger(name=__name__)

class ExecuteAllocFreeCweGoal:
    """
    A goal that prioritizes nodes that reach a free node and then a cwe address in max steps.
    """
    def __init__(self, addrs: list[int], cfg: CFGFast) -> None:
        self.addrs = addrs
        self.cfg = cfg

    def __repr__(self):
        return '<TargetCondition execute address>'

    @staticmethod
    def _get_cfg_nodes(cfg: CFGFast, state: SimState) -> list[CFGNode]:
        """
        Get the CFGNode objects on the control flow graph given an angr state.
        """
        is_syscall = state.history.jumpkind is not None and state.history.jumpkind.startswith('Ijk_Sys')
        return cfg.model.get_all_nodes(state.addr, is_syscall, anyaddr=True)

    @staticmethod
    def _bfs_nodes(node: CFGNode, max_steps: int, get_neighbors: Callable[[CFGNode], Iterable[CFGNode]]) -> Generator[CFGNode, None, None]:
        """
        Generator function for nodes in the DiGraph using a breadth-first search,
        with a limit on maximum steps. The function keeps track of each traversed node
        and the numbers of steps to reach the node. Already visited nodes are skipped and
        the function terminates when there are no more nodes left or the maximum number of steps is reached.
        """
        steps_map = {node: 0} 
        traversed = {node}
        queue = [node]

        while len(queue) > 0:
            src = queue.pop(0)
            yield src
            neighbors = get_neighbors(src)

            for dst in neighbors:
                if dst in traversed:
                    continue
                traversed.add(dst)
                if dst not in steps_map.keys():
                    dst_steps = steps_map[src] + 1
                else:
                    dst_steps = min(steps_map[src] + 1, steps_map[dst])
                if dst_steps <= max_steps:
                    steps_map[dst] = dst_steps
                    queue.append(dst)
                else:
                    l.debug(f'Reached MAX peek blocks @ {hex(dst.addr)}')
    
    def _get_all_predecessors(self, node: CFGNode, max_steps: int) -> list[CFGNode]:
        """
        Get a list with all predecessors of a node.
        """
        return list(self._bfs_nodes(node, max_steps, self.cfg.graph.predecessors))

    def _get_all_successors(self, node: CFGNode, max_steps: int) -> list[CFGNode]:
        """
        Get a list with all successors of a node.
        """
        return list(self._bfs_nodes(node, max_steps, self.cfg.graph.successors))

    @staticmethod
    def _addr_is_in_block(addr: int, node: CFGNode) -> bool:
        """
        Check if an address is in a CFGNode.
        """
        return node.addr <= addr and addr <= node.addr + node.size

    @staticmethod
    def _cfg_node_to_tuple(node: CFGNode) -> tuple[int, int]:
        """
        Cast a CFGNode to an int tuple: (start_address, end_address)
        """
        return (node.addr, node.addr + node.size)

    @staticmethod
    def _add_node_to_sorted(node_list: list[tuple[int, int]], node: tuple[int, int]) -> None:
        """
        Add a node into a sorted list.
        """
        index = bisect_left(node_list, node)
        # only add unique nodes
        if index == len(node_list) or node_list[index] != node:
            insort(node_list, node)

    def _add_all_nodes(self, node_list: list[tuple[int, int]], nodes: list[CFGNode]) -> None:
        """
        Add all nodes to a sorted list.
        """
        for node in nodes:
            self._add_node_to_sorted(node_list, self._cfg_node_to_tuple(node))

    def find_free_cwe_nodes(self, state: SimState, max_steps: int, free_cwe_nodes: list[tuple[int, int]]) -> list[tuple[int, int]]:
        """
        Find all nodes, which are first reaching a free node and then the target use address.
        """
        # get the current CFGNodes from the CFG
        source_nodes = self._get_cfg_nodes(self.cfg, state)
        pred_nodes = {'source': set(), 'free': set(), 'cwe': set()}
        succ_nodes = {'free': set()}
        all_nodes = set()

        # get the source predecessor nodes without the source nodes themselves
        for source_node in source_nodes:
            pred_nodes['source'].update(self._get_all_predecessors(source_node, max_steps))
        for source_node in source_nodes:
            pred_nodes['source'].remove(source_node)

        # due to context sensitivity, a given basic block can have multiple nodes in the graph (for multiple context)
        for source_node in source_nodes:
            # crawl the graph
            for node in self._bfs_nodes(source_node, max_steps, self.cfg.graph.successors):
                # save all memory free predecessor and successor nodes.
                if node.is_simprocedure and (node.simprocedure_name in ['free', 'realloc', 'reallocarray'] or 'operator delete' in node.simprocedure_name):
                    l.info(f'Found free node: {node}')
                    pred_nodes['free'].update(self._get_all_predecessors(node, max_steps))
                    succ_nodes['free'].update(self._get_all_successors(node, max_steps))
                # save all cwe predecessor nodes.
                for addr in self.addrs:
                    if self._addr_is_in_block(addr, node):
                        l.info(f'Found (potential) UAF node: {node}')
                        pred_nodes['cwe'].update(self._get_all_predecessors(node, max_steps))

        # get the intersection between all cwe predecessors and the relevant free nodes
        all_nodes = list(pred_nodes['cwe'] - pred_nodes['source'] & (pred_nodes['free'] | succ_nodes['free']))
        self._add_all_nodes(free_cwe_nodes, all_nodes)
        return free_cwe_nodes

class PreDirector(angr.Analysis):
    """
    An analysis for the NewDirector exploration technique.

    Given a control flow graph (using CFGFast) it finds all nodes
    that will definitely reach one of the goal addresses in the range of max steps.
    """
    def __init__(self, start_state: SimState, cfg: CFGFast, max_steps: int, goal_addrs: list[int]) -> None:
        self.start_state = start_state
        self.cfg = cfg
        self.max_steps = max_steps
        self.goal_addrs = goal_addrs
        self.free_cwe_nodes = []

    def get_free_cwe_nodes(self) -> list[tuple[int, int]]:
        """
        Get all nodes that reach certain goal addresses.
        """
        goal = ExecuteAllocFreeCweGoal(self.goal_addrs, self.cfg)
        self.free_cwe_nodes = goal.find_free_cwe_nodes(self.start_state, self.max_steps, self.free_cwe_nodes)
        return self.free_cwe_nodes
