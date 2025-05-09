import angr
import copy

class SimStateLocals(angr.SimStatePlugin):
    """
    State plugin to store the allocation and free site.
    In contrast to the state.globals plugin this performs a deep copy of the dictionary.
    """
    def __init__(self, memory_info: dict = {}) -> None:
        super().__init__()
        self.memory_info = memory_info

    def merge(self, others, merge_conditions, common_ancestor=None):
        """
        Merge the memory_info dictionaries of other SimStateLocals objects with the current instance's memory_info.
        """
        for other in others:
            for k in other.memory_info.keys():
                if k not in self.memory_info:
                    self.memory_info[k] = other.memory_info[k]

        return True

    @angr.SimStatePlugin.memo
    def copy(self, memo: dict) -> 'SimStateLocals':
        """
        Create a deep copy of the SimStateLocals object.
        """
        memory_info_copy = {key: copy.deepcopy(values) for key, values in self.memory_info.items()}
        return SimStateLocals(memory_info_copy)
