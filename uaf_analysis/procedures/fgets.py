import angr
import claripy
from claripy.ast.bv import BV
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

class FgetsHook(angr.SimProcedure):
    """
    Tries to address the following issues:
    https://github.com/angr/angr/issues/2943
    https://github.com/angr/angr/issues/804
    https://github.com/angr/angr/issues/615
    """
    def run(self, dst: BV, size: BV, file_ptr: BV):
        size = size.zero_extend(self.arch.bits - self.arch.sizeof['int'])

        fd_offset = fd_offset = io_file_data_for_arch(self.state.arch)['fd'] 
        fd = self.state.mem[file_ptr + fd_offset :].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        # case 0: empty read
        if self.state.solver.is_true(size == 0):
            return 0

        # case 1: the size is concrete.
        elif not size.symbolic:
            size = self.state.solver.eval(size)
            count = 0
            while count < size - 1:
                data, real_size = simfd.read_data(1)
                if self.state.solver.is_true(real_size == 0):
                    break
                self.state.memory.store(dst + count, data)
                count += 1
                if self.state.solver.is_true(data == b'\n'):
                    break
            self.state.memory.store(dst + count, b'\0')
            return count

        # case 2: the size is symbolic.
        else:
            data, real_size = simfd.read_data(size - 1)

            for i, byte in enumerate(data.chop(8)):
                self.state.add_constraints(
                    self.state.solver.If(
                        i + 1 != real_size,
                        byte != b"\n",  # if not last byte returned, not newline
                        self.state.solver.Or(  # otherwise one of the following must be true:
                            i + 2 == size,  # - we ran out of space, or
                            simfd.eof(),  # - the file is at EOF, or
                            byte == b"\n",  # - it is a newline
                        ),
                    )
                )
            self.state.memory.store(dst, data, size=real_size)
            end_address = dst + real_size
            end_address = end_address.annotate(MultiwriteAnnotation())
            self.state.memory.store(end_address, b"\0")

            return real_size
