# Mutation M3 (version-removed): real module removed in Python 3.12.
# `asyncore` was a long-deprecated stdlib module for async socket programming.
# PEP 594 removed it from the stdlib in Python 3.12. An LLM trained before
# 3.12's release will still suggest it for "async socket" prompts.
# Expected runtime: ModuleNotFoundError No module named 'asyncore'.
# Expected scanner layer: L1.5 cached-hallucination OR forge: hallucinated-import.
import asyncore


class EchoHandler(asyncore.dispatcher):
    def handle_read(self):
        data = self.recv(8192)
        if data:
            self.send(data)


server = EchoHandler()
server.create_socket(socket.AF_INET, socket.SOCK_STREAM)
